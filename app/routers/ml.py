"""
Machine Learning router for model training, predictions, and clustering.
"""

import os
import time
import logging

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models import LogEntry, Anomaly, MLModel
from app.schemas import MLTrainRequest
from app.auth import get_current_user
from app.config import settings
from app.ml import AnomalyDetector, LogClustering
from app.websocket.manager import ws_manager

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/ml",
    tags=["Machine Learning"]
)

# Global ML models
anomaly_detector = AnomalyDetector()
log_clustering = LogClustering()


# ============================================================
# TRAIN ANOMALY MODEL
# ============================================================

@router.post("/train/anomaly")
async def train_anomaly_detector(
    request: Optional[MLTrainRequest] = None,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Train anomaly detection model."""

    start_time = time.time()

    try:

        # Default values
        sample_size = 1000
        contamination = 0.1

        # Override request values if provided
        if request:

            if request.sample_size:
                sample_size = request.sample_size

            if request.contamination:
                contamination = request.contamination

        # Fetch logs
        logs = (
            db.query(LogEntry)
            .order_by(desc(LogEntry.timestamp))
            .limit(sample_size)
            .all()
        )

        # Safety checks
        if not logs:
            raise HTTPException(
                status_code=400,
                detail="No logs found. Upload logs first."
            )

        if len(logs) < 10:
            raise HTTPException(
                status_code=400,
                detail=f"Need at least 10 logs for training. Found {len(logs)}."
            )

        # Convert logs
        log_dicts = []

        for log in logs:

            log_dicts.append({
                "id": log.id,
                "raw_log": str(log.raw_log or ""),
                "source_type": str(log.source_type or ""),
                "event_type": str(log.event_type or ""),
                "severity": str(log.severity or ""),
                "status_code": log.status_code,
                "event_id": log.event_id,
                "endpoint": str(log.endpoint or ""),
                "hostname": str(log.hostname or ""),
                "username": str(log.username or ""),
                "process_name": str(log.process_name or ""),
                "operating_system": str(log.operating_system or ""),
                "source_ip": str(log.source_ip or ""),
            })

        # Initialize detector
        global anomaly_detector

        anomaly_detector = AnomalyDetector(
            contamination=contamination
        )

        # Train
        metrics = anomaly_detector.fit(log_dicts)

        training_time = (
            time.time() - start_time
        ) * 1000

        # Save model
        model_path = anomaly_detector.save_model()

        # Store model metadata
        ml_model = MLModel(
            model_name="anomaly_detector",
            model_version=metrics.get("model_version", "1.0"),
            model_type="isolation_forest",
            file_path=model_path,
            samples_used=len(logs),
            features_used=(
                anomaly_detector.feature_names[:20]
                if anomaly_detector.feature_names
                else []
            ),
            training_date=datetime.utcnow(),
        )

        db.add(ml_model)
        db.commit()

        return {
            "message": "Anomaly model trained successfully",
            "model_id": ml_model.id,
            "samples_used": len(logs),
            "training_time_ms": round(training_time, 2),
            "metrics": metrics,
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.error(f"Anomaly training failed: {e}")

        raise HTTPException(
            status_code=500,
            detail=f"Training failed: {str(e)}"
        )


# ============================================================
# PREDICT ANOMALIES
# ============================================================

@router.post("/predict/anomaly")
async def predict_anomalies(
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Predict anomalies from recent logs."""

    try:

        if not anomaly_detector.is_fitted:
            raise HTTPException(
                status_code=400,
                detail="Model not trained yet."
            )

        logs = (
            db.query(LogEntry)
            .order_by(desc(LogEntry.timestamp))
            .limit(limit)
            .all()
        )

        if not logs:
            return {
                "total_processed": 0,
                "anomalies_detected": 0,
                "anomalies": [],
            }

        log_dicts = []

        for log in logs:

            log_dicts.append({
                "id": log.id,
                "raw_log": str(log.raw_log or ""),
                "source_type": str(log.source_type or ""),
                "event_type": str(log.event_type or ""),
                "severity": str(log.severity or ""),
                "status_code": log.status_code,
                "event_id": log.event_id,
                "endpoint": str(log.endpoint or ""),
                "hostname": str(log.hostname or ""),
                "username": str(log.username or ""),
                "process_name": str(log.process_name or ""),
                "operating_system": str(log.operating_system or ""),
                "source_ip": str(log.source_ip or ""),
            })

        predictions = anomaly_detector.predict(log_dicts)

        anomalies = []

        for log, pred in zip(logs, predictions):

            if pred.get("is_anomaly"):

                anomaly = Anomaly(
                    log_entry_id=log.id,
                    anomaly_score=pred.get("anomaly_score", 0),
                    anomaly_type=log.event_type,
                    features=pred.get("features"),
                    model_version=pred.get("model_version"),
                )

                db.add(anomaly)

                anomaly_data = {
                    "log_id": log.id,
                    "source_ip": log.source_ip,
                    "event_type": log.event_type,
                    "anomaly_score": pred.get("anomaly_score", 0),
                    "confidence": pred.get("confidence", 0),
                    "raw_log": str(log.raw_log)[:200],
                }

                anomalies.append(anomaly_data)

                # WebSocket
                await ws_manager.send_anomaly(anomaly_data)

        db.commit()

        return {
            "total_processed": len(logs),
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies[:50],
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.error(f"Prediction failed: {e}")

        raise HTTPException(
            status_code=500,
            detail=f"Prediction failed: {str(e)}"
        )


# ============================================================
# GET ANOMALIES
# ============================================================

@router.get("/anomalies")
async def get_anomalies(
    limit: int = Query(50, ge=1, le=500),
    min_score: float = Query(0.0, ge=0.0, le=1.0),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get anomaly results."""

    anomalies = (
        db.query(Anomaly)
        .filter(Anomaly.anomaly_score >= min_score)
        .order_by(desc(Anomaly.anomaly_score))
        .limit(limit)
        .all()
    )

    return anomalies


# ============================================================
# TRAIN CLUSTERING
# ============================================================

@router.post("/train/clustering")
async def train_clustering(
    n_clusters: int = Query(5, ge=2, le=20),
    sample_size: int = Query(1000, ge=10, le=10000),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Train clustering model."""

    try:

        logs = (
            db.query(LogEntry)
            .order_by(desc(LogEntry.timestamp))
            .limit(sample_size)
            .all()
        )

        if len(logs) < 10:
            raise HTTPException(
                status_code=400,
                detail="Need at least 10 logs for clustering."
            )

        return {
            "message": "Clustering placeholder working",
            "logs_used": len(logs),
            "clusters": n_clusters,
        }

    except HTTPException:
        raise

    except Exception as e:

        logger.error(f"Clustering failed: {e}")

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )


# ============================================================
# GET CLUSTERS
# ============================================================

@router.get("/clusters")
async def get_clusters():
    """Safe clusters endpoint."""

    return {
        "clusters": [],
        "total_clusters": 0,
        "message": "No clustering data yet"
    }


# ============================================================
# LIST MODELS
# ============================================================

@router.get("/models")
async def list_models(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """List ML models."""

    models = (
        db.query(MLModel)
        .order_by(desc(MLModel.created_at))
        .all()
    )

    return models


# ============================================================
# MODEL INFO
# ============================================================

@router.get("/model/info")
async def get_model_info(
    current_user = Depends(get_current_user),
):
    """Get ML model info."""

    return {
        "anomaly_detector": anomaly_detector.get_model_info(),

        "clustering": {
            "is_fitted": log_clustering.is_fitted,
            "model_version": getattr(
                log_clustering,
                "model_version",
                "1.0"
            ),
            "algorithm": getattr(
                log_clustering,
                "algorithm",
                "kmeans"
            ),
            "n_clusters": getattr(
                log_clustering,
                "n_clusters",
                0
            ),
        },
    }