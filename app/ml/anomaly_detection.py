"""
Anomaly detection using Isolation Forest and TF-IDF vectorization.
"""
import os
import pickle
import hashlib
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib

from app.config import settings

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """ML-based anomaly detector using Isolation Forest and TF-IDF."""
    
    def __init__(self, contamination: float = None):
        self.contamination = contamination or settings.ANOMALY_CONTAMINATION
        self.model = None
        self.vectorizer = None
        self.scaler = None
        self.pca = None
        self.is_fitted = False
        self.model_version = "1.0.0"
        self.training_samples = 0
        self.feature_names = []
    
    def _extract_features(self, logs: List[Dict[str, Any]]) -> Tuple[np.ndarray, List[str]]:
        """Extract features from log entries."""
        texts = []
        numeric_features = []
        
        for log in logs:
            # Text feature: raw log
            texts.append(log.get("raw_log", ""))
            
            # Numeric features
            features = []
            
            # Source type encoding
            source_type = log.get("source_type", "")
            features.append(hash(source_type) % 100 / 100.0)
            
            # Event type encoding
            event_type = log.get("event_type", "")
            features.append(hash(event_type) % 100 / 100.0)
            
            # Severity encoding
            severity_map = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0, "info": 0.0}
            features.append(severity_map.get(log.get("severity", "low"), 0.25))
            
            # Status code (if applicable)
            status_code = log.get("status_code", 0) or 0
            features.append(status_code / 600.0)  # Normalize
            
            # Event ID encoding
            event_id = log.get("event_id", "")
            features.append(hash(str(event_id)) % 100 / 100.0)
            
            # Log length
            features.append(len(log.get("raw_log", "")) / 1000.0)
            
            # Has IP indicator
            features.append(1.0 if log.get("source_ip") else 0.0)
            
            # Has username
            features.append(1.0 if log.get("username") else 0.0)
            
            # Has process
            features.append(1.0 if log.get("process_name") else 0.0)
            
            # OS type encoding
            os_type = log.get("operating_system", "")
            features.append(hash(os_type) % 100 / 100.0)
            
            # Has endpoint (web)
            features.append(1.0 if log.get("endpoint") else 0.0)
            
            numeric_features.append(features)
        
        # TF-IDF on raw logs
        if self.vectorizer is None:
            self.vectorizer = TfidfVectorizer(
                max_features=100,
                ngram_range=(1, 2),
                min_df=1,
                max_df=0.95,
                stop_words="english",
            )
            tfidf_features = self.vectorizer.fit_transform(texts).toarray()
        else:
            tfidf_features = self.vectorizer.transform(texts).toarray()
        
        # Combine features
        numeric_array = np.array(numeric_features)
        
        # Scale numeric features
        if self.scaler is None:
            self.scaler = StandardScaler()
            numeric_scaled = self.scaler.fit_transform(numeric_array)
        else:
            numeric_scaled = self.scaler.transform(numeric_array)
        
        combined = np.hstack([numeric_scaled, tfidf_features])
        
        # PCA for dimensionality reduction
        if combined.shape[1] > 20:
            n_components = min(20, combined.shape[0] - 1, combined.shape[1])
            if self.pca is None:
                self.pca = PCA(n_components=n_components)
                combined = self.pca.fit_transform(combined)
            else:
                combined = self.pca.transform(combined)
        
        self.feature_names = [f"feature_{i}" for i in range(combined.shape[1])]
        
        return combined, texts
    
    def fit(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Train the anomaly detection model."""
        if len(logs) < settings.MIN_SAMPLES_FOR_ML:
            raise ValueError(f"Need at least {settings.MIN_SAMPLES_FOR_ML} samples for training")
        
        logger.info(f"Training anomaly detection model with {len(logs)} samples")
        
        # Extract features
        X, _ = self._extract_features(logs)
        
        # Train Isolation Forest
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X)
        
        self.is_fitted = True
        self.training_samples = len(logs)
        self.model_version = f"1.0.{int(datetime.utcnow().timestamp())}"
        
        # Get training predictions for metrics
        predictions = self.model.predict(X)
        scores = self.model.decision_function(X)
        
        anomaly_count = sum(1 for p in predictions if p == -1)
        
        metrics = {
            "samples_used": len(logs),
            "features_count": X.shape[1],
            "anomalies_detected": anomaly_count,
            "anomaly_rate": anomaly_count / len(logs),
            "mean_anomaly_score": float(np.mean(scores)),
            "model_version": self.model_version,
        }
        
        logger.info(f"Model training complete: {metrics}")
        return metrics
    
    def predict(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Predict anomalies in log entries."""
        if not self.is_fitted:
            logger.warning("Model not fitted yet, returning empty predictions")
            return []
        
        X, texts = self._extract_features(logs)
        
        predictions = self.model.predict(X)
        scores = self.model.decision_function(X)
        
        results = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            is_anomaly = pred == -1
            
            # Convert score to anomaly score (0-1 range, higher = more anomalous)
            anomaly_score = float(1.0 - (score + 0.5))  # Normalize
            anomaly_score = max(0.0, min(1.0, anomaly_score))
            
            result = {
                "is_anomaly": is_anomaly,
                "anomaly_score": round(anomaly_score, 4),
                "confidence": round(min(1.0, abs(score) + 0.5), 4),
                "model_version": self.model_version,
                "features": dict(zip(self.feature_names[:10], X[i][:10].tolist())),
            }
            results.append(result)
        
        return results
    
    def predict_single(self, log: Dict[str, Any]) -> Dict[str, Any]:
        """Predict anomaly for a single log entry."""
        results = self.predict([log])
        return results[0] if results else {"is_anomaly": False, "anomaly_score": 0.0}
    
    def save_model(self, filepath: str = None) -> str:
        """Save the trained model."""
        if not self.is_fitted:
            raise ValueError("Model not fitted yet")
        
        if filepath is None:
            filepath = os.path.join(
                settings.MODEL_DIR, 
                f"anomaly_detector_{self.model_version}.joblib"
            )
        
        model_data = {
            "model": self.model,
            "vectorizer": self.vectorizer,
            "scaler": self.scaler,
            "pca": self.pca,
            "model_version": self.model_version,
            "training_samples": self.training_samples,
            "contamination": self.contamination,
        }
        
        joblib.dump(model_data, filepath)
        logger.info(f"Model saved to {filepath}")
        return filepath
    
    def load_model(self, filepath: str) -> bool:
        """Load a trained model."""
        try:
            model_data = joblib.load(filepath)
            
            self.model = model_data["model"]
            self.vectorizer = model_data["vectorizer"]
            self.scaler = model_data["scaler"]
            self.pca = model_data.get("pca")
            self.model_version = model_data.get("model_version", "unknown")
            self.training_samples = model_data.get("training_samples", 0)
            self.contamination = model_data.get("contamination", 0.1)
            self.is_fitted = True
            
            logger.info(f"Model loaded from {filepath}, version {self.model_version}")
            return True
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            return False
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            "is_fitted": self.is_fitted,
            "model_version": self.model_version,
            "training_samples": self.training_samples,
            "contamination": self.contamination,
            "feature_count": len(self.feature_names),
            "algorithm": "Isolation Forest",
            "vectorizer": "TF-IDF",
        }
