"""
Log management router for upload, search, and retrieval.
"""
import os
import time
import hashlib
import logging
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from sqlalchemy.sql import text

from app.database import get_db
from app.models import LogEntry, Alert, Anomaly
from app.schemas import LogUploadResponse, LogSearchRequest, LogSearchResponse, LogEntryResponse
from app.auth import get_current_user
from app.config import settings
from app.parsers import parse_log, detect_log_type
from app.detection import ThreatDetectionEngine
from app.ml import AnomalyDetector
from app.websocket.manager import ws_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/logs", tags=["Logs"])

# Initialize detection engine
detection_engine = ThreatDetectionEngine()


@router.post("/upload", response_model=LogUploadResponse)
async def upload_logs(
    file: UploadFile = File(...),
    source_type: str = Form("auto"),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Upload and process a log file."""
    start_time = time.time()
    
    # Validate file
    allowed_extensions = [".log", ".txt", ".json", ".csv", ".evtx"]
    file_ext = os.path.splitext(file.filename)[1].lower()
    
    if file_ext not in allowed_extensions:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed: {', '.join(allowed_extensions)}",
        )
    
    # Save uploaded file
    upload_path = os.path.join(settings.UPLOAD_DIR, f"{datetime.utcnow().timestamp()}_{file.filename}")
    content = await file.read()
    
    with open(upload_path, "wb") as f:
        f.write(content)
    
    # Parse logs
    logs_inserted = 0
    parsing_errors = 0
    logs_processed = 0
    
    try:
        # Decode content
        try:
            content_str = content.decode("utf-8")
        except UnicodeDecodeError:
            content_str = content.decode("latin-1")
        
        lines = [str(line).strip() for line in content_str.split("\n") if str(line).strip()]
        parsed_logs = []
        
        for line in lines:
            line = str(line).replace("\x00", "").strip()
            if not line:
                continue
            
            logs_processed += 1
            
            try:
                # Detect and parse log type
                detected_type = source_type if source_type != "auto" else detect_log_type(line)
                parsed = parse_log(line, detected_type)
                
                # Generate hash for deduplication
                log_hash = hashlib.sha256(line.encode()).hexdigest()
                
                # Check for duplicates
                existing = db.query(LogEntry).filter(LogEntry.log_hash == log_hash).first()
                if existing:
                    continue
                
                # Create log entry
                log_entry = LogEntry(
                    timestamp=parsed.get("timestamp", datetime.utcnow()),
                    source_ip=parsed.get("source_ip"),
                    destination_ip=parsed.get("destination_ip"),
                    username=parsed.get("username"),
                    hostname=parsed.get("hostname"),
                    process_name=parsed.get("process_name"),
                    event_id=parsed.get("event_id"),
                    request_method=parsed.get("request_method"),
                    endpoint=parsed.get("endpoint"),
                    status_code=parsed.get("status_code"),
                    event_type=parsed.get("event_type", detected_type),
                    severity=parsed.get("severity", "low"),
                    operating_system=parsed.get("operating_system"),
                    source_type=detected_type,
                    source_file=file.filename,
                    raw_log=line,
                    parsed_data=parsed.get("parsed_data"),
                    log_hash=log_hash,
                )
                
                db.add(log_entry)
                parsed_logs.append(log_entry)
                logs_inserted += 1
                
                # Commit in batches
                if logs_inserted % 100 == 0:
                    db.commit()
            
            except Exception as e:
                parsing_errors += 1
                logger.warning(f"Error parsing line: {e}")
                continue
        
        db.commit()
        
        # Run threat detection on new logs
        if parsed_logs:
            log_dicts = []
            for log in parsed_logs:
                db.refresh(log)
                log_dicts.append({
                    "id": log.id,
                    "source_ip": log.source_ip,
                    "event_type": log.event_type,
                    "severity": log.severity,
                    "raw_log": log.raw_log,
                    "parsed_data": log.parsed_data,
                    "source_type": log.source_type,
                    "event_id": log.event_id,
                    "status_code": log.status_code,
                    "endpoint": log.endpoint,
                    "hostname": log.hostname,
                    "username": log.username,
                    "process_name": log.process_name,
                })
            
            alerts = detection_engine.analyze_logs(log_dicts)
            
            # Store alerts
            for alert_data in alerts:
                alert = Alert(
                    alert_id=alert_data["alert_id"],
                    severity=alert_data["severity"],
                    attack_type=alert_data["attack_type"],
                    source_ip=alert_data.get("source_ip"),
                    affected_system=alert_data.get("affected_system"),
                    description=alert_data["description"],
                    recommendation=alert_data.get("recommendation"),
                    mitre_tactic=alert_data.get("mitre_tactic"),
                    mitre_technique=alert_data.get("mitre_technique"),
                    mitre_technique_id=alert_data.get("mitre_technique_id"),
                    risk_score=alert_data.get("risk_score", 0),
                    confidence=alert_data.get("confidence", 0.8),
                )
                db.add(alert)
            
            db.commit()
            
            # Send real-time alerts via WebSocket
            for alert_data in alerts[:10]:  # Limit to first 10
                await ws_manager.send_alert(alert_data)
        
        processing_time = (time.time() - start_time) * 1000
        
        return LogUploadResponse(
            message="Logs processed successfully",
            logs_processed=logs_processed,
            logs_inserted=logs_inserted,
            parsing_errors=parsing_errors,
            source_type=detected_type if logs_processed > 0 else "unknown",
            filename=file.filename,
            processing_time_ms=round(processing_time, 2),
        )
    
    except Exception as e:
        logger.error(f"Error processing file: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing file: {str(e)}")


@router.get("/search", response_model=LogSearchResponse)
async def search_logs(
    query: Optional[str] = Query(None),
    source_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    start_date: Optional[datetime] = Query(None),
    end_date: Optional[datetime] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Search logs with filters."""
    query_obj = db.query(LogEntry)
    
    # Apply filters
    if query:
        query_obj = query_obj.filter(
            text("raw_log ILIKE :query").bindparams(query=f"%{query}%")
        )
    
    if source_type:
        query_obj = query_obj.filter(LogEntry.source_type == source_type)
    
    if severity:
        query_obj = query_obj.filter(LogEntry.severity == severity)
    
    if source_ip:
        query_obj = query_obj.filter(LogEntry.source_ip == source_ip)
    
    if event_type:
        query_obj = query_obj.filter(LogEntry.event_type == event_type)
    
    if start_date:
        query_obj = query_obj.filter(LogEntry.timestamp >= start_date)
    
    if end_date:
        query_obj = query_obj.filter(LogEntry.timestamp <= end_date)
    
    # Get total count
    total = query_obj.count()
    
    # Get paginated results
    logs = query_obj.order_by(desc(LogEntry.timestamp)).offset((page - 1) * page_size).limit(page_size).all()
    
    return LogSearchResponse(
        total=total,
        page=page,
        page_size=page_size,
        logs=logs,
    )


@router.get("/recent")
async def get_recent_logs(
    limit: int = Query(50, ge=1, le=500),
    source_type: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get recent log entries."""
    query = db.query(LogEntry)
    
    if source_type:
        query = query.filter(LogEntry.source_type == source_type)
    
    logs = query.order_by(desc(LogEntry.timestamp)).limit(limit).all()
    return logs


@router.get("/types")
async def get_log_types(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get all distinct log source types."""
    types = db.query(LogEntry.source_type, func.count(LogEntry.id)).group_by(LogEntry.source_type).all()
    return [{"type": t[0], "count": t[1]} for t in types]


@router.get("/stats")
async def get_log_stats(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get log statistics."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    total = db.query(LogEntry).filter(LogEntry.timestamp >= since).count()
    
    by_type = db.query(LogEntry.source_type, func.count(LogEntry.id)).filter(
        LogEntry.timestamp >= since
    ).group_by(LogEntry.source_type).all()
    
    by_severity = db.query(LogEntry.severity, func.count(LogEntry.id)).filter(
        LogEntry.timestamp >= since
    ).group_by(LogEntry.severity).all()
    
    by_hour = db.query(
        func.date_trunc("hour", LogEntry.timestamp),
        func.count(LogEntry.id)
    ).filter(
        LogEntry.timestamp >= since
    ).group_by(
        func.date_trunc("hour", LogEntry.timestamp)
    ).order_by(
        func.date_trunc("hour", LogEntry.timestamp)
    ).all()
    
    return {
        "total": total,
        "by_type": [{"type": t[0], "count": t[1]} for t in by_type],
        "by_severity": [{"severity": s[0], "count": s[1]} for s in by_severity],
        "by_hour": [{"hour": h[0].isoformat(), "count": h[1]} for h in by_hour],
    }


@router.delete("/clear")
async def clear_logs(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Clear all logs (admin only)."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    deleted = db.query(LogEntry).delete()
    db.commit()
    
    return {"message": f"Deleted {deleted} log entries"}
