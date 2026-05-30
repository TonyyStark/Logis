"""
Alert management router for viewing and managing security alerts.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_

from app.database import get_db
from app.models import Alert, LogEntry
from app.schemas import AlertResponse, AlertUpdate, AlertStats
from app.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/", response_model=list[AlertResponse])
async def list_alerts(
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    attack_type: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """List alerts with filters."""
    query = db.query(Alert)
    
    if severity:
        query = query.filter(Alert.severity == severity)
    if status:
        query = query.filter(Alert.status == status)
    if attack_type:
        query = query.filter(Alert.attack_type.ilike(f"%{attack_type}%"))
    if source_ip:
        query = query.filter(Alert.source_ip == source_ip)
    
    alerts = query.order_by(desc(Alert.timestamp)).offset((page - 1) * page_size).limit(page_size).all()
    return alerts


@router.get("/stats")
async def get_alert_stats(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get alert statistics."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    total = db.query(Alert).count()
    total_recent = db.query(Alert).filter(Alert.timestamp >= since).count()
    
    by_severity = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    by_status = db.query(Alert.status, func.count(Alert.id)).group_by(Alert.status).all()
    by_type = db.query(Alert.attack_type, func.count(Alert.id)).group_by(Alert.attack_type).all()
    
    # Recent critical alerts
    recent_critical = db.query(Alert).filter(
        and_(Alert.severity == "critical", Alert.timestamp >= since)
    ).order_by(desc(Alert.timestamp)).limit(5).all()
    
    return {
        "total_alerts": total,
        "total_recent": total_recent,
        "by_severity": {s[0]: s[1] for s in by_severity},
        "by_status": {s[0]: s[1] for s in by_status},
        "by_attack_type": {t[0]: t[1] for t in by_type},
        "recent_critical": recent_critical,
    }


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get a specific alert."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: str,
    update: AlertUpdate,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Update an alert's status or assignment."""
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    if update.status:
        alert.status = update.status
        if update.status in ["resolved", "false_positive"]:
            alert.resolved_at = datetime.utcnow()
    
    if update.assigned_user_id:
        alert.assigned_user_id = update.assigned_user_id
    
    db.commit()
    db.refresh(alert)
    
    return alert


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: str,
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Delete an alert (admin only)."""
    if not current_user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    
    alert = db.query(Alert).filter(Alert.alert_id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    db.delete(alert)
    db.commit()
    
    return {"message": "Alert deleted"}


@router.get("/timeline/daily")
async def get_alert_timeline(
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get alert timeline."""
    since = datetime.utcnow() - timedelta(days=days)
    
    timeline = db.query(
        func.date_trunc("day", Alert.timestamp).label("date"),
        Alert.severity,
        func.count(Alert.id).label("count")
    ).filter(
        Alert.timestamp >= since
    ).group_by(
        func.date_trunc("day", Alert.timestamp),
        Alert.severity
    ).order_by("date").all()
    
    result = {}
    for date, severity, count in timeline:
        date_str = date.strftime("%Y-%m-%d")
        if date_str not in result:
            result[date_str] = {}
        result[date_str][severity] = count
    
    return [{"date": k, **v} for k, v in sorted(result.items())]
