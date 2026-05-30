"""
Analytics router for dashboard statistics and threat analytics.
"""
import logging
from datetime import datetime, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, and_
from collections import Counter

from app.database import get_db
from app.models import LogEntry, Alert, Anomaly, ThreatScore
from app.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/analytics", tags=["Analytics"])


@router.get("/dashboard")
async def get_dashboard_stats(
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get main dashboard statistics."""
    now = datetime.utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)
    
    # Total counts
    total_logs = db.query(func.count(LogEntry.id)).scalar()
    total_alerts = db.query(func.count(Alert.id)).scalar()
    total_anomalies = db.query(func.count(Anomaly.id)).scalar()
    
    # Today's counts
    logs_today = db.query(func.count(LogEntry.id)).filter(LogEntry.timestamp >= today_start).scalar()
    alerts_today = db.query(func.count(Alert.id)).filter(Alert.timestamp >= today_start).scalar()
    
    # Alerts by severity
    severity_counts = db.query(Alert.severity, func.count(Alert.id)).group_by(Alert.severity).all()
    severity_dict = {s[0]: s[1] for s in severity_counts}
    
    # Active threats (new and acknowledged high/critical alerts)
    active_threats = db.query(func.count(Alert.id)).filter(
        and_(
            Alert.status.in_(["new", "acknowledged"]),
            Alert.severity.in_(["high", "critical"])
        )
    ).scalar()
    
    # Top source IPs
    top_ips = db.query(
        LogEntry.source_ip,
        func.count(LogEntry.id).label("count"),
        func.count(Alert.id).label("alert_count")
    ).outerjoin(Alert, Alert.log_entry_id == LogEntry.id).filter(
        LogEntry.source_ip.isnot(None)
    ).group_by(LogEntry.source_ip).order_by(desc("count")).limit(10).all()
    
    # Top attack types
    top_attacks = db.query(
        Alert.attack_type,
        func.count(Alert.id).label("count")
    ).group_by(Alert.attack_type).order_by(desc("count")).limit(10).all()
    
    # Logs over time (last 24 hours)
    logs_hourly = db.query(
        func.date_trunc("hour", LogEntry.timestamp).label("hour"),
        func.count(LogEntry.id).label("count")
    ).filter(LogEntry.timestamp >= last_24h).group_by("hour").order_by("hour").all()
    
    # Alerts over time (last 24 hours)
    alerts_hourly = db.query(
        func.date_trunc("hour", Alert.timestamp).label("hour"),
        func.count(Alert.id).label("count")
    ).filter(Alert.timestamp >= last_24h).group_by("hour").order_by("hour").all()
    
    # Log source distribution
    source_dist = db.query(
        LogEntry.source_type,
        func.count(LogEntry.id).label("count")
    ).group_by(LogEntry.source_type).order_by(desc("count")).limit(10).all()
    
    # Event type distribution
    event_dist = db.query(
        LogEntry.event_type,
        func.count(LogEntry.id).label("count")
    ).group_by(LogEntry.event_type).order_by(desc("count")).limit(10).all()
    
    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "active_threats": active_threats,
        "logs_today": logs_today,
        "alerts_today": alerts_today,
        "critical_alerts": severity_dict.get("critical", 0),
        "high_alerts": severity_dict.get("high", 0),
        "medium_alerts": severity_dict.get("medium", 0),
        "low_alerts": severity_dict.get("low", 0),
        "total_anomalies": total_anomalies,
        "top_source_ips": [{"ip": ip[0], "count": ip[1], "alert_count": ip[2]} for ip in top_ips],
        "top_attack_types": [{"type": t[0], "count": t[1]} for t in top_attacks],
        "severity_distribution": severity_dict,
        "logs_over_time": [{"hour": h[0].isoformat(), "count": h[1]} for h in logs_hourly],
        "alerts_over_time": [{"hour": h[0].isoformat(), "count": h[1]} for h in alerts_hourly],
        "source_distribution": [{"source": s[0], "count": s[1]} for s in source_dist],
        "event_distribution": [{"event": e[0], "count": e[1]} for e in event_dist],
        "uptime_percentage": 99.99,
        "average_latency_ms": 45,
    }


@router.get("/threats")
async def get_threat_analytics(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get threat analytics."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Top attacker IPs
    top_attackers = db.query(
        Alert.source_ip,
        func.count(Alert.id).label("attack_count"),
        func.sum(Alert.risk_score).label("total_risk")
    ).filter(
        and_(Alert.timestamp >= since, Alert.source_ip.isnot(None))
    ).group_by(Alert.source_ip).order_by(desc("attack_count")).limit(15).all()
    
    # Most targeted systems
    targeted = db.query(
        Alert.affected_system,
        func.count(Alert.id).label("count"),
        Alert.attack_type
    ).filter(
        and_(Alert.timestamp >= since, Alert.affected_system.isnot(None))
    ).group_by(Alert.affected_system, Alert.attack_type).order_by(desc("count")).limit(15).all()
    
    # Attack categories
    categories = db.query(
        Alert.attack_type,
        func.count(Alert.id).label("count"),
        Alert.severity
    ).filter(Alert.timestamp >= since).group_by(Alert.attack_type, Alert.severity).order_by(
        desc("count")
    ).limit(15).all()
    
    # Threat trends over time
    trends = db.query(
        func.date_trunc("hour", Alert.timestamp).label("hour"),
        Alert.severity,
        func.count(Alert.id).label("count")
    ).filter(Alert.timestamp >= since).group_by("hour", Alert.severity).order_by("hour").all()
    
    # MITRE technique distribution
    mitre = db.query(
        Alert.mitre_technique_id,
        Alert.mitre_technique,
        Alert.mitre_tactic,
        func.count(Alert.id).label("count")
    ).filter(
        and_(Alert.timestamp >= since, Alert.mitre_technique_id.isnot(None))
    ).group_by(Alert.mitre_technique_id, Alert.mitre_technique, Alert.mitre_tactic).order_by(
        desc("count")
    ).limit(15).all()
    
    return {
        "top_attacker_ips": [
            {"ip": a[0], "attack_count": a[1], "total_risk": round(a[2] or 0, 2)}
            for a in top_attackers
        ],
        "most_targeted_systems": [
            {"system": t[0], "count": t[1], "attack_type": t[2]}
            for t in targeted
        ],
        "attack_categories": [
            {"type": c[0], "count": c[1], "severity": c[2]}
            for c in categories
        ],
        "threat_trends": [
            {"hour": t[0].isoformat(), "severity": t[1], "count": t[2]}
            for t in trends
        ],
        "mitre_techniques": [
            {"technique_id": m[0], "technique": m[1], "tactic": m[2], "count": m[3]}
            for m in mitre
        ],
    }


@router.get("/windows")
async def get_windows_analytics(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get Windows-specific security analytics."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Event ID frequency
    event_ids = db.query(
        LogEntry.event_id,
        func.count(LogEntry.id).label("count")
    ).filter(
        and_(
            LogEntry.timestamp >= since,
            LogEntry.source_type.like("windows_%"),
            LogEntry.event_id.isnot(None)
        )
    ).group_by(LogEntry.event_id).order_by(desc("count")).limit(20).all()
    
    # PowerShell events
    ps_events = db.query(
        LogEntry.event_type,
        func.count(LogEntry.id).label("count")
    ).filter(
        and_(
            LogEntry.timestamp >= since,
            LogEntry.source_type.like("%powershell%")
        )
    ).group_by(LogEntry.event_type).order_by(desc("count")).all()
    
    # RDP activity
    rdp_events = db.query(
        LogEntry.event_type,
        func.count(LogEntry.id).label("count")
    ).filter(
        and_(
            LogEntry.timestamp >= since,
            LogEntry.source_type.like("%rdp%")
        )
    ).group_by(LogEntry.event_type).order_by(desc("count")).all()
    
    # Process creation events
    process_events = db.query(
        LogEntry.process_name,
        func.count(LogEntry.id).label("count")
    ).filter(
        and_(
            LogEntry.timestamp >= since,
            LogEntry.process_name.isnot(None),
            LogEntry.event_id.in_(["4688", "1"])
        )
    ).group_by(LogEntry.process_name).order_by(desc("count")).limit(20).all()
    
    # Failed RDP logins
    failed_rdp = db.query(func.count(LogEntry.id)).filter(
        and_(
            LogEntry.timestamp >= since,
            LogEntry.source_type.like("%rdp%"),
            LogEntry.event_type.in_(["failed_login", "auth_failure"])
        )
    ).scalar()
    
    return {
        "event_id_frequency": [{"event_id": e[0], "count": e[1]} for e in event_ids],
        "powershell_events": [{"event_type": e[0], "count": e[1]} for e in ps_events],
        "rdp_events": [{"event_type": e[0], "count": e[1]} for e in rdp_events],
        "process_events": [{"process": p[0], "count": p[1]} for p in process_events],
        "failed_rdp_count": failed_rdp,
    }


@router.get("/network")
async def get_network_analytics(
    hours: int = Query(24, ge=1, le=720),
    db: Session = Depends(get_db),
    current_user = Depends(get_current_user),
):
    """Get network traffic analytics."""
    since = datetime.utcnow() - timedelta(hours=hours)
    
    # Traffic by source IP
    traffic = db.query(
        LogEntry.source_ip,
        func.count(LogEntry.id).label("request_count"),
    ).filter(
        and_(LogEntry.timestamp >= since, LogEntry.source_ip.isnot(None))
    ).group_by(LogEntry.source_ip).order_by(desc("request_count")).limit(20).all()
    
    # HTTP status distribution
    statuses = db.query(
        LogEntry.status_code,
        func.count(LogEntry.id).label("count")
    ).filter(
        and_(LogEntry.timestamp >= since, LogEntry.status_code.isnot(None))
    ).group_by(LogEntry.status_code).order_by(desc("count")).all()
    
    # Top endpoints
    endpoints = db.query(
        LogEntry.endpoint,
        func.count(LogEntry.id).label("count"),
        func.avg(LogEntry.status_code).label("avg_status")
    ).filter(
        and_(LogEntry.timestamp >= since, LogEntry.endpoint.isnot(None))
    ).group_by(LogEntry.endpoint).order_by(desc("count")).limit(20).all()
    
    return {
        "traffic_by_ip": [{"ip": t[0], "request_count": t[1]} for t in traffic],
        "status_distribution": [{"status": s[0], "count": s[1]} for s in statuses],
        "top_endpoints": [
            {"endpoint": e[0], "count": e[1], "avg_status": round(e[2] or 0)}
            for e in endpoints
        ],
    }
