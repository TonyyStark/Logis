"""
SQLAlchemy database models for the CyberAI SOC Platform.
"""
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, BigInteger, Float, Boolean, 
    DateTime, Text, JSON, ForeignKey, Index, Enum
)
from sqlalchemy.orm import relationship
from enum import Enum as PyEnum
from app.database import Base


def generate_uuid():
    """Generate a unique UUID string."""
    return str(uuid.uuid4())


class SeverityLevel(PyEnum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class LogSource(PyEnum):
    """Source types for logs."""
    LINUX_AUTH = "linux_auth"
    LINUX_SYSLOG = "linux_syslog"
    LINUX_SSH = "linux_ssh"
    LINUX_SUDO = "linux_sudo"
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSTEM = "windows_system"
    WINDOWS_POWERSHELL = "windows_powershell"
    WINDOWS_SYSMON = "windows_sysmon"
    WINDOWS_DEFENDER = "windows_defender"
    WINDOWS_RDP = "windows_rdp"
    APACHE_ACCESS = "apache_access"
    APACHE_ERROR = "apache_error"
    NGINX = "nginx"
    JSON_LOG = "json_log"
    GENERIC = "generic"


class AlertStatus(PyEnum):
    """Alert status types."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class User(Base):
    """User model for authentication."""
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(100), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(255), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    role = Column(String(50), default="analyst")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    alerts = relationship("Alert", back_populates="assigned_user")


class LogEntry(Base):
    """Normalized log entry model."""
    __tablename__ = "log_entries"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Normalized fields
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)  # IPv6 compatible
    destination_ip = Column(String(45), nullable=True)
    username = Column(String(255), nullable=True, index=True)
    hostname = Column(String(255), nullable=True, index=True)
    process_name = Column(String(255), nullable=True)
    event_id = Column(String(50), nullable=True, index=True)
    request_method = Column(String(10), nullable=True)
    endpoint = Column(Text, nullable=True)
    status_code = Column(Integer, nullable=True)
    event_type = Column(String(100), nullable=True, index=True)
    severity = Column(String(20), nullable=True)
    operating_system = Column(String(50), nullable=True)
    
    # Source information
    source_type = Column(String(50), nullable=False, index=True)
    source_file = Column(String(500), nullable=True)
    
    # Raw log
    raw_log = Column(Text, nullable=False)
    parsed_data = Column(JSON, nullable=True)
    
    # Metadata
    ingestion_time = Column(DateTime, default=datetime.utcnow)
    log_hash = Column(String(64), unique=True, nullable=True, index=True)
    
    # Relationships
    alerts = relationship("Alert", back_populates="log_entry")
    anomalies = relationship("Anomaly", back_populates="log_entry")
    
    # Indexes
    __table_args__ = (
        Index("idx_log_timestamp_source", "timestamp", "source_type"),
        Index("idx_log_source_ip_time", "source_ip", "timestamp"),
    )


class Alert(Base):
    """Security alert model."""
    __tablename__ = "alerts"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    alert_id = Column(String(50), unique=True, nullable=False, index=True)
    
    # Alert details
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    severity = Column(String(20), nullable=False, index=True)
    attack_type = Column(String(100), nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    affected_system = Column(String(255), nullable=True, index=True)
    description = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=True)
    
    # MITRE ATT&CK mapping
    mitre_tactic = Column(String(100), nullable=True)
    mitre_technique = Column(String(100), nullable=True)
    mitre_technique_id = Column(String(20), nullable=True)
    
    # Status
    status = Column(String(20), default="new", index=True)
    
    # Relationships
    log_entry_id = Column(String(36), ForeignKey("log_entries.id"), nullable=True)
    log_entry = relationship("LogEntry", back_populates="alerts")
    
    assigned_user_id = Column(String(36), ForeignKey("users.id"), nullable=True)
    assigned_user = relationship("User", back_populates="alerts")
    
    # Score
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    
    # Indexes
    __table_args__ = (
        Index("idx_alert_severity_status", "severity", "status"),
        Index("idx_alert_attack_type", "attack_type", "timestamp"),
    )


class Anomaly(Base):
    """ML-detected anomaly model."""
    __tablename__ = "anomalies"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Anomaly details
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    anomaly_score = Column(Float, nullable=False)
    anomaly_type = Column(String(100), nullable=True)
    features = Column(JSON, nullable=True)
    
    # Clustering info
    cluster_id = Column(Integer, nullable=True, index=True)
    cluster_label = Column(String(100), nullable=True)
    
    # Relationships
    log_entry_id = Column(String(36), ForeignKey("log_entries.id"), nullable=True)
    log_entry = relationship("LogEntry", back_populates="anomalies")
    
    # Model info
    model_version = Column(String(50), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)


class ThreatScore(Base):
    """Threat score model for IPs, users, endpoints."""
    __tablename__ = "threat_scores"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    # Entity being scored
    entity_type = Column(String(50), nullable=False, index=True)  # ip, user, endpoint, process
    entity_value = Column(String(255), nullable=False, index=True)
    
    # Scores
    overall_score = Column(Float, default=0.0)  # 0-100
    frequency_score = Column(Float, default=0.0)
    severity_score = Column(Float, default=0.0)
    behavior_score = Column(Float, default=0.0)
    reputation_score = Column(Float, default=0.0)
    
    # Details
    total_events = Column(Integer, default=0)
    alert_count = Column(Integer, default=0)
    anomaly_count = Column(Integer, default=0)
    first_seen = Column(DateTime, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    
    # MITRE categories observed
    mitre_techniques = Column(JSON, nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Indexes
    __table_args__ = (
        Index("idx_threat_entity", "entity_type", "entity_value"),
        Index("idx_threat_score", "overall_score", "last_seen"),
    )


class MLModel(Base):
    """ML model tracking."""
    __tablename__ = "ml_models"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    
    model_name = Column(String(100), nullable=False)
    model_version = Column(String(50), nullable=False)
    model_type = Column(String(50), nullable=False)  # isolation_forest, clustering, etc.
    file_path = Column(String(500), nullable=True)
    
    # Training info
    training_date = Column(DateTime, default=datetime.utcnow)
    samples_used = Column(Integer, default=0)
    features_used = Column(JSON, nullable=True)
    
    # Performance metrics
    accuracy = Column(Float, nullable=True)
    precision_score = Column(Float, nullable=True)
    recall_score = Column(Float, nullable=True)
    f1_score = Column(Float, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)


class DashboardStat(Base):
    """Cached dashboard statistics."""
    __tablename__ = "dashboard_stats"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    stat_name = Column(String(100), nullable=False, unique=True)
    stat_value = Column(JSON, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
