"""
Pydantic schemas for request/response validation.
"""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


# ============= AUTH SCHEMAS =============

class UserCreate(BaseModel):
    """User registration schema."""
    username: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = Field(None, max_length=255)


class UserLogin(BaseModel):
    """User login schema."""
    username: str
    password: str


class UserResponse(BaseModel):
    """User response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    username: str
    email: str
    full_name: Optional[str]
    is_active: bool
    role: str
    created_at: datetime


class TokenResponse(BaseModel):
    """Token response schema."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


# ============= LOG SCHEMAS =============

class LogEntryCreate(BaseModel):
    """Schema for creating a log entry."""
    timestamp: datetime
    source_type: str
    raw_log: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    hostname: Optional[str] = None
    process_name: Optional[str] = None
    event_id: Optional[str] = None
    request_method: Optional[str] = None
    endpoint: Optional[str] = None
    status_code: Optional[int] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    operating_system: Optional[str] = None
    parsed_data: Optional[Dict[str, Any]] = None


class LogEntryResponse(BaseModel):
    """Log entry response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    timestamp: datetime
    source_ip: Optional[str]
    destination_ip: Optional[str]
    username: Optional[str]
    hostname: Optional[str]
    process_name: Optional[str]
    event_id: Optional[str]
    request_method: Optional[str]
    endpoint: Optional[str]
    status_code: Optional[int]
    event_type: Optional[str]
    severity: Optional[str]
    operating_system: Optional[str]
    source_type: str
    source_file: Optional[str]
    raw_log: str
    parsed_data: Optional[Dict[str, Any]]
    ingestion_time: datetime


class LogUploadResponse(BaseModel):
    """Response for log upload."""
    message: str
    logs_processed: int
    logs_inserted: int
    parsing_errors: int
    source_type: str
    filename: str
    processing_time_ms: float


class LogSearchRequest(BaseModel):
    """Schema for log search."""
    query: Optional[str] = None
    source_type: Optional[str] = None
    severity: Optional[str] = None
    source_ip: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    event_type: Optional[str] = None
    page: int = 1
    page_size: int = 50


class LogSearchResponse(BaseModel):
    """Response for log search."""
    total: int
    page: int
    page_size: int
    logs: List[LogEntryResponse]


# ============= ALERT SCHEMAS =============

class AlertCreate(BaseModel):
    """Schema for creating an alert."""
    severity: str
    attack_type: str
    source_ip: Optional[str] = None
    affected_system: Optional[str] = None
    description: str
    recommendation: Optional[str] = None
    log_entry_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    risk_score: float = 0.0
    confidence: float = 0.0


class AlertResponse(BaseModel):
    """Alert response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    alert_id: str
    timestamp: datetime
    severity: str
    attack_type: str
    source_ip: Optional[str]
    affected_system: Optional[str]
    description: str
    recommendation: Optional[str]
    status: str
    mitre_tactic: Optional[str]
    mitre_technique: Optional[str]
    mitre_technique_id: Optional[str]
    risk_score: float
    confidence: float
    created_at: datetime
    updated_at: datetime
    log_entry: Optional[LogEntryResponse] = None


class AlertUpdate(BaseModel):
    """Schema for updating an alert."""
    status: Optional[str] = None
    assigned_user_id: Optional[str] = None
    severity: Optional[str] = None


class AlertStats(BaseModel):
    """Alert statistics."""
    total_alerts: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]
    by_attack_type: Dict[str, int]
    recent_alerts: List[AlertResponse]


# ============= ANALYTICS SCHEMAS =============

class DashboardStats(BaseModel):
    """Dashboard statistics."""
    total_logs: int
    total_alerts: int
    active_threats: int
    alerts_today: int
    logs_today: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    top_source_ips: List[Dict[str, Any]]
    top_attack_types: List[Dict[str, Any]]
    severity_distribution: Dict[str, int]
    logs_over_time: List[Dict[str, Any]]
    alerts_over_time: List[Dict[str, Any]]
    uptime_percentage: float
    average_latency_ms: float
    anomaly_count: int


class ThreatAnalytics(BaseModel):
    """Threat analytics response."""
    top_attacker_ips: List[Dict[str, Any]]
    most_targeted_endpoints: List[Dict[str, Any]]
    attack_categories: List[Dict[str, Any]]
    threat_trends: List[Dict[str, Any]]
    geographic_distribution: List[Dict[str, Any]]
    risk_scores: List[Dict[str, Any]]


# ============= ML SCHEMAS =============

class AnomalyResponse(BaseModel):
    """Anomaly response schema."""
    model_config = ConfigDict(from_attributes=True)
    
    id: str
    timestamp: datetime
    anomaly_score: float
    anomaly_type: Optional[str]
    features: Optional[Dict[str, Any]]
    cluster_id: Optional[int]
    cluster_label: Optional[str]
    model_version: Optional[str]
    log_entry: Optional[LogEntryResponse] = None


class MLTrainRequest(BaseModel):
    """Request to train ML model."""
    model_type: str = "isolation_forest"
    contamination: float = 0.1
    n_estimators: int = 100
    sample_size: Optional[int] = None


class MLTrainResponse(BaseModel):
    """Response from ML training."""
    message: str
    model_id: str
    model_type: str
    samples_used: int
    training_time_ms: float
    metrics: Dict[str, Any]


class ClusteringResponse(BaseModel):
    """Clustering results."""
    clusters: List[Dict[str, Any]]
    total_clusters: int
    silhouette_score: Optional[float]


# ============= WEBSOCKET SCHEMAS =============

class WSMessage(BaseModel):
    """WebSocket message schema."""
    type: str  # alert, log, stats, ping
    data: Dict[str, Any]
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ============= EXPORT SCHEMAS =============

class ExportRequest(BaseModel):
    """Export request schema."""
    format: str  # csv, pdf
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    source_type: Optional[str] = None
    severity: Optional[str] = None
