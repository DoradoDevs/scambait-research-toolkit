"""
Scambait Research Suite - Pydantic Models

Data validation and serialization models for the API.
"""

from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# =============================================================================
# Enums
# =============================================================================

class SessionStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


class MessageDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class ScamType(str, Enum):
    CRYPTO = "crypto"
    ROMANCE = "romance"
    TECH_SUPPORT = "tech_support"
    INVESTMENT = "investment"
    LOTTERY = "lottery"
    PHISHING = "phishing"
    EMPLOYMENT = "employment"
    OTHER = "other"


class PatternType(str, Enum):
    URGENCY = "urgency"
    AUTHORITY = "authority"
    FEAR = "fear"
    GREED = "greed"
    SOCIAL_PROOF = "social_proof"
    RECIPROCITY = "reciprocity"


# =============================================================================
# Session Models
# =============================================================================

class SessionCreate(BaseModel):
    """Create a new research session."""
    scam_type: Optional[ScamType] = None
    source: Optional[str] = Field(None, description="Where the scam contact originated")
    title: Optional[str] = Field(None, description="Session title/label")
    script_id: Optional[str] = Field(None, description="ID of baiting script to use")
    notes: Optional[str] = None
    scammer_identifier: Optional[str] = Field(None, description="Scammer's username/ID")


class SessionUpdate(BaseModel):
    """Update session fields."""
    status: Optional[SessionStatus] = None
    scam_type: Optional[ScamType] = None
    source: Optional[str] = None
    title: Optional[str] = None
    script_id: Optional[str] = None
    notes: Optional[str] = None
    scammer_identifier: Optional[str] = None


class SessionResponse(BaseModel):
    """Session response model."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: datetime
    updated_at: datetime
    status: SessionStatus
    scam_type: Optional[str] = None
    source: Optional[str] = None
    title: Optional[str] = None
    script_id: Optional[str] = None
    notes: Optional[str] = None
    total_time_wasted_seconds: int = 0
    scammer_identifier: Optional[str] = None


class SessionWithMessages(SessionResponse):
    """Session with messages included."""
    messages: List["MessageResponse"] = []
    pattern_flags: List["PatternFlagResponse"] = []
    attachments: List["AttachmentResponse"] = []


# =============================================================================
# Message Models
# =============================================================================

class MessageCreate(BaseModel):
    """Create a new message."""
    session_id: str
    direction: MessageDirection
    content: str
    content_type: str = "text"
    metadata: Optional[Dict[str, Any]] = None
    apply_delay: bool = Field(False, description="Apply time-wasting delay")


class MessageResponse(BaseModel):
    """Message response model."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    timestamp: datetime
    direction: MessageDirection
    content: str
    content_type: str
    metadata: Optional[Dict[str, Any]] = None
    delay_applied_seconds: int = 0


# =============================================================================
# Metadata Models
# =============================================================================

class MetadataCapture(BaseModel):
    """Captured metadata from interaction."""
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    geo_data: Optional[Dict[str, Any]] = None
    fingerprint: Optional[str] = None
    additional: Optional[Dict[str, Any]] = None


class MetadataResponse(BaseModel):
    """Metadata response model."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    captured_at: datetime
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    geo_data: Optional[Dict[str, Any]] = None
    fingerprint: Optional[str] = None
    additional: Optional[Dict[str, Any]] = None


# =============================================================================
# Attachment Models
# =============================================================================

class AttachmentResponse(BaseModel):
    """Attachment response model."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    message_id: Optional[str] = None
    original_filename: str
    stored_filename: str
    file_size: int
    mime_type: str
    md5_hash: str
    sha256_hash: str
    sha1_hash: str
    analysis_result: Optional[Dict[str, Any]] = None
    is_malicious: bool = False
    uploaded_at: datetime


class HashResult(BaseModel):
    """File hash result."""
    md5: str
    sha1: str
    sha256: str
    file_size: int


class AnalysisResult(BaseModel):
    """Static analysis result."""
    file_type: str
    mime_type: str
    magic_signature: Optional[str] = None
    is_suspicious: bool = False
    suspicious_indicators: List[str] = []
    metadata_extracted: Optional[Dict[str, Any]] = None


# =============================================================================
# Pattern Detection Models
# =============================================================================

class PatternFlagCreate(BaseModel):
    """Create a pattern flag."""
    session_id: str
    pattern_type: PatternType
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: str
    message_id: Optional[str] = None


class PatternFlagResponse(BaseModel):
    """Pattern flag response model."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    session_id: str
    message_id: Optional[str] = None
    pattern_type: str
    confidence: float
    detected_at: datetime
    evidence: str


class PatternDetectionResult(BaseModel):
    """Result of pattern detection on text."""
    patterns_found: List[Dict[str, Any]] = []
    total_score: float = 0.0
    risk_level: str = "low"  # low, medium, high


# =============================================================================
# Script Models
# =============================================================================

class ScriptResponse(BaseModel):
    """Baiting script response model."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str] = None
    persona: str
    responses: List[Dict[str, Any]] = []
    delay_config: Dict[str, Any] = {}
    created_at: datetime


class SuggestedResponse(BaseModel):
    """Suggested response from script engine."""
    text: str
    delay_seconds: int = 0
    persona: str
    follow_up_hints: List[str] = []


# =============================================================================
# Link Analysis Models
# =============================================================================

class LinkAnalysis(BaseModel):
    """Link/URL analysis result."""
    original_url: str
    defanged_url: str
    domain: str
    is_suspicious: bool = False
    suspicious_indicators: List[str] = []
    pattern_matches: List[str] = []


# =============================================================================
# Wallet Honeypot Models
# =============================================================================

class WalletDisplay(BaseModel):
    """Fake wallet display data."""
    address: str
    balance_sol: float
    balance_usd: float
    network: str
    recent_transactions: List[Dict[str, Any]] = []
    disclaimer: str


class WalletInteraction(BaseModel):
    """Wallet interaction log."""
    session_id: Optional[str] = None
    action: str
    details: Optional[Dict[str, Any]] = None


# =============================================================================
# Report Models
# =============================================================================

class SessionReport(BaseModel):
    """Exported session report."""
    session: SessionResponse
    messages: List[MessageResponse] = []
    metadata: List[MetadataResponse] = []
    attachments: List[AttachmentResponse] = []
    pattern_flags: List[PatternFlagResponse] = []
    summary: Dict[str, Any] = {}
    generated_at: datetime
    research_metadata: Dict[str, Any] = {}


class DashboardStats(BaseModel):
    """Dashboard statistics."""
    total_sessions: int = 0
    active_sessions: int = 0
    completed_sessions: int = 0
    total_messages: int = 0
    total_time_wasted_seconds: int = 0
    total_attachments: int = 0
    malicious_attachments: int = 0
    scam_types_breakdown: Dict[str, int] = {}
    pattern_types_breakdown: Dict[str, int] = {}


# =============================================================================
# Audit Models
# =============================================================================

class AuditLogEntry(BaseModel):
    """Audit log entry."""
    model_config = ConfigDict(from_attributes=True)

    id: str
    timestamp: datetime
    action: str
    details: Optional[Dict[str, Any]] = None
    user_id: str = "researcher"
    ip_address: Optional[str] = None


# Update forward references
SessionWithMessages.model_rebuild()
