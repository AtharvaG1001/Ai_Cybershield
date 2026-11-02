"""
Pydantic schemas for request validation and response serialization.
"""
from __future__ import annotations
from typing import Optional, List, Dict, Any
from datetime import datetime
from pydantic import BaseModel, field_validator, HttpUrl
import re


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

class URLScanRequest(BaseModel):
    url: str

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty.")
        if len(v) > 2048:
            raise ValueError("URL must not exceed 2048 characters.")
        # Add scheme if missing
        if not re.match(r"^https?://", v, re.IGNORECASE):
            v = "https://" + v
        return v


class EmailScanRequest(BaseModel):
    raw_email: str

    @field_validator("raw_email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Email content must not be empty.")
        if len(v) > 500_000:
            raise ValueError("Email content must not exceed 500,000 characters.")
        return v


# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

class FindingResponse(BaseModel):
    id: str
    finding_type: str
    severity: str
    title: str
    description: str
    evidence: Optional[str] = None
    evidence_source: Optional[str] = None


class ScanSummary(BaseModel):
    id: str
    scan_type: str
    input_value: str
    risk_category: str
    risk_score: float
    verdict: str
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    scan_status: str
    created_at: datetime

    class Config:
        from_attributes = True


class ScanDetail(ScanSummary):
    findings: List[FindingResponse] = []
    model_version: Optional[str] = None


class URLScanResponse(BaseModel):
    scan_id: str
    status: str
    url: str
    normalized_url: str
    risk_score: float
    risk_category: str
    verdict: str
    ml_prediction: Optional[str] = None
    ml_confidence: Optional[float] = None
    phishing_probability: Optional[float] = None
    legitimate_probability: Optional[float] = None
    url_features: Dict[str, Any] = {}
    rule_findings: List[Dict[str, Any]] = []
    ssl: Dict[str, Any] = {}
    dns: Dict[str, Any] = {}
    whois: Dict[str, Any] = {}
    keywords: Dict[str, Any] = {}
    findings: List[Dict[str, Any]] = []
    warnings: List[str] = []
    recommendations: List[str] = []
    scan_timestamp: str
    model_version: Optional[str] = None
    limitations: List[str] = []


class EmailScanResponse(BaseModel):
    scan_id: str
    status: str
    risk_score: float
    risk_category: str
    verdict: str
    sender: Optional[str] = None
    subject: Optional[str] = None
    link_count: int = 0
    links: List[str] = []
    findings: List[Dict[str, Any]] = []
    warnings: List[str] = []
    recommendations: List[str] = []
    scan_timestamp: str
    keyword_analysis: Dict[str, Any] = {}
    sender_analysis: Dict[str, Any] = {}
    link_analysis: Dict[str, Any] = {}
    spam_analysis: Dict[str, Any] = {}


class DashboardSummary(BaseModel):
    total_scans: int
    url_scans: int
    email_scans: int
    high_risk_count: int
    critical_count: int
    safe_count: int
    recent_scans: List[ScanSummary] = []
    risk_distribution: Dict[str, int] = {}
    scans_today: int


class ModelStatus(BaseModel):
    loaded: bool
    model_type: str
    n_features: int
    model_version: str
    feature_names: List[str] = []


class ModelMetrics(BaseModel):
    available: bool
    model_version: str
    dataset_id: str
    evaluated_at: Optional[str] = None
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    roc_auc: Optional[float] = None
    false_positive_rate: Optional[float] = None
    false_negative_rate: Optional[float] = None
    dataset_size: Optional[int] = None
    phishing_count: Optional[int] = None
    legitimate_count: Optional[int] = None
    confusion_matrix: Optional[List[List[int]]] = None


class HealthResponse(BaseModel):
    status: str
    model_loaded: bool
    database_ok: bool
    version: str


class IntegrationStatus(BaseModel):
    name: str
    configured: bool
    available: bool
    note: str


class IntegrationsResponse(BaseModel):
    integrations: List[IntegrationStatus]


class ScansListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    scans: List[ScanSummary]
