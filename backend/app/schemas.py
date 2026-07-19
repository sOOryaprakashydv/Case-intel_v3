from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel


class CaseSummary(BaseModel):
    id: str
    case_number: str
    label: Optional[str]
    verdict: str
    risk_score: int
    risk_level: str
    upload_timestamp: datetime

    class Config:
        from_attributes = True


class CaseDetail(CaseSummary):
    file_name: str
    sha256: str
    sha1: Optional[str]
    md5: Optional[str]
    mitre_techniques: list = []
    risk_contributions: dict = {}
    executive_summary: Optional[str]
    key_findings: list = []
    recommendation: Optional[str]
    confidence: Optional[int]
    narrative: Optional[str]
    examiner: Optional[str]
    dynamic_analysis_status: str


class AnalystNoteCreate(BaseModel):
    analyst: str
    note: str


class InvestigationOutcomeCreate(BaseModel):
    action_type: str
    action_detail: Optional[str] = None
    result_metric: Optional[int] = None
    result_label: Optional[str] = None


class CorrelationMatch(BaseModel):
    matched_case_id: str
    matched_case_number: Optional[str] = None
    matched_case_label: Optional[str] = None
    similarity_score: int
    matched_features: list = []
    feature_breakdown: dict = {}
    confidence_bucket: str


class DashboardStats(BaseModel):
    most_common_mitre_technique: Optional[str]
    top_malware_family: Optional[str]
    average_risk_score: float
    most_common_ioc: Optional[str]
    top_domain: Optional[str]
    top_correlated_cases: list[dict] = []
    most_reused_investigation_technique: Optional[dict] = None
