"""
CaseIntel database models.

Schema notes (per PRD Section 11):
- Every table is keyed to `case_id` so the Correlation Engine can join
  fingerprint / IOC / notes / outcomes for any pair of cases cheaply.
- Static-analysis-only MVP: dynamic_analysis fields exist but are nullable
  and unused until sandbox infra is available (see Known Limitations).
"""
import uuid
import enum
from datetime import datetime

from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime, ForeignKey,
    Text, JSON, Enum as SAEnum, UniqueConstraint, Index
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship, declarative_base

Base = declarative_base()


def gen_uuid():
    return str(uuid.uuid4())


class Verdict(str, enum.Enum):
    malicious = "malicious"
    suspicious = "suspicious"
    clean = "clean"
    unknown = "unknown"


class RiskLevel(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Case(Base):
    """One row per completed (or in-progress) investigation."""
    __tablename__ = "cases"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_number = Column(String(32), unique=True, nullable=False, index=True)  # e.g. "Case-17"
    label = Column(String(255), nullable=True)          # short human label, e.g. "Fake SBI"
    file_name = Column(String(512), nullable=False)
    sha256 = Column(String(64), nullable=False, index=True)
    sha1 = Column(String(40), nullable=True)
    md5 = Column(String(32), nullable=True, index=True)
    file_size = Column(Integer, nullable=True)

    verdict = Column(SAEnum(Verdict), default=Verdict.unknown, nullable=False)
    risk_score = Column(Integer, default=0)
    risk_level = Column(SAEnum(RiskLevel), default=RiskLevel.low)
    risk_contributions = Column(JSON, default=dict)   # {"rule": {"weight": int, "counted": bool, "group": str}}

    mitre_techniques = Column(JSON, default=list)      # [{"id","name","description","confidence"}]

    # Chain of custody
    examiner = Column(String(255), nullable=True)
    upload_timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Structured summary (Section 7.6)
    executive_summary = Column(Text, nullable=True)
    key_findings = Column(JSON, default=list)          # ["Embedded EXE", "No IOC", ...]
    recommendation = Column(String(64), nullable=True) # "Monitor" | "Escalate" | "Run sandbox"
    confidence = Column(Integer, nullable=True)         # 0-100
    narrative = Column(Text, nullable=True)

    # Dynamic analysis placeholders — unused in this deployment (no sandbox infra yet)
    dynamic_analysis_status = Column(String(32), default="not_run")  # not_run | queued | complete
    dynamic_analysis_data = Column(JSON, nullable=True)

    static_analysis = relationship("StaticAnalysis", back_populates="case", uselist=False, cascade="all,delete")
    fingerprint = relationship("Fingerprint", back_populates="case", uselist=False, cascade="all,delete")
    iocs = relationship("IOC", back_populates="case", cascade="all,delete")
    notes = relationship("AnalystNote", back_populates="case", cascade="all,delete")
    outcomes = relationship("InvestigationOutcome", back_populates="case", cascade="all,delete")
    reports = relationship("Report", back_populates="case", cascade="all,delete")
    threat_intel = relationship("ThreatIntelResult", back_populates="case", uselist=False, cascade="all,delete")

    correlations_as_source = relationship(
        "CorrelationResult", foreign_keys="CorrelationResult.source_case_id", back_populates="source_case"
    )

    __table_args__ = (Index("ix_cases_sha256_verdict", "sha256", "verdict"),)


class StaticAnalysis(Base):
    __tablename__ = "static_analysis"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False, unique=True)

    pe_header = Column(JSON, default=dict)
    imports = Column(JSON, default=list)
    exports = Column(JSON, default=list)
    sections = Column(JSON, default=list)      # [{"name","entropy","virtual_size","raw_size"}]
    entropy = Column(Float, nullable=True)      # overall file entropy
    is_signed = Column(Boolean, default=False)
    signature_info = Column(JSON, default=dict)
    strings_sample = Column(JSON, default=list)  # truncated list of interesting strings
    yara_matches = Column(JSON, default=list)    # [{"rule","tags","meta"}]
    is_packed = Column(Boolean, default=False)
    packer_signature = Column(String(128), nullable=True)  # e.g. "UPX"

    case = relationship("Case", back_populates="static_analysis")


class Fingerprint(Base):
    """
    The comparable feature-set used by the Correlation Engine.
    Kept as its own table (not just JSON on Case) so correlation queries
    can index/filter on these columns directly (Section 10 perf note).
    """
    __tablename__ = "fingerprints"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False, unique=True)

    sha256 = Column(String(64), nullable=False, index=True)
    ssdeep = Column(String(256), nullable=True)          # fuzzy hash, candidate pruning
    tlsh = Column(String(128), nullable=True)

    certificate_thumbprint = Column(String(128), nullable=True, index=True)
    certificate_subject = Column(String(512), nullable=True)

    c2_domains = Column(JSON, default=list)               # list[str], indexed via GIN in migration
    c2_ips = Column(JSON, default=list)
    embedded_config_hash = Column(String(64), nullable=True, index=True)  # e.g. Firebase-style config

    malware_family = Column(String(128), nullable=True, index=True)
    permissions = Column(JSON, default=list)              # capability/permission strings
    mitre_technique_ids = Column(JSON, default=list)       # ["T1547.001", ...]

    case = relationship("Case", back_populates="fingerprint")

    __table_args__ = (
        Index("ix_fingerprint_cert", "certificate_thumbprint"),
        Index("ix_fingerprint_family", "malware_family"),
    )


class IOC(Base):
    __tablename__ = "iocs"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False)
    ioc_type = Column(String(32), nullable=False)   # md5|sha1|sha256|ip|domain|url|registry_key|mutex|file_path
    value = Column(String(1024), nullable=False, index=True)

    case = relationship("Case", back_populates="iocs")

    __table_args__ = (Index("ix_ioc_type_value", "ioc_type", "value"),)


class ThreatIntelResult(Base):
    __tablename__ = "threat_intel_results"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False, unique=True)

    virustotal = Column(JSON, default=dict)   # detection_ratio, av_verdicts, community_score, relationships
    malwarebazaar = Column(JSON, default=dict)
    otx = Column(JSON, default=dict)
    urlhaus = Column(JSON, default=dict)
    abuseipdb = Column(JSON, default=dict)

    community_tags = Column(JSON, default=list)  # e.g. contains-pe, long-sleeps, anti-debug
    last_seen = Column(DateTime, nullable=True)

    case = relationship("Case", back_populates="threat_intel")


class AnalystNote(Base):
    """Free-text notes — never auto-resolved, never hidden (Section 7.10 v3.0)."""
    __tablename__ = "analyst_notes"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False)
    analyst = Column(String(255), nullable=False)
    note = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    case = relationship("Case", back_populates="notes")


class InvestigationOutcome(Base):
    """
    Structured outcome data ONLY — this is what Investigation Acceleration
    ranks on. Never free text, so subjective analyst disagreement can't
    change which recommendation surfaces (Section 7.10 v3.0).
    """
    __tablename__ = "investigation_outcomes"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False)
    action_type = Column(String(64), nullable=False)     # e.g. "proxy_log_query", "check_scheduled_tasks"
    action_detail = Column(String(512), nullable=True)   # e.g. the actual query used
    result_metric = Column(Integer, nullable=True)        # e.g. infected_host_count
    result_label = Column(String(255), nullable=True)     # e.g. "found 4 infected hosts"
    recorded_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    case = relationship("Case", back_populates="outcomes")

    __table_args__ = (Index("ix_outcome_case_metric", "case_id", "result_metric"),)


class CorrelationResult(Base):
    """
    Persisted correlation between two cases so the dashboard's
    'Top Correlated Cases' metric doesn't require recomputation (Section 7.15).
    """
    __tablename__ = "correlation_results"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    source_case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False)
    matched_case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False)

    similarity_score = Column(Integer, nullable=False)  # 0-100, capped
    matched_features = Column(JSON, default=list)        # ["certificate","embedded_config","url",...]
    feature_breakdown = Column(JSON, default=dict)       # {"certificate": 25, "infrastructure": 20, ...}
    confidence_bucket = Column(String(16), nullable=False)  # high|medium|low
    compared_against_count = Column(Integer, nullable=False)  # size of KB at comparison time

    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    source_case = relationship("Case", foreign_keys=[source_case_id], back_populates="correlations_as_source")
    matched_case = relationship("Case", foreign_keys=[matched_case_id])

    __table_args__ = (
        UniqueConstraint("source_case_id", "matched_case_id", name="uq_correlation_pair"),
        Index("ix_correlation_score", "similarity_score"),
    )


class Report(Base):
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=False), primary_key=True, default=gen_uuid)
    case_id = Column(UUID(as_uuid=False), ForeignKey("cases.id"), nullable=False)
    file_name = Column(String(512), nullable=False)
    format = Column(String(8), nullable=False)   # pdf|html|csv
    version = Column(String(16), default="v1")
    generated_by = Column(String(255), nullable=True)
    generated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    storage_path = Column(String(1024), nullable=False)

    case = relationship("Case", back_populates="reports")
