"""
Dashboard Analytics (Section 7.15). Includes the two v3.0 metrics that
exist specifically to make the Knowledge Base's value visible:
Top Correlated Cases, and Most Reused Investigation Technique.
"""
from collections import Counter
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..database import get_db
from ..models import Case, Fingerprint, IOC, CorrelationResult, InvestigationOutcome, ThreatIntelResult

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/stats")
def dashboard_stats(db: Session = Depends(get_db)):
    cases = db.query(Case).all()

    # Most common MITRE technique
    mitre_counter = Counter()
    for c in cases:
        for t in (c.mitre_techniques or []):
            mitre_counter[t.get("name", t.get("id"))] += 1
    most_common_mitre = mitre_counter.most_common(1)[0][0] if mitre_counter else None

    # Top malware family
    family_counter = Counter(
        fp.malware_family for fp in db.query(Fingerprint).all() if fp.malware_family
    )
    top_family = family_counter.most_common(1)[0][0] if family_counter else None

    # Average risk score
    avg_risk = db.query(func.avg(Case.risk_score)).scalar() or 0.0

    # Most common IOC
    ioc_counter = Counter(i.value for i in db.query(IOC).all())
    top_ioc = ioc_counter.most_common(1)[0][0] if ioc_counter else None

    # Top domain (from IOC type=domain)
    domain_counter = Counter(
        i.value for i in db.query(IOC).filter(IOC.ioc_type == "domain").all()
    )
    top_domain = domain_counter.most_common(1)[0][0] if domain_counter else None

    # Top Correlated Cases (New, v3.0) — cases most frequently matched
    match_counter = Counter(cr.matched_case_id for cr in db.query(CorrelationResult).all())
    top_correlated = []
    for case_id, count in match_counter.most_common(5):
        case = db.query(Case).filter(Case.id == case_id).first()
        if case:
            top_correlated.append({
                "case_id": case_id, "case_number": case.case_number,
                "label": case.label, "times_matched": count,
            })

    # Most Reused Investigation Technique (New, v3.0)
    outcomes = db.query(InvestigationOutcome).all()
    technique_counter = Counter(o.action_type for o in outcomes)
    most_reused = None
    if technique_counter:
        top_technique, uses = technique_counter.most_common(1)[0]
        metrics = [o.result_metric for o in outcomes if o.action_type == top_technique and o.result_metric is not None]
        success_rate = (sum(1 for m in metrics if m > 0) / len(metrics) * 100) if metrics else 0
        most_reused = {
            "technique": top_technique,
            "times_used": uses,
            "success_rate": round(success_rate, 1),
        }

    return {
        "most_common_mitre_technique": most_common_mitre,
        "top_malware_family": top_family,
        "average_risk_score": round(avg_risk, 1),
        "most_common_ioc": top_ioc,
        "top_domain": top_domain,
        "top_correlated_cases": top_correlated,
        "most_reused_investigation_technique": most_reused,
        "total_cases": len(cases),
        "correlation_engine_runs": len(cases),  # runs on 100% of completed cases (Section 12)
    }
