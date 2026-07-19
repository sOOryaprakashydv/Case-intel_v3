"""
Investigation Acceleration (PRD Section 7.12).

Deterministic, ranked display of previously-recorded, structured outcome
data. Never AI-generated, never a guess. If no matched case has a
recorded outcome, the card is omitted rather than populated.

Ranking rule: among the recorded outcomes of the most similar prior
case(s), the recommendation with the strongest recorded result (highest
result_metric) wins. Ties broken by most recent (Section 7.10 v3.0 —
this is also how conflicting structured outcomes are resolved).
"""
from sqlalchemy.orm import Session
from ..models import CorrelationResult, InvestigationOutcome


def get_recommended_next_step(db: Session, case_id: str) -> dict | None:
    top_correlations = (
        db.query(CorrelationResult)
        .filter(CorrelationResult.source_case_id == case_id)
        .order_by(CorrelationResult.similarity_score.desc())
        .limit(5)
        .all()
    )
    if not top_correlations:
        return None

    matched_case_ids = [c.matched_case_id for c in top_correlations]
    outcomes = (
        db.query(InvestigationOutcome)
        .filter(InvestigationOutcome.case_id.in_(matched_case_ids))
        .order_by(
            InvestigationOutcome.result_metric.desc().nullslast(),
            InvestigationOutcome.recorded_at.desc(),
        )
        .all()
    )
    if not outcomes:
        # No recorded outcome on any matched case — omit, don't guess.
        return None

    best = outcomes[0]
    source_correlation = next(c for c in top_correlations if c.matched_case_id == best.case_id)

    return {
        "run": best.action_type,
        "detail": best.action_detail,
        "reason": f"This matched Case {best.case_id[:8]} (similarity {source_correlation.similarity_score}%)",
        "result": best.result_label,
        "confidence": source_correlation.similarity_score,
    }


def get_suggested_investigation(db: Session, case_id: str) -> dict | None:
    """
    Aggregate pattern across correlated cases rather than a single
    outcome — e.g. "N of the top correlated cases used persistence."
    """
    top_correlations = (
        db.query(CorrelationResult)
        .filter(CorrelationResult.source_case_id == case_id)
        .order_by(CorrelationResult.similarity_score.desc())
        .limit(10)
        .all()
    )
    if not top_correlations:
        return None

    persistence_hits = sum(
        1 for c in top_correlations if "mitre_overlap" in (c.matched_features or [])
    )
    if persistence_hits == 0:
        return None

    return {
        "check": "Scheduled Tasks / Registry Run Keys",
        "reason": f"Previous {persistence_hits} correlated sample(s) used a MITRE-overlapping persistence technique.",
    }
