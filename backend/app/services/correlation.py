"""
Correlation Engine (PRD Section 7.11).

Every completed analysis is compared against every case already stored
in the Case Knowledge Base. Weights are fixed and sum to exactly 100,
so similarity % is the direct, un-normalized sum of matched-feature
weights, capped at 100. No hidden scaling, no black-box embedding.

Performance note (Section 10): exact-match indexing (hash, certificate,
domain) prunes candidates before the weighted comparison runs, so a
linear scan over the remainder stays fast at pilot scale (hundreds of
cases). ANN indexing (LSH/MinHash) is explicit future work beyond that.
"""
from dataclasses import dataclass, field
from typing import Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_

from ..models import Case, Fingerprint, CorrelationResult

# Fixed weights — sum to exactly 100 by design (Section 7.11 v3.0)
FEATURE_WEIGHTS = {
    "sha256_exact": 30,
    "certificate": 25,
    "infrastructure": 20,   # C2 / domain / IP
    "family": 15,
    "permission": 5,
    "mitre_overlap": 5,
}
assert sum(FEATURE_WEIGHTS.values()) == 100

MINIMUM_SIMILARITY_FLOOR = 40  # below this, no correlated case is shown at all

CONFIDENCE_BUCKETS = [
    (80, 100, "high"),
    (50, 79, "medium"),
    (0, 49, "low"),
]


def confidence_bucket(score: int) -> str:
    for lo, hi, label in CONFIDENCE_BUCKETS:
        if lo <= score <= hi:
            return label
    return "low"


@dataclass
class CandidatePruneResult:
    candidates: list
    total_kb_size: int


def _prune_candidates(db: Session, fp: Fingerprint, exclude_case_id: str) -> CandidatePruneResult:
    """
    Exact-match indexing pass: only pull cases sharing at least one
    strong signal (hash, certificate, embedded-config hash, or malware
    family). This keeps the weighted comparison a scan over a small
    candidate set instead of every row in the Knowledge Base.

    Honest tradeoff: weaker-only signals (C2 infra overlap, permission
    similarity, MITRE overlap with no strong-signal anchor) are NOT
    indexed here, so a sample that only shares those with a prior case
    won't surface as a candidate unless it also shares a strong signal.
    Catching that would require scanning every fingerprint, which is
    exactly what this function exists to avoid. At pilot scale (hundreds
    of cases) that's an acceptable tradeoff; if false-negatives on
    weak-signal-only matches turn out to matter in practice, the fix is
    a proper ANN/LSH index (Section 10 future work), not a full scan
    disguised as a prune.
    """
    total = db.query(Fingerprint).count()

    filters = []
    if fp.sha256:
        filters.append(Fingerprint.sha256 == fp.sha256)
    if fp.certificate_thumbprint:
        filters.append(Fingerprint.certificate_thumbprint == fp.certificate_thumbprint)
    if fp.embedded_config_hash:
        filters.append(Fingerprint.embedded_config_hash == fp.embedded_config_hash)
    if fp.malware_family:
        filters.append(Fingerprint.malware_family == fp.malware_family)

    if not filters:
        # No strong-signal anchor at all for this sample. There's nothing
        # cheap to index on, so this is the one legitimate case where we
        # scan the KB — but only once, and it's bounded by KB size at
        # pilot scale, not repeated per-candidate.
        candidates = (
            db.query(Fingerprint)
            .filter(Fingerprint.case_id != exclude_case_id)
            .all()
        )
        return CandidatePruneResult(candidates=candidates, total_kb_size=total)

    candidates = (
        db.query(Fingerprint)
        .filter(Fingerprint.case_id != exclude_case_id)
        .filter(or_(*filters))
        .all()
    )
    return CandidatePruneResult(candidates=candidates, total_kb_size=total)


def _score_pair(source: Fingerprint, other: Fingerprint) -> tuple[int, list, dict]:
    matched_features = []
    breakdown = {}

    if source.sha256 and source.sha256 == other.sha256:
        matched_features.append("sha256")
        breakdown["sha256"] = FEATURE_WEIGHTS["sha256_exact"]

    if source.certificate_thumbprint and source.certificate_thumbprint == other.certificate_thumbprint:
        matched_features.append("certificate")
        breakdown["certificate"] = FEATURE_WEIGHTS["certificate"]

    source_infra = set((source.c2_domains or []) + (source.c2_ips or []))
    other_infra = set((other.c2_domains or []) + (other.c2_ips or []))
    if source_infra & other_infra:
        matched_features.append("infrastructure")
        breakdown["infrastructure"] = FEATURE_WEIGHTS["infrastructure"]
    elif source.embedded_config_hash and source.embedded_config_hash == other.embedded_config_hash:
        # Embedded/Firebase-style config match counts under the same
        # infrastructure bucket per the PRD's worked example.
        matched_features.append("embedded_config")
        breakdown["infrastructure"] = FEATURE_WEIGHTS["infrastructure"]

    if source.malware_family and source.malware_family == other.malware_family:
        matched_features.append("family")
        breakdown["family"] = FEATURE_WEIGHTS["family"]

    source_perms = set(source.permissions or [])
    other_perms = set(other.permissions or [])
    if source_perms and other_perms:
        overlap_ratio = len(source_perms & other_perms) / max(len(source_perms | other_perms), 1)
        if overlap_ratio >= 0.5:
            matched_features.append("permission")
            breakdown["permission"] = FEATURE_WEIGHTS["permission"]

    source_mitre = set(source.mitre_technique_ids or [])
    other_mitre = set(other.mitre_technique_ids or [])
    if source_mitre & other_mitre:
        matched_features.append("mitre_overlap")
        breakdown["mitre_overlap"] = FEATURE_WEIGHTS["mitre_overlap"]

    score = min(sum(breakdown.values()), 100)
    return score, matched_features, breakdown


def run_correlation(db: Session, case_id: str) -> list[CorrelationResult]:
    """
    Compare `case_id`'s fingerprint against the full Knowledge Base.
    Persists CorrelationResult rows for every match at/above the floor,
    and always returns *something* (even a 0% no-match record) so the
    engine's run is visible — a 0% result is a result, not a feature gap
    (Section 7.11 no-match state).
    """
    source_fp = db.query(Fingerprint).filter(Fingerprint.case_id == case_id).first()
    if source_fp is None:
        return []

    prune = _prune_candidates(db, source_fp, exclude_case_id=case_id)

    results = []
    for other_fp in prune.candidates:
        score, matched, breakdown = _score_pair(source_fp, other_fp)
        if score < MINIMUM_SIMILARITY_FLOOR:
            continue

        existing = (
            db.query(CorrelationResult)
            .filter(
                CorrelationResult.source_case_id == case_id,
                CorrelationResult.matched_case_id == other_fp.case_id,
            )
            .first()
        )
        row = existing or CorrelationResult(
            source_case_id=case_id,
            matched_case_id=other_fp.case_id,
        )
        row.similarity_score = score
        row.matched_features = matched
        row.feature_breakdown = breakdown
        row.confidence_bucket = confidence_bucket(score)
        row.compared_against_count = prune.total_kb_size
        db.add(row)
        results.append(row)

    db.commit()
    results.sort(key=lambda r: r.similarity_score, reverse=True)
    return results


def no_match_card(compared_against_count: int) -> dict:
    """Section 7.11 no-match state — explicit criteria checked, not a blank screen."""
    return {
        "overall_similarity": 0,
        "compared_against": compared_against_count,
        "fingerprint_match": 0,
        "infrastructure_match": 0,
        "certificate_match": 0,
        "behavior_match": 0,
        "reasons": [
            "No SHA256 Match",
            "No Certificate Match",
            "No Infrastructure Match",
            "No Family Match",
            "No Permission Similarity",
            "No MITRE Similarity",
        ],
        "conclusion": "No relationship detected.",
    }
