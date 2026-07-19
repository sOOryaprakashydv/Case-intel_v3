from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Case, AnalystNote, InvestigationOutcome, CorrelationResult
from ..schemas import CaseDetail, AnalystNoteCreate, InvestigationOutcomeCreate, CorrelationMatch
from ..services import correlation, acceleration
from ..auth import require_api_key

router = APIRouter(prefix="/api/cases", tags=["cases"])


@router.get("", response_model=list[CaseDetail])
def list_cases(db: Session = Depends(get_db)):
    return db.query(Case).order_by(Case.upload_timestamp.desc()).all()


@router.get("/{case_id}", response_model=CaseDetail)
def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    return case


@router.get("/{case_id}/correlations")
def get_correlations(case_id: str, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")

    results = (
        db.query(CorrelationResult)
        .filter(CorrelationResult.source_case_id == case_id)
        .order_by(CorrelationResult.similarity_score.desc())
        .all()
    )

    if not results:
        total_kb = db.query(Case).count()
        return {"no_match": correlation.no_match_card(total_kb), "matches": []}

    matches = []
    for r in results:
        matched_case = db.query(Case).filter(Case.id == r.matched_case_id).first()
        matches.append({
            "matched_case_id": r.matched_case_id,
            "matched_case_number": matched_case.case_number if matched_case else None,
            "matched_case_label": matched_case.label if matched_case else None,
            "similarity_score": r.similarity_score,
            "matched_features": r.matched_features,
            "feature_breakdown": r.feature_breakdown,
            "confidence_bucket": r.confidence_bucket,
        })
    return {"no_match": None, "matches": matches}


@router.get("/{case_id}/acceleration")
def get_acceleration(case_id: str, db: Session = Depends(get_db)):
    return {
        "recommended_next_step": acceleration.get_recommended_next_step(db, case_id),
        "suggested_investigation": acceleration.get_suggested_investigation(db, case_id),
    }


@router.post("/{case_id}/notes", dependencies=[Depends(require_api_key)])
def add_note(case_id: str, payload: AnalystNoteCreate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    note = AnalystNote(case_id=case_id, analyst=payload.analyst, note=payload.note)
    db.add(note)
    db.commit()
    db.refresh(note)
    return note


@router.get("/{case_id}/notes")
def list_notes(case_id: str, db: Session = Depends(get_db)):
    # Most recent first, labeled "Latest" client-side — never merged or hidden (Section 7.10 v3.0)
    return (
        db.query(AnalystNote)
        .filter(AnalystNote.case_id == case_id)
        .order_by(AnalystNote.created_at.desc())
        .all()
    )


@router.post("/{case_id}/outcomes", dependencies=[Depends(require_api_key)])
def add_outcome(case_id: str, payload: InvestigationOutcomeCreate, db: Session = Depends(get_db)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    outcome = InvestigationOutcome(case_id=case_id, **payload.model_dump())
    db.add(outcome)
    db.commit()
    db.refresh(outcome)
    return outcome
