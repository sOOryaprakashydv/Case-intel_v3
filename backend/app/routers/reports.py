from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import Case, Report
from ..services import reports as report_service
from ..auth import require_api_key

router = APIRouter(prefix="/api/reports", tags=["reports"])


@router.post("/{case_id}/generate/{fmt}", dependencies=[Depends(require_api_key)])
def generate_report(case_id: str, fmt: str, generated_by: str = "system", db: Session = Depends(get_db)):
    if fmt not in ("pdf", "html", "csv"):
        raise HTTPException(400, "format must be pdf, html, or csv")
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(404, "Case not found")
    report = report_service.save_report(db, case, fmt, generated_by)
    return report


@router.get("/history")
def report_history(db: Session = Depends(get_db)):
    reports = db.query(Report).order_by(Report.generated_at.desc()).all()
    return [
        {
            "id": r.id, "case_id": r.case_id, "file_name": r.file_name,
            "format": r.format, "version": r.version,
            "generated_by": r.generated_by, "generated_at": r.generated_at,
        }
        for r in reports
    ]


@router.get("/{report_id}/download")
def download_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")
    return FileResponse(report.storage_path, filename=report.file_name)


@router.delete("/{report_id}", dependencies=[Depends(require_api_key)])
def delete_report(report_id: str, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(404, "Report not found")
    db.delete(report)
    db.commit()
    return {"deleted": True}
