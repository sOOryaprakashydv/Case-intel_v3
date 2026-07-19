"""
Upload pipeline (Section 6), scoped to this deployment:
1. Upload PE file           -> here
2. Hash calculation         -> here
3. VirusTotal lookup        -> here
4. Static analysis          -> here
[5. Dynamic sandbox]        -> SKIPPED (no sandbox infra in this deployment)
6. Merge results            -> here
7. Risk score               -> here
8. Extract IOCs             -> here
9. MITRE mapping            -> here (static-inferable only)
10. Correlate w/ KB         -> here
11. Investigation Accel.    -> here
12. Investigation Summary   -> here
13. Store in KB             -> here (this whole thing IS the KB)
14. Export report           -> separate endpoint, see routers/reports.py
"""
import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor

from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Form
from sqlalchemy.orm import Session

from ..database import get_db
from ..config import settings
from ..models import Case, StaticAnalysis, Fingerprint, IOC, ThreatIntelResult, Verdict
from ..services import static_analysis, virustotal, threat_intel, risk_score, correlation, acceleration
from ..schemas import CaseDetail
from ..auth import require_api_key

router = APIRouter(prefix="/api/upload", tags=["upload"])

_executor = ThreadPoolExecutor(max_workers=4)


def _safe_filename(name: str) -> str:
    """
    Strip directory components and anything but a conservative charset.
    Prevents path traversal via a crafted filename (e.g. "../../etc/passwd")
    and null-byte tricks. Never trust file.filename as a path fragment.
    """
    base = os.path.basename(name or "upload.bin")
    base = base.replace("\x00", "")
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base)
    return base[:255] or "upload.bin"


def _next_case_number(db: Session) -> str:
    count = db.query(Case).count()
    return f"Case-{count + 1}"


def _infer_mitre_from_static(sa_result: dict) -> list[dict]:
    """
    Static-only MITRE inference. Genuinely limited compared to dynamic
    behavioral mapping — this deployment is honest about that gap
    (see Known Limitations in the PRD).
    """
    techniques = []
    if sa_result.get("is_packed"):
        techniques.append({
            "id": "T1027", "name": "Obfuscated Files or Information",
            "description": "Binary shows packing/high entropy consistent with obfuscation.",
            "confidence": 70,
        })
    for match in sa_result.get("yara_matches", []):
        if "anti" in match["rule"].lower() and "debug" in match["rule"].lower():
            techniques.append({
                "id": "T1622", "name": "Debugger Evasion",
                "description": "Anti-debugging API references detected in static strings/imports.",
                "confidence": 60,
            })
    if not sa_result.get("is_signed"):
        techniques.append({
            "id": "T1036", "name": "Masquerading (unsigned binary)",
            "description": "Binary is unsigned, a common (weak) masquerading/evasion signal.",
            "confidence": 30,
        })
    return techniques


def _fired_rules_from_static(sa_result: dict, vt_result: dict) -> set[str]:
    fired = set()
    if sa_result.get("is_packed"):
        fired.add("packed_binary")
    if sa_result.get("entropy", 0) > 7.0:
        fired.add("high_entropy")
    if sa_result.get("packer_signature"):
        fired.add("upx_signature")
    if not sa_result.get("is_signed"):
        fired.add("unsigned_binary")
    if vt_result.get("found") and vt_result.get("malicious_count", 0) > 0:
        fired.add("known_malicious_hash")
    return fired


def _extract_iocs(sa_result: dict, vt_result: dict, hashes: dict) -> list[dict]:
    iocs = [
        {"ioc_type": "sha256", "value": hashes["sha256"]},
        {"ioc_type": "sha1", "value": hashes["sha1"]},
        {"ioc_type": "md5", "value": hashes["md5"]},
    ]
    for s in sa_result.get("strings_sample", []):
        if s.startswith("HKEY_") or "\\Run\\" in s:
            iocs.append({"ioc_type": "registry_key", "value": s})
        elif s.startswith(("http://", "https://")):
            iocs.append({"ioc_type": "url", "value": s})
    return iocs


@router.post("", response_model=CaseDetail, dependencies=[Depends(require_api_key)])
async def upload_sample(
    file: UploadFile = File(...),
    examiner: str = Form(default="Unassigned"),
    db: Session = Depends(get_db),
):
    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024

    # Read in chunks and enforce the size cap as we go, rather than trusting
    # the client-reported `file.size` (unreliable on streamed uploads) or
    # buffering an unbounded amount of attacker-controlled data first.
    contents = bytearray()
    while chunk := await file.read(1024 * 1024):
        contents.extend(chunk)
        if len(contents) > max_bytes:
            raise HTTPException(413, f"File exceeds {settings.MAX_UPLOAD_SIZE_MB}MB limit")
    contents = bytes(contents)

    safe_name = _safe_filename(file.filename)
    temp_path = os.path.join(settings.UPLOAD_DIR, f"{uuid.uuid4()}_{safe_name}")
    with open(temp_path, "wb") as f:
        f.write(contents)

    try:
        # Step 2: Hash calculation
        hashes = static_analysis.hash_file(temp_path)

        # Duplicate detection against the FULL Knowledge Base (Section 7.1)
        existing = db.query(Case).filter(Case.sha256 == hashes["sha256"]).first()
        if existing:
            raise HTTPException(409, f"Duplicate of {existing.case_number} (already in Knowledge Base)")

        # Step 3 + 4 run concurrently: VirusTotal lookup, static analysis
        future_vt = _executor.submit(virustotal.lookup_hash, hashes["sha256"])
        future_sa = _executor.submit(static_analysis.analyze_pe, temp_path)
        vt_result = future_vt.result()
        sa_result = future_sa.result()

        # [Step 5 skipped: dynamic sandbox analysis — not in this deployment]

        # Step 7: Risk score
        fired = _fired_rules_from_static(sa_result, vt_result)
        risk = risk_score.calculate_risk(fired)

        # Step 8: IOC extraction
        ioc_list = _extract_iocs(sa_result, vt_result, hashes)

        # Step 9: MITRE mapping (static-inferable)
        mitre = _infer_mitre_from_static(sa_result)

        verdict = Verdict.malicious if risk.score >= 50 or (vt_result.get("malicious_count", 0) > 3) else (
            Verdict.suspicious if risk.score >= 25 else Verdict.clean
        )

        case = Case(
            case_number=_next_case_number(db),
            file_name=file.filename,
            sha256=hashes["sha256"], sha1=hashes["sha1"], md5=hashes["md5"],
            file_size=len(contents),
            verdict=verdict,
            risk_score=risk.score,
            risk_level=risk.level,
            risk_contributions=risk.contributions,
            mitre_techniques=mitre,
            examiner=examiner,
            key_findings=_build_key_findings(sa_result, vt_result, ioc_list),
            recommendation="Escalate" if risk.level in ("high", "critical") else (
                "Monitor" if risk.level == "medium" else "No action required"
            ),
            confidence=max([t["confidence"] for t in mitre], default=50),
            narrative=_build_narrative(sa_result, vt_result, risk),
        )
        db.add(case)
        db.flush()  # get case.id before creating children

        db.add(StaticAnalysis(case_id=case.id, **sa_result))

        fp = Fingerprint(
            case_id=case.id,
            sha256=hashes["sha256"],
            certificate_thumbprint=(sa_result.get("signature_info") or {}).get("thumbprint"),
            malware_family=(vt_result.get("names") or [None])[0],
            mitre_technique_ids=[t["id"] for t in mitre],
        )
        db.add(fp)

        for ioc in ioc_list:
            db.add(IOC(case_id=case.id, **ioc))

        ti_enrichment = threat_intel.enrich_case(hashes["sha256"], domains=[], ips=[])
        db.add(ThreatIntelResult(
            case_id=case.id,
            virustotal=vt_result,
            malwarebazaar=ti_enrichment["malwarebazaar"],
            otx=ti_enrichment["otx"],
            urlhaus={"results": ti_enrichment["urlhaus"]},
            abuseipdb={"results": ti_enrichment["abuseipdb"]},
            community_tags=vt_result.get("community_tags", []),
        ))

        db.commit()
        db.refresh(case)

        # Step 10: Correlation Engine
        correlation.run_correlation(db, case.id)

        # Step 11: Investigation Acceleration — computed on read, not stored redundantly here

        return case
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


def _build_key_findings(sa_result, vt_result, ioc_list) -> list[str]:
    findings = []
    if sa_result.get("is_packed"):
        findings.append(f"Packed binary ({sa_result.get('packer_signature') or 'high entropy'})")
    if vt_result.get("found"):
        findings.append(f"VirusTotal: {vt_result.get('detection_ratio')}")
    else:
        findings.append("Not previously seen by VirusTotal")
    if not sa_result.get("is_signed"):
        findings.append("Unsigned binary")
    findings.append(f"{len(ioc_list)} IOC(s) extracted")
    return findings


def _build_narrative(sa_result, vt_result, risk) -> str:
    parts = [
        f"Static analysis measured file entropy at {sa_result.get('entropy')}, "
        f"{'indicating likely packing.' if sa_result.get('is_packed') else 'within normal range.'}",
    ]
    if vt_result.get("found"):
        parts.append(f"VirusTotal reports {vt_result.get('detection_ratio')} engines flagging this hash.")
    else:
        parts.append("This hash was not previously known to VirusTotal at analysis time.")
    parts.append(f"Overall risk score: {risk.score} ({risk.level}), based on disclosed rule weights.")
    return " ".join(parts)
