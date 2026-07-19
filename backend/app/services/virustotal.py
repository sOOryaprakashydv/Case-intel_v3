"""
VirusTotal Integration (PRD Section 7.2).

Free-tier constraints this is designed around:
- 4 requests/minute, 500/day
- No file upload on free tier — query by SHA256 only, which matches
  the PRD's "query by SHA256 first" requirement anyway.
- Must "handle API rate limits gracefully" (explicit requirement) —
  see the simple token-bucket throttle below.
"""
import os
import time
import threading
import httpx

VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

# --- Minimal rate limiter: 4 req/min free tier ---
_lock = threading.Lock()
_request_timestamps: list[float] = []
MAX_REQUESTS_PER_MINUTE = 4


def _throttle():
    with _lock:
        now = time.time()
        window_start = now - 60
        _request_timestamps[:] = [t for t in _request_timestamps if t > window_start]
        if len(_request_timestamps) >= MAX_REQUESTS_PER_MINUTE:
            sleep_for = 60 - (now - _request_timestamps[0]) + 0.5
            time.sleep(max(sleep_for, 0))
        _request_timestamps.append(time.time())


class VirusTotalError(Exception):
    pass


def lookup_hash(sha256: str) -> dict:
    """
    Returns a normalized dict:
    {detection_ratio, av_verdicts, community_score, relationships, tags, last_seen}
    Returns {"found": False} on a clean 404 (not yet in VT) rather than raising,
    since "not in VT" is a valid, expected result for a brand-new sample.
    """
    if not VT_API_KEY:
        return {"found": False, "error": "VIRUSTOTAL_API_KEY not configured"}

    _throttle()
    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE_URL}/files/{sha256}"

    try:
        resp = httpx.get(url, headers=headers, timeout=15)
    except httpx.RequestError as e:
        raise VirusTotalError(f"Network error contacting VirusTotal: {e}")

    if resp.status_code == 404:
        return {"found": False}
    if resp.status_code == 429:
        raise VirusTotalError("VirusTotal rate limit exceeded — back off and retry")
    if resp.status_code != 200:
        raise VirusTotalError(f"VirusTotal returned HTTP {resp.status_code}")

    data = resp.json().get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    total = sum(stats.values()) if stats else 0

    av_verdicts = {
        engine: result.get("category")
        for engine, result in data.get("last_analysis_results", {}).items()
        if result.get("category") in ("malicious", "suspicious")
    }

    return {
        "found": True,
        "detection_ratio": f"{malicious}/{total}",
        "malicious_count": malicious,
        "total_engines": total,
        "av_verdicts": av_verdicts,
        "community_score": data.get("reputation", 0),
        "community_tags": data.get("tags", []),
        "last_seen": data.get("last_analysis_date"),
        "names": data.get("names", []),
        "signature_info": data.get("signature_info", {}),
    }
