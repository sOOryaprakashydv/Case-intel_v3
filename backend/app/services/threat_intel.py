"""
Optional (Free) threat-intel integrations (PRD Section 9).
Each function fails soft (returns {"available": False, "error": ...})
rather than raising, so one missing/rate-limited API never blocks the
rest of the pipeline. All are called concurrently from routers/upload.py.
"""
import os
import httpx

MALWAREBAZAAR_URL = "https://mb-api.abuse.ch/api/v1/"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"
URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/"
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")  # optional, raises free-tier limits


def query_malwarebazaar(sha256: str) -> dict:
    try:
        headers = {"Auth-Key": MALWAREBAZAAR_API_KEY} if MALWAREBAZAAR_API_KEY else {}
        resp = httpx.post(
            MALWAREBAZAAR_URL,
            data={"query": "get_info", "hash": sha256},
            headers=headers,
            timeout=15,
        )
        data = resp.json()
        if data.get("query_status") != "ok":
            return {"available": True, "found": False}
        sample = data["data"][0]
        return {
            "available": True,
            "found": True,
            "family": sample.get("signature"),
            "file_type": sample.get("file_type"),
            "tags": sample.get("tags", []),
            "first_seen": sample.get("first_seen"),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def query_otx(sha256: str) -> dict:
    if not OTX_API_KEY:
        return {"available": False, "error": "OTX_API_KEY not configured"}
    try:
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        resp = httpx.get(
            f"{OTX_BASE_URL}/indicators/file/{sha256}/general",
            headers=headers,
            timeout=15,
        )
        if resp.status_code != 200:
            return {"available": True, "found": False}
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("pulses", [])
        return {
            "available": True,
            "found": bool(pulses),
            "pulse_count": len(pulses),
            "pulse_names": [p.get("name") for p in pulses[:10]],
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def query_urlhaus(domain_or_url: str) -> dict:
    try:
        resp = httpx.post(URLHAUS_URL + "url/", data={"url": domain_or_url}, timeout=15)
        data = resp.json()
        if data.get("query_status") != "ok":
            return {"available": True, "found": False}
        return {
            "available": True,
            "found": True,
            "threat": data.get("threat"),
            "tags": data.get("tags", []),
            "date_added": data.get("date_added"),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def query_abuseipdb(ip: str) -> dict:
    if not ABUSEIPDB_API_KEY:
        return {"available": False, "error": "ABUSEIPDB_API_KEY not configured"}
    try:
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        resp = httpx.get(
            ABUSEIPDB_URL,
            headers=headers,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        if resp.status_code != 200:
            return {"available": True, "found": False}
        data = resp.json().get("data", {})
        return {
            "available": True,
            "found": True,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "total_reports": data.get("totalReports"),
            "country_code": data.get("countryCode"),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}


def enrich_case(sha256: str, domains: list[str], ips: list[str]) -> dict:
    """Convenience aggregator called once per upload."""
    result = {
        "malwarebazaar": query_malwarebazaar(sha256),
        "otx": query_otx(sha256),
        "urlhaus": [query_urlhaus(d) for d in domains[:5]],
        "abuseipdb": [query_abuseipdb(ip) for ip in ips[:5]],
    }
    return result
