import os

class Settings:
    APP_NAME = "CaseIntel"
    VERSION = "3.0.0"

    CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")

    UPLOAD_DIR = os.getenv("UPLOAD_DIR", "/tmp/caseintel_uploads")
    REPORTS_DIR = os.getenv("REPORTS_DIR", "/tmp/caseintel_reports")

    MAX_UPLOAD_SIZE_MB = int(os.getenv("MAX_UPLOAD_SIZE_MB", "50"))

    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
    OTX_API_KEY = os.getenv("OTX_API_KEY", "")
    ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
    MALWAREBAZAAR_API_KEY = os.getenv("MALWAREBAZAAR_API_KEY", "")


settings = Settings()

os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
