from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .config import settings
from .database import init_db
from .routers import upload, cases, dashboard, reports

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    description="Case-Correlated, Explainable Malware Investigation Platform "
                 "(static-analysis + correlation deployment — dynamic sandbox not yet integrated)",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(upload.router)
app.include_router(cases.router)
app.include_router(dashboard.router)
app.include_router(reports.router)


@app.on_event("startup")
def on_startup():
    init_db()


@app.get("/api/health")
def health():
    return {"status": "ok", "service": settings.APP_NAME, "version": settings.VERSION}
