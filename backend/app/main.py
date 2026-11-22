import logging
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import desc, func, select, text
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.config import get_settings
from app.database import engine, get_db
from app.models import DashboardSnapshot, ExposureRecord

settings = get_settings()
logging.basicConfig(level=settings.log_level.upper())
logger = logging.getLogger("prioris.api")

app = FastAPI(
    title="PRIORIS API",
    version="0.1.0",
    description="Read API for evidence-preserving PRIORIS dashboard snapshots.",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=False,
    allow_methods=["GET"],
    allow_headers=["Content-Type", "X-Request-ID"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        return response


app.add_middleware(SecurityHeadersMiddleware)


@app.get("/", tags=["service"])
def service_info():
    return {"service": "PRIORIS API", "version": app.version, "docs": "/docs"}


@app.get("/health/live", tags=["health"])
def liveness():
    return {"status": "ok", "service": "prioris-api"}


@app.get("/health/ready", tags=["health"])
def readiness():
    if engine is None:
        raise HTTPException(status_code=503, detail="Database is not configured")
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        logger.exception("Readiness check failed")
        raise HTTPException(status_code=503, detail="Database is unavailable")
    return {"status": "ready", "service": "prioris-api"}


def latest_snapshot(db: Session) -> DashboardSnapshot:
    snapshot = db.scalar(
        select(DashboardSnapshot).order_by(desc(DashboardSnapshot.generated_at)).limit(1)
    )
    if snapshot is None:
        raise HTTPException(status_code=404, detail="No dashboard snapshot has been imported")
    return snapshot


@app.get("/api/v1/dashboard/summary", tags=["dashboard"])
def dashboard_summary(db: Session = Depends(get_db)):
    return latest_snapshot(db).summary


@app.get("/api/v1/assets", tags=["dashboard"])
def dashboard_assets(db: Session = Depends(get_db)):
    return latest_snapshot(db).summary.get("assets", [])


@app.get("/api/v1/vulnerabilities", tags=["dashboard"])
def dashboard_vulnerabilities(db: Session = Depends(get_db)):
    return latest_snapshot(db).summary.get("cves", [])


def exposure_page(
    view_name: str,
    offset: int,
    limit: int,
    asset_id: str | None,
    cve_id: str | None,
    risk_tier: str | None,
    db: Session,
):
    snapshot = latest_snapshot(db)
    filters = [
        ExposureRecord.snapshot_id == snapshot.id,
        ExposureRecord.view_name == view_name,
    ]
    if asset_id:
        filters.append(ExposureRecord.asset_id == asset_id)
    if cve_id:
        filters.append(ExposureRecord.cve_id == cve_id.upper())
    if risk_tier:
        filters.append(ExposureRecord.risk_tier == risk_tier.lower())

    total = db.scalar(
        select(func.count()).select_from(ExposureRecord).where(*filters)
    ) or 0
    rows = db.scalars(
        select(ExposureRecord)
        .where(*filters)
        .order_by(ExposureRecord.risk_score.desc().nullslast(), ExposureRecord.record_id.asc())
        .offset(offset)
        .limit(limit)
    ).all()
    return {
        "view": view_name,
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [row.payload for row in rows],
    }


@app.get("/api/v1/exposures/confirmed", tags=["exposures"])
def confirmed_exposures(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    asset_id: str | None = None,
    cve_id: str | None = None,
    risk_tier: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    db: Session = Depends(get_db),
):
    return exposure_page("confirmed", offset, limit, asset_id, cve_id, risk_tier, db)


@app.get("/api/v1/exposures/review", tags=["exposures"])
def review_exposures(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    asset_id: str | None = None,
    cve_id: str | None = None,
    risk_tier: str | None = Query(None, pattern="^(critical|high|medium|low)$"),
    db: Session = Depends(get_db),
):
    return exposure_page("review", offset, limit, asset_id, cve_id, risk_tier, db)
