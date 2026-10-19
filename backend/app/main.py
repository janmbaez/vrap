from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError
from .db import SessionLocal
from .models import SyncJob, now
from .auth import router as auth_router
from .api.core import router as core_router
from .api.classification_jobs import router as classification_jobs_router, start_worker
from .api.imports import router as imports_router
from .api.tenable import router as tenable_router
from .api.governance import router as governance_router
from .api.campaigns import router as campaigns_router
from .api.campaign_exports import router as campaign_exports_router

@asynccontextmanager
async def lifespan(_app):
    # BackgroundTasks are process-local. A restart cannot resume one, so make
    # its historical job truthful instead of blocking every future sync.
    with SessionLocal() as db:
        try:
            abandoned = db.scalars(select(SyncJob).where(SyncJob.status.in_(('Running', 'Cancel requested')))).all()
        except OperationalError:
            # The isolated test database is initialized after application startup.
            db.rollback()
            abandoned = []
        for job in abandoned:
            job.status, job.finished_at = 'Interrupted', now()
            job.error = job.error or 'Sync stopped when the application restarted; no active worker remains.'
        if abandoned:
            db.commit()
    worker_stop = start_worker()
    try:
        yield
    finally:
        worker_stop.set()

app = FastAPI(title='VRAP', version='1.0.0', docs_url='/api/docs', openapi_url='/api/openapi.json', redoc_url=None, lifespan=lifespan)
for router in (classification_jobs_router, auth_router, core_router, imports_router, tenable_router, governance_router, campaigns_router, campaign_exports_router):
    app.include_router(router, prefix='/api')

@app.middleware('http')
async def security_headers(request: Request, call_next):
    # Includes multipart framing around the 100 MiB import file limit.
    if int(request.headers.get('content-length', '0') or '0') > 105 * 1024 * 1024:
        return JSONResponse({'detail': 'Request exceeds 105 MiB'}, status_code=413)
    response = await call_next(request)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Cache-Control'] = 'no-store'
    # The API only returns data, never executable page content. Keep its
    # browser policy deliberately restrictive even when the SPA is hosted by a
    # separate reverse proxy.
    response.headers['Content-Security-Policy'] = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'"
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-site'
    response.headers['Permissions-Policy'] = 'camera=(), geolocation=(), microphone=()'
    response.headers['X-Permitted-Cross-Domain-Policies'] = 'none'
    if request.url.scheme == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

@app.exception_handler(IntegrityError)
async def conflict(request, exc):
    return JSONResponse({'detail': 'A conflicting record already exists. Reload and try again.'}, status_code=409)

@app.exception_handler(Exception)
async def safe_error(request, exc):
    return JSONResponse({'detail': 'The request could not be completed. Contact your administrator.'}, status_code=500)

@app.get('/api/health')
def health():
    """Liveness only: the process can answer HTTP."""
    return {'status': 'ok'}

@app.get('/api/health/ready')
def readiness():
    """Readiness: database access is available before a proxy sends traffic."""
    try:
        with SessionLocal() as db:
            db.execute(select(1))
    except OperationalError:
        raise HTTPException(503, 'Database is not ready')
    return {'status': 'ready'}
