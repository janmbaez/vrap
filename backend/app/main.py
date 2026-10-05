from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy.exc import IntegrityError
from .auth import router as auth_router
from .api.core import router as core_router
from .api.imports import router as imports_router
from .api.tenable import router as tenable_router
from .api.governance import router as governance_router

app = FastAPI(title='VRAP', version='1.0.0', docs_url='/api/docs', openapi_url='/api/openapi.json', redoc_url=None)
for router in (auth_router, core_router, imports_router, tenable_router, governance_router):
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
    return response

@app.exception_handler(IntegrityError)
async def conflict(request, exc):
    return JSONResponse({'detail': 'A conflicting record already exists. Reload and try again.'}, status_code=409)

@app.exception_handler(Exception)
async def safe_error(request, exc):
    return JSONResponse({'detail': 'The request could not be completed. Contact your administrator.'}, status_code=500)

@app.get('/api/health')
def health():
    return {'status': 'ok'}
