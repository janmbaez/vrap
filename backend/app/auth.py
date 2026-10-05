import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pwdlib import PasswordHash
from sqlalchemy import select, delete
from .db import get_db
from .models import User, Session, Audit
from .config import settings
from .schemas import Login

router = APIRouter(prefix='/auth', tags=['Authentication'])
passwords = PasswordHash.recommended()
DUMMY_HASH = passwords.hash(secrets.token_urlsafe(32))

def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()

def require_user(request: Request, db=Depends(get_db)):
    token = request.cookies.get('vrap_session', '')
    session = db.get(Session, digest(token)) if token else None
    if not session or session.expires_at.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise HTTPException(401, 'Sign in required')
    user = db.get(User, session.user_id)
    if not user or not user.active:
        raise HTTPException(401, 'Sign in required')
    if request.method not in ('GET', 'HEAD', 'OPTIONS'):
        if not secrets.compare_digest(session.csrf_hash, digest(request.headers.get('x-csrf-token', ''))):
            raise HTTPException(403, 'Invalid CSRF token')
    request.state.session = session
    return user

def roles(*allowed):
    def check(user=Depends(require_user)):
        if user.role not in allowed:
            raise HTTPException(403, 'Your role cannot perform this action')
        return user
    return check

writer = roles('Administrator', 'Security Analyst')
admin = roles('Administrator')

@router.post('/login')
def login(data: Login, request: Request, response: Response, db=Depends(get_db)):
    if request.headers.get('origin') not in (None, settings().app_origin):
        raise HTTPException(403, 'Origin not allowed')
    # Database-backed per-account throttle survives API process restarts.
    since = datetime.now(timezone.utc) - timedelta(minutes=15)
    failures = db.scalars(select(Audit).where(Audit.action == 'login.failed', Audit.created_at > since)).all()
    if sum(a.details.get('username') == data.username for a in failures) >= 8:
        raise HTTPException(429, 'Too many attempts. Try again in 15 minutes.')
    user = db.scalar(select(User).where(User.username == data.username))
    valid = passwords.verify(data.password, user.password_hash if user else DUMMY_HASH)
    if not user or not valid or not user.active:
        db.add(Audit(action='login.failed', entity='session', details={'username': data.username}))
        db.commit()
        raise HTTPException(401, 'Invalid username or password')
    old = request.cookies.get('vrap_session')
    if old:
        db.execute(delete(Session).where(Session.id == digest(old)))
    token, csrf = secrets.token_urlsafe(48), secrets.token_urlsafe(32)
    db.add(Session(id=digest(token), user_id=user.id, csrf_hash=digest(csrf), expires_at=datetime.now(timezone.utc) + timedelta(hours=settings().session_hours), workspace=data.environment))
    db.add(Audit(actor_id=user.id, action='login.success', entity='session', details={'environment': data.environment}))
    db.commit()
    response.set_cookie('vrap_session', token, httponly=True, secure=settings().cookie_secure, samesite='strict', max_age=settings().session_hours * 3600, path='/api')
    # CSRF cookie readable by same-origin frontend; opaque session stays HttpOnly.
    response.set_cookie('vrap_csrf', csrf, secure=settings().cookie_secure, samesite='strict', max_age=settings().session_hours * 3600, path='/')
    return {'id': user.id, 'username': user.username, 'role': user.role, 'environment': data.environment}

@router.get('/me')
def me(request: Request, user=Depends(require_user)):
    # The workspace is carried by the server-side session, never trusted from query parameters.
    return {'id': user.id, 'username': user.username, 'role': user.role, 'environment': request.state.session.workspace}

@router.post('/logout')
def logout(request: Request, response: Response, user=Depends(require_user), db=Depends(get_db)):
    db.execute(delete(Session).where(Session.id == request.state.session.id))
    db.add(Audit(actor_id=user.id, action='logout', entity='session'))
    db.commit()
    response.delete_cookie('vrap_session', path='/api')
    response.delete_cookie('vrap_csrf', path='/')
    return {'ok': True}
