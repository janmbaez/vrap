import os
from cryptography.fernet import Fernet
os.environ.update(DATABASE_URL='sqlite://', COOKIE_SECURE='false', APP_ORIGIN='http://testserver',
                  CREDENTIAL_ENCRYPTION_KEY=Fernet.generate_key().decode())
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient
from app.main import app
from app.db import Base, get_db
from app.models import User, Methodology
from app.auth import passwords
from app.risk.policy import DEFAULT

@pytest.fixture
def db():
    engine = create_engine('sqlite://', connect_args={'check_same_thread':False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with sessionmaker(engine, expire_on_commit=False)() as session:
        for name, role in [('admin','Administrator'),('analyst','Security Analyst'),('viewer','Viewer')]:
            session.add(User(username=name, role=role, password_hash=passwords.hash('Test-password-123!')))
        session.add(Methodology(version='1.0', configuration=DEFAULT))
        session.commit()
        yield session
    engine.dispose()

@pytest.fixture
def client(db):
    def override(): yield db
    app.dependency_overrides[get_db] = override
    with TestClient(app) as client: yield client
    app.dependency_overrides.clear()

def login(client, username='admin', environment='Production'):
    assert client.post('/api/auth/login',json={'username':username,'password':'Test-password-123!','environment':environment}).status_code == 200
    client.headers['X-CSRF-Token'] = client.cookies.get('vrap_csrf')
