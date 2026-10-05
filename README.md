# Vulnerability Risk Assessment Platform (VRAP)

VRAP is an analyst workbench that turns technical vulnerability evidence into a versioned, explainable organizational risk assessment. It keeps technical severity, inherent risk, contextual risk, validated compensating controls, residual risk, appetite comparison, and the final decision distinct.

The MVP includes authentication and roles, separate Demo and Production workspaces, a security dashboard, manual findings, authoritative asset context and subnet/tag/hostname rules, a three-column assessment workbench, live deterministic scoring, a GRC 5×5 matrix crosswalk, immutable assessment revisions, audit history, versioned methodology administration, CSV/XLSX imports, and an isolated Tenable Vulnerability Management connector. The included records are synthetic demo data.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the architecture, database model, API contract, scoring methodology, security model, and phased roadmap.

## Run with Docker Compose

Docker Desktop or another Docker daemon must be running.

1. Copy `.env.example` to `.env`, replace both passwords, and generate a Fernet key for `CREDENTIAL_ENCRYPTION_KEY` with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.
2. Run `docker compose up -d --build`.
3. Bootstrap the administrator and synthetic demo records:

   ```sh
   docker compose exec \
     -e BOOTSTRAP_USER=admin \
     -e BOOTSTRAP_PASSWORD='your-long-unique-password' \
     api python -m app.seed --demo
   ```

4. Open <http://localhost:8080> and sign in with the bootstrap account.

The web service binds to localhost by default. For an organizational deployment, place it behind TLS, set `APP_ORIGIN` to the public origin, set `COOKIE_SECURE=true`, use managed secrets and PostgreSQL backups, and retain audit logs outside the application database.

Tenable credentials are optional. In Administration, enter the access key, secret key, and the default Tenable Vulnerability Management URL, `https://cloud.tenable.com`. The backend encrypts saved keys with `CREDENTIAL_ENCRYPTION_KEY`; it never returns them to the browser. Environment variables remain available for deployment-managed secrets.

## Local development without Docker

```sh
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cd frontend && npm install && cd ..
mkdir -p .local
export DATABASE_URL="sqlite:///$PWD/.local/vrap.db"
export COOKIE_SECURE=false
export APP_ORIGIN=http://localhost:5173
export CREDENTIAL_ENCRYPTION_KEY="$(.venv/bin/python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')"
cd backend && ../.venv/bin/alembic upgrade head
BOOTSTRAP_PASSWORD='your-long-unique-password' ../.venv/bin/python -m app.seed --demo
../.venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second terminal, run `cd frontend && npm run dev`, then open <http://localhost:5173>.

## Verification

```sh
.venv/bin/python -m pytest -q backend/tests
cd frontend && npm run build
docker compose config
```

Live Tenable synchronization requires tenant credentials and appropriate export permissions. Docker runtime validation requires an active Docker daemon.
