.PHONY: test build demo up down

test:
	.venv/bin/python -m pytest -q backend/tests
	cd frontend && npm run build

build:
	docker compose build

up:
	docker compose up -d --build

demo:
	docker compose exec -e BOOTSTRAP_USER="$${BOOTSTRAP_USER:-admin}" -e BOOTSTRAP_PASSWORD="$${BOOTSTRAP_PASSWORD}" api python -m app.seed --demo

down:
	docker compose down
