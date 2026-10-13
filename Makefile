# Copyright (c) 2026 Md. Moshiur Rahman Mohi / THAMJJ13.TOP. Proprietary. All Rights Reserved.
#
# Common tasks. `make help` lists everything.
.DEFAULT_GOAL := help
SHELL := /bin/bash
PYTHON ?= .venv/bin/python
PIP ?= .venv/bin/pip
COMPOSE ?= docker compose
ENV_FILE ?= .env

.PHONY: help venv install fmt lint typecheck test test-cov verify migrate revision \
        create-admin worker api scan audit-deps backup clean docker-build docker-up \
        docker-down docker-logs prod-check

help: ## show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

venv: ## create the local virtualenv (Python 3.12 preferred, 3.11 minimum)
	python3 -m venv .venv && $(PIP) install --upgrade pip

install: ## install the package with dev dependencies
	$(PIP) install -e ".[dev]"

fmt: ## format code
	$(PYTHON) -m ruff format app tests scripts migrations
	$(PYTHON) -m ruff check --fix app tests scripts migrations

lint: ## lint
	$(PYTHON) -m ruff format --check app tests scripts migrations
	$(PYTHON) -m ruff check app tests scripts migrations

typecheck: ## static types (strict)
	$(PYTHON) -m mypy app

test: ## run the test suite
	$(PYTHON) -m pytest -q

test-cov: ## run the test suite with coverage
	$(PYTHON) -m pytest -q --cov=app --cov-report=term-missing --cov-report=html

scan: ## scan the tree for committed secrets
	$(PYTHON) scripts/secret_scan.py

audit-deps: ## dependency vulnerability audit
	$(PYTHON) -m pip_audit

verify: lint typecheck scan test ## everything CI runs

migrate: ## apply migrations locally
	$(PYTHON) -m alembic upgrade head

revision: ## autogenerate a migration: make revision m="add approvals index"
	$(PYTHON) -m alembic revision --autogenerate -m "$(m)"

create-admin: ## create/promote an account: make create-admin email=owner@example.com
	$(PYTHON) -m app.cli.create_admin --email "$(email)" --name "$(name)" --role "$(role=admin)"

api: ## run the API locally
	$(PYTHON) -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

worker: ## run the worker locally
	$(PYTHON) -m app.jobs.run_worker

backup: ## encrypted database backup (requires DATABASE_URL + BACKUP_ENCRYPTION_PASSWORD)
	./scripts/backup.sh

prod-check: ## validate a production .env without starting the app
	ENVIRONMENT=production $(PYTHON) -c "from app.config import Settings; Settings(); print('production configuration is valid')"

docker-build: ## build the application image
	$(COMPOSE) build

docker-up: ## start the full stack
	$(COMPOSE) --env-file $(ENV_FILE) up -d

docker-down: ## stop the stack
	$(COMPOSE) --env-file $(ENV_FILE) down

docker-logs: ## tail the API logs
	$(COMPOSE) --env-file $(ENV_FILE) logs -f api

clean: ## remove caches and local runtime data
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage data var/sites var/images
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
