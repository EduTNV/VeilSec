.PHONY: up down logs test lint migrate shell

up:
	cp -n .env.example .env 2>/dev/null || true
	docker compose up -d --build
	@echo "\n✅ VeilSec rodando em:"
	@echo "   API:    http://localhost:8000"
	@echo "   Docs:   http://localhost:8000/docs"
	@echo "   Flower: http://localhost:5555"
	@echo "   MinIO:  http://localhost:9001"

down:
	docker compose down -v

logs:
	docker compose logs -f api worker_sast worker_dast

logs-%:
	docker compose logs -f $*

test:
	pytest tests/ -v --cov=apps --cov=packages --cov-report=term-missing

test-unit:
	pytest tests/unit -v

test-security:
	pytest tests/security -v

lint:
	black . && ruff check . --fix

shell:
	docker compose exec api bash

migrate:
	docker compose exec api alembic upgrade head

migration:
	docker compose exec api alembic revision --autogenerate -m "$(name)"

status:
	docker compose ps

restart-%:
	docker compose restart $*

clean:
	docker compose down -v --remove-orphans
	docker system prune -f
