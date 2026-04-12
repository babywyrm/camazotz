.PHONY: help up up-local down logs test test-zitadel-flows build clean status ps env compose-gen helm-template qa qa-json smoke-local smoke-k8s smoke-local-llm smoke-k8s-llm smoke-local-identity smoke-k8s-identity smoke-local-identity-llm smoke-k8s-identity-llm

COMPOSE := docker compose -f compose/docker-compose.yml
ENV_FILE := compose/.env

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

env: ## Create .env from example if missing
	@test -f $(ENV_FILE) || cp compose/.env.example $(ENV_FILE)
	@echo "$(ENV_FILE) ready — add ANTHROPIC_API_KEY for cloud, or BRAIN_PROVIDER=bedrock + AWS settings"

build: env ## Build all container images
	$(COMPOSE) --env-file $(ENV_FILE) build

up: env ## Start stack (gateway + portal; default brain: Anthropic API)
	$(COMPOSE) --env-file $(ENV_FILE) up -d --build
	@echo ""
	@echo "  Portal:  http://localhost:3000"
	@echo "  Gateway: http://localhost:8080"
	@echo ""

up-local: env ## Start with local provider (Ollama)
	BRAIN_PROVIDER=local $(COMPOSE) --env-file $(ENV_FILE) --profile local up -d --build
	@echo ""
	@echo "  Portal:  http://localhost:3000"
	@echo "  Gateway: http://localhost:8080"
	@echo "  Ollama:  http://localhost:11434"
	@echo ""
	@echo "  Model will be pulled automatically by ollama-init."
	@echo "  Run 'make logs-init' to watch progress."
	@echo ""

down: ## Stop all services and remove containers
	$(COMPOSE) --env-file $(ENV_FILE) --profile local down

clean: down ## Stop services and remove volumes
	$(COMPOSE) --env-file $(ENV_FILE) --profile local down -v
	docker network rm camazotz 2>/dev/null || true

ps: ## Show running services
	$(COMPOSE) --env-file $(ENV_FILE) --profile local ps

status: ## Health check all services
	@echo "brain-gateway:"; curl -sf http://localhost:8080/health 2>/dev/null && echo "" || echo "  DOWN"
	@echo "portal:"; curl -sf http://localhost:3000/health 2>/dev/null && echo "" || echo "  DOWN"
	@echo "ollama:"; curl -sf http://localhost:11434/api/tags 2>/dev/null | head -c 120 && echo "" || echo "  DOWN or not running"

logs: ## Tail logs from all services
	$(COMPOSE) --env-file $(ENV_FILE) --profile local logs -f

logs-gateway: ## Tail brain-gateway logs
	$(COMPOSE) --env-file $(ENV_FILE) logs -f brain-gateway

logs-portal: ## Tail portal logs
	$(COMPOSE) --env-file $(ENV_FILE) logs -f portal

logs-observer: ## Tail observer sidecar logs
	$(COMPOSE) --env-file $(ENV_FILE) logs -f observer

logs-init: ## Tail ollama-init model pull logs
	$(COMPOSE) --env-file $(ENV_FILE) --profile local logs -f ollama-init

test: ## Run pytest with coverage
	uv run pytest -q

test-zitadel-flows: ## Run dedicated ZITADEL flow tests
	uv run pytest -q --no-cov tests/test_zitadel_flows.py

test-v: ## Run pytest verbose
	uv run pytest -v

qa: ## Run QA harness against live gateway (all modules × all guardrails)
	uv run python scripts/qa_harness.py

qa-json: ## Run QA harness with JSON output
	uv run python scripts/qa_harness.py --json

smoke-local: ## Smoke test local Docker Compose target
	uv run python scripts/smoke_test.py --target local

smoke-local-llm: ## Smoke test local target including LLM-backed probe
	uv run python scripts/smoke_test.py --target local --require-llm

smoke-k8s: ## Smoke test k8s target (set K8S_HOST=ip if needed)
	uv run python scripts/smoke_test.py --target k8s --k8s-host $${K8S_HOST:-192.168.1.114}

smoke-k8s-llm: ## Smoke test k8s target including LLM-backed probe
	uv run python scripts/smoke_test.py --target k8s --k8s-host $${K8S_HOST:-192.168.1.114} --require-llm

smoke-local-identity: ## Smoke test local target including identity (/config) probe
	uv run python scripts/smoke_test.py --target local --require-identity

smoke-k8s-identity: ## Smoke test k8s target including identity (/config) probe
	uv run python scripts/smoke_test.py --target k8s --k8s-host $${K8S_HOST:-192.168.1.114} --require-identity

smoke-local-identity-llm: ## Smoke local target including identity and LLM probe
	uv run python scripts/smoke_test.py --target local --require-identity --require-llm

smoke-k8s-identity-llm: ## Smoke k8s target including identity and LLM probe
	uv run python scripts/smoke_test.py --target k8s --k8s-host $${K8S_HOST:-192.168.1.114} --require-identity --require-llm

zitadel-bootstrap: ## Bootstrap ZITADEL service user for non-degraded IDP operation
	uv run python scripts/zitadel_bootstrap.py --write-env
	@echo "Restart brain-gateway to apply: make up"

compose-gen: ## Regenerate docker-compose.yml from Helm values
	uv run python deploy/generate-compose.py
	@echo "compose/docker-compose.yml regenerated from deploy/helm/camazotz/values.yaml"

helm-template: ## Render Helm templates to stdout
	helm template camazotz deploy/helm/camazotz --namespace camazotz

helm-deploy: ## Deploy to K8s via Helm (requires cluster access)
	helm upgrade --install camazotz deploy/helm/camazotz --namespace camazotz --create-namespace

helm-deploy-local: ## Deploy with Ollama enabled
	helm upgrade --install camazotz deploy/helm/camazotz --namespace camazotz --create-namespace --set ollama.enabled=true --set config.brainProvider=local
