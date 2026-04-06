# VeilSec — Security Scanner for Vibe Coders

POC de segurança cibernética e compliance LGPD para aplicações desenvolvidas com IA.

## Visão Geral

VeilSec é um scanner de segurança self-service com duas frentes:

- **SAST** — Analisa código fonte em busca de falhas de segurança e violações da LGPD
- **DAST** — Testa aplicações em produção com payloads controlados, incluindo Prompt Injection para APIs com LLM

## Início Rápido

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/veilsec.git
cd veilsec

# 2. Configure o ambiente
cp .env.example .env
# Edite .env com suas chaves (ANTHROPIC_API_KEY, OWNERSHIP_HMAC_SECRET)

# 3. Suba a stack completa
make up

# 4. Aplique as migrations
make migrate

# 5. Rode os testes
make test

# 6. Acesse
open http://localhost:8000/docs
```

## Stack

| Componente | Tecnologia |
|---|---|
| API | FastAPI + Uvicorn |
| Workers | Celery + Redis |
| AST Parser | tree-sitter |
| LLM | Claude claude-sonnet-4-5 (Anthropic) |
| Banco | PostgreSQL |
| Storage | S3 / MinIO (dev) |
| Containers | Docker + Docker Compose |

## Serviços Locais

| Serviço | URL |
|---|---|
| API + Swagger | http://localhost:8000/docs |
| Flower (Celery monitor) | http://localhost:5555 |
| MinIO Console | http://localhost:9001 |

## Comandos

```bash
make up           # Sobe toda a stack
make down         # Derruba a stack
make test         # Roda todos os testes
make test-unit    # Apenas testes unitários
make test-security # Apenas testes de segurança
make migrate      # Aplica migrations
make logs         # Logs em tempo real
make lint         # Formatação e linting
make clean        # Remove tudo incluindo volumes
```

## Arquitetura de Segurança

### Pipeline de IA — 4 Camadas

```
Input do usuário
    → Camada 1: Extração AST (tree-sitter) — sem LLM
    → Camada 2: Classificador local de Prompt Injection
    → Camada 3: LLM principal com prompt blindado
    → Camada 4: Validação de schema (Pydantic v2)
```

### Invariantes de Segurança

1. Zero DAST sem verificação de ownership (2 de 3 métodos)
2. Isolamento de PII entre tenants (IDOR protection em todas queries)
3. Input nunca chega ao LLM como texto livre
4. Código deletado imediatamente após análise (retenção máx. 24h)
8. Isolamento de redes: DAST executado em VPCs isoladas e efêmeras
5. Consentimento LGPD obrigatório (Art. 7º)
6. Secrets apenas como hash — nunca texto claro
7. Audit log imutável via trigger no PostgreSQL

## Estrutura

```
veilsec/
├── apps/
│   ├── api/              # FastAPI
│   ├── worker_sast/      # Celery SAST
│   └── worker_dast/      # Celery DAST
├── packages/
│   ├── domain/           # Regras de negócio
│   ├── infra/            # Adaptadores externos
│   └── shared/           # DTOs, settings, audit
├── infrastructure/
│   ├── alembic/          # Migrations
│   └── docker/           # Dockerfiles
└── tests/
    ├── unit/
    ├── integration/
    └── security/
```

## LGPD

| Artigo | Implementação |
|---|---|
| Art. 7º | Consentimento verificado em todo scan |
| Art. 15 | Retenção: deletado após análise (máx. 24h) |
| Art. 18, IV | `GET /me/data` — portabilidade |
| Art. 18, VI | `DELETE /me` — exclusão completa |
| Art. 46 | Pipeline 4 camadas + DAST Isolado + audit |

## Licença

MIT
