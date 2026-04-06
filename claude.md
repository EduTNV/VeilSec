# Contexto do Projeto: VeilSec

## Visão Geral
VeilSec é um sistema de segurança ofensiva e defensiva (SAST/DAST) focado em detecção de vulnerabilidades e compliance com a LGPD. O sistema utiliza uma arquitetura de pipeline de IA em 4 camadas para isolar dados sensíveis (PII) e mitigar riscos de prompt injection.

A arquitetura segue os princípios de Domain-Driven Design (DDD) estruturada em um Monorepo.

O público-alvo são "vibe coders" — pessoas que utilizam IA para gerar e lançar sistemas em produção sem background técnico em segurança. O VeilSec oferece três portas de entrada para análise:
- **Porta 1 (SAST Manual):** Usuário cola o código diretamente (ex: código gerado pelo ChatGPT)
- **Porta 2 (SAST via GitHub App):** Integração futura — fora do escopo da POC
- **Porta 3 (DAST via URL):** Usuário informa a URL da aplicação em produção

---

## Comandos Principais

- **Rodar a API (FastAPI):** `uvicorn apps.api.main:app --reload --port 8000`
- **Rodar Worker SAST (Celery):** `celery -A apps.worker_sast.worker worker --loglevel=info`
- **Rodar Worker DAST (Celery):** `celery -A apps.worker_dast.worker worker --loglevel=info`
- **Rodar Classificador IA (Camada 2):**
  - Dev: `AI_CLASSIFIER_MODE=mock python -m apps.ai_classifier.service`
  - Prod: `python -m apps.ai_classifier.service` (requer modelo baixado em `/models`)
- **Testes Unitários e Integração:** `pytest tests/unit tests/integration -v`
- **Testes de Segurança (E2E):** `pytest tests/security -v`
- **Formatação e Linting:** `black . && ruff check .`

---

## Configuração Local (Desenvolvimento)

Copie `.env.example` para `.env` antes de rodar qualquer serviço:

```env
ENVIRONMENT=development
DATABASE_URL=postgresql+asyncpg://veilsec:veilsec@localhost:5432/veilsec
REDIS_URL=redis://localhost:6379/0
ANTHROPIC_API_KEY=sk-...
ANTHROPIC_MODEL=claude-sonnet-4-5
OPENAI_API_KEY=sk-...
OWNERSHIP_HMAC_SECRET=qualquer-string-longa-para-dev-min-32-chars
AWS_S3_BUCKET=veilsec-local
AWS_ENDPOINT_URL=http://localhost:9000
AI_CLASSIFIER_MODE=mock
AI_CLASSIFIER_MODEL_PATH=./models/deberta-injection-detector
```

> ⚠️ Em produção, NENHUM segredo vem de variável de ambiente.
> Todos os valores sensíveis são lidos do **AWS Secrets Manager**.

---

## Estrutura do Monorepo

```
veilsec/
├── apps/
│   ├── api/                    # FastAPI — API principal
│   ├── worker_sast/            # Celery worker SAST
│   ├── worker_dast/            # Celery worker DAST
│   └── ai_classifier/          # Serviço isolado Camada 2
├── packages/
│   ├── domain/                 # Regras de negócio puras, sem I/O externo
│   ├── infra/                  # Adaptadores: PostgreSQL, Redis, S3, Anthropic
│   └── shared/                 # DTOs Pydantic, enums, exceções, structlog
├── infrastructure/
│   ├── terraform/              # IaC AWS
│   ├── docker/                 # Dockerfiles por serviço
│   └── alembic/                # Migrations do banco
├── tests/
│   ├── unit/
│   ├── integration/
│   └── security/
├── models/                     # Modelos locais de IA — não versionar
├── .env.example
└── claude.md
```

---

## Escopo da POC vs V1

### ✅ IN SCOPE — POC
- SAST via cola de código manual
- DAST via URL com verificação de propriedade Zero Trust
- Pipeline de IA completa nas 4 camadas
- Autenticação via API Key
- Relatório com findings + artigos LGPD
- Audit log imutável
- Compliance LGPD (Art. 7º, 15, 18, 46)
- Testes unitários, integração e segurança

### ❌ OUT OF SCOPE — V1
- GitHub App integration
- Frontend completo
- Export PDF
- Notificações
- Billing e planos

---

## Decisões Arquiteturais

| Componente | Decisão |
|---|---|
| Backend | FastAPI + Uvicorn |
| Workers | Celery + Redis Streams |
| AST Parser | tree-sitter |
| Classificador (Camada 2) | DeBERTa-v3-small local ou Llama Guard 3 |
| LLM Principal (Camada 3) | Claude claude-sonnet-4-5 + fallback GPT-4o-mini |
| Banco | PostgreSQL + JSONB |
| Cache | Redis |
| Storage | S3 (MinIO em dev) |
| DAST Runners | EC2 Spot em VPC isolada |
| Comunicação VPCs | SQS exclusivamente |

---

## 🛑 INVARIANTES DE NEGÓCIO E SEGURANÇA

**NUNCA ESCREVA CÓDIGO QUE VIOLE ESTAS REGRAS:**

1. **Zero DAST sem Ownership:** Nenhum scan DAST sem `OwnershipProof` válido com 2 de 3 métodos verificados.
2. **Isolamento de PII:** Nenhum dado de cliente A acessível por cliente B. Audit log imutável.
3. **Pipeline de IA rigorosa:** NENHUM input cru chega ao LLM. Fluxo: Input → Camada 1 → Camada 2 → Camada 3 → Camada 4.
4. **Retenção:** Código submetido deletado em 24h máximo.
5. **Consentimento LGPD:** Nenhum scan sem `lgpd_consent_at` válido (Art. 7º).
6. **Segredos:** Apenas hashes armazenados. Nunca texto claro, nunca env vars em produção.
7. **Audit log:** Append-only. Sem UPDATE ou DELETE. Enforced no banco via trigger.
8. **Input nunca executa:** Código do usuário é dado, nunca executável.

---

## Padrões de Código

- Python 3.11+, tipagem estrita em todas as assinaturas
- `async/await` para todo I/O
- `Depends` do FastAPI para injeção de dependências
- Nunca retornar stack traces ao cliente
- Logging via `structlog` — nunca logar PII, tokens ou código fonte

```python
# ✅ CORRETO
log.info("scan.started", scan_id=str(scan.id), scan_type=scan.type)

# ❌ ERRADO
log.info("scan.started", code=user_code, email=client.email)
```

---

## STRIDE — Threat Model

| Ameaça | Controle |
|---|---|
| Spoofing | API Key via hash em todos endpoints privados |
| Tampering | Ownership tokens assinados com HMAC-SHA256 + TTL |
| Repudiation | ImmutableAuditLog em toda mutação |
| Information Disclosure | client_id validado em todas as queries |
| DoS | Token Bucket adaptativo + limite 500KB no AST |
| Elevation of Privilege | Workers privilégios mínimos. DAST em VPC isolada |

---

## Direitos LGPD Implementados

| Artigo | Direito | Endpoint |
|---|---|---|
| Art. 7º | Consentimento | Verificado em todo scan |
| Art. 15 | Retenção | Cron job diário |
| Art. 18, IV | Portabilidade | `GET /me/data` |
| Art. 18, VI | Exclusão | `DELETE /me` |
| Art. 46 | Segurança adequada | Pipeline 4 camadas + audit |
