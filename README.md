# VeilSec

**Scanner de segurança e compliance LGPD para aplicações desenvolvidas com IA.**

As ferramentas de IA facilitaram muito a criação de aplicações e sites. Junto com essa facilidade, surgiram sistemas em produção construídos no modo *vibe coding*: sem análise, sem entendimento do código gerado, sem testes. Esses sistemas coletam dados reais de usuários reais e, na maioria dos casos, não passaram por nenhuma revisão de segurança.

O VeilSec foi criado para fechar essa lacuna. Você não precisa entender de segurança para descobrir se o seu sistema tem problemas graves. O VeilSec faz isso por você.

---

## O que o VeilSec faz

O sistema oferece duas formas de análise:

**SAST — Análise de código**
Você cola o código que a IA gerou. O VeilSec lê esse código, rastreia onde os dados pessoais dos seus usuários vão parar e te diz exatamente o que está errado, o nível de gravidade de cada problema e como corrigir. Cada falha encontrada é conectada ao artigo específico da LGPD que está sendo violado.

**DAST — Teste da aplicação em produção**
Você informa a URL do seu sistema que já está no ar. O VeilSec simula ataques reais contra a sua aplicação, os mesmos que um invasor usaria, incluindo vetores específicos para sistemas construídos com IA, como Prompt Injection. Você descobre o que está vulnerável antes que alguém mal-intencionado descubra.

---

## Como o SAST funciona

Antes de qualquer análise por IA, o código submetido passa por uma pipeline de 4 camadas de verificação. Isso garante que o sistema seja seguro e que o código do usuário seja tratado com responsabilidade.

```
Código do usuário
    │
    ▼
Camada 1 — AST Parser (tree-sitter)
    Extrai a estrutura do código sem executá-lo.
    Identifica de onde vêm os dados pessoais (PII)
    e para onde eles vão, sem ler strings ou comentários.
    │
    ▼
Camada 2 — Classificador local de Prompt Injection
    Modelo offline que analisa se o código contém
    tentativas de manipular o sistema de IA.
    Score alto = scan bloqueado antes de chegar ao LLM.
    │
    ▼
Camada 3 — LLM principal (Claude + fallback GPT-4o-mini)
    Recebe apenas o subgrafo estruturado, nunca o código bruto.
    Classifica as violações LGPD com contexto semântico.
    │
    ▼
Camada 4 — Validação de schema (Pydantic v2)
    O output do LLM é validado contra um schema estrito.
    Qualquer resposta fora do formato esperado é descartada.
```

O código submetido nunca chega ao LLM como texto livre. Strings, comentários e conteúdo literal são descartados ainda na Camada 1. Apenas a estrutura do código avança para as etapas seguintes.

---

## Como o DAST funciona

Antes de qualquer ataque, o VeilSec exige que você prove que o domínio é seu. Isso impede que a ferramenta seja usada contra sistemas de terceiros.

**Verificação de propriedade do domínio (2 de 3 métodos obrigatórios):**

```
O VeilSec gera um token único para o seu domínio.
Você prova que é o dono usando pelo menos 2 das 3 opções:

  [1] DNS TXT   →  _aegis-verify.seudominio.com = "aegis-ownership=<token>"
  [2] Arquivo   →  seudominio.com/.well-known/aegis-security.txt
  [3] Header    →  X-Aegis-Ownership: <token> em qualquer resposta HTTP
```

Após a verificação, o scanner mede o tempo de resposta normal da sua aplicação (baseline) e só então começa a disparar os payloads. Ele para automaticamente se detectar que está causando lentidão no sistema.

**Categorias de ataques simulados:**

| Categoria | Exemplo | Severidade |
|---|---|---|
| SQL Injection | `' OR '1'='1` | Critical |
| Path Traversal | `../../../etc/passwd` | Critical |
| SSRF | `http://169.254.169.254/latest/meta-data/` | Critical |
| XSS | `<script>alert('test')</script>` | High |
| Prompt Injection | `Ignore all previous instructions...` | Critical |
| Header Injection | CRLF via headers HTTP | High |
| Open Redirect | Redirecionamento para domínio externo | Medium |

---

## Mapeamento LGPD

Todo problema encontrado é conectado ao artigo da lei correspondente:

| Padrão detectado | Artigo LGPD | Severidade |
|---|---|---|
| PII gravada em log sem mascaramento | Art. 46 | Critical |
| PII enviada para API externa sem consentimento | Art. 7º | Critical |
| PII exposta em response da API | Art. 6º | Medium |
| Sistema sem mecanismo de exclusão de dados | Art. 18 | High |

---

## Stack

| Componente | Tecnologia |
|---|---|
| API | FastAPI + Uvicorn |
| Workers assíncronos | Celery + Redis |
| Parser de código | tree-sitter (Python e JavaScript) |
| LLM principal | Claude claude-sonnet-4-5 (Anthropic) |
| LLM fallback | GPT-4o-mini (OpenAI) |
| Banco de dados | PostgreSQL |
| Storage | AWS S3 (MinIO em desenvolvimento) |
| Containers | Docker + Docker Compose |

---

## Início rápido

```bash
# 1. Clone o repositório
git clone https://github.com/seu-usuario/veilsec.git
cd veilsec

# 2. Configure o ambiente
cp .env.example .env
# Edite .env com suas chaves: ANTHROPIC_API_KEY e OWNERSHIP_HMAC_SECRET

# 3. Suba a stack completa
make up

# 4. Aplique as migrations do banco
make migrate

# 5. Acesse a documentação
open http://localhost:8000/docs
```

**Serviços disponíveis após `make up`:**

| Serviço | URL |
|---|---|
| API + Swagger | http://localhost:8000/docs |
| Flower (monitor de tasks) | http://localhost:5555 |
| MinIO (storage local) | http://localhost:9001 |

---

## Comandos

```bash
make up            # Sobe toda a stack
make down          # Derruba a stack
make test          # Roda todos os testes
make test-unit     # Apenas testes unitários
make test-security # Apenas testes de segurança
make migrate       # Aplica migrations
make logs          # Logs em tempo real
make lint          # Formatação e linting
make clean         # Remove tudo incluindo volumes
```

---

## Estrutura do projeto

```
veilsec/
├── apps/
│   ├── api/              # FastAPI: rotas, middlewares, autenticação
│   ├── worker_sast/      # Pipeline SAST (4 camadas)
│   └── worker_dast/      # Pipeline DAST, payloads e rate limiting
├── packages/
│   ├── domain/           # Regras de negócio, entidades, invariantes
│   ├── infra/            # PostgreSQL, Redis, S3, LLM, classificador
│   └── shared/           # DTOs, settings, audit log
├── infrastructure/
│   ├── alembic/          # Migrations do banco
│   └── docker/           # Dockerfiles por serviço
└── tests/
    ├── unit/             # Lógica de domínio
    ├── integration/      # API com banco real
    └── security/         # Prompt injection, IDOR, bypass de ownership
```

---

## Compliance LGPD

| Artigo | Implementação |
|---|---|
| Art. 7º | Consentimento verificado antes de qualquer scan |
| Art. 15 | Código submetido deletado após análise (máx. 24h) |
| Art. 18, IV | `GET /me/data` para portabilidade dos dados |
| Art. 18, VI | `DELETE /me` para exclusão completa da conta |
| Art. 46 | Pipeline 4 camadas com audit log imutável |

---

## Invariantes de segurança

Essas são regras que o sistema nunca viola, independente do contexto. Pense nelas como os pilares que garantem que o VeilSec seja confiável e não seja usado de forma indevida:

1. Nenhum scan DAST inicia sem que o ownership do domínio seja verificado com 2 de 3 métodos
2. Dados de um cliente nunca são acessíveis por outro (proteção contra IDOR)
3. Nenhum input chega ao LLM sem passar pelas Camadas 1 e 2
4. Código submetido é deletado em no máximo 24 horas
5. Nenhum scan ocorre sem consentimento LGPD registrado
6. Senhas e API keys são armazenadas apenas como hash, nunca em texto claro
7. O audit log é append-only, garantido por trigger no PostgreSQL
8. Código submetido é tratado como dado, nunca como executável

---

## Status

Este projeto é uma **POC (Proof of Concept)**. O código pode ter bugs, as análises podem errar e muita coisa ainda precisa ser construída. A ideia é crescer em público.

**O que está fora do escopo desta versão (planejado para V1):**
- Interface web / dashboard visual
- Integração com GitHub via App
- Export de relatório em PDF
- Sistema de notificações
- Planos e billing

---

## Licença

MIT
