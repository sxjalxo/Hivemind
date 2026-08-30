# Hivemind

**AI-assisted honeypot log analysis and threat intelligence.**

Hivemind ingests live honeypot telemetry, reconstructs attacker sessions, classifies
attacker behaviour with a local LLM, maps observed commands to MITRE ATT&CK, extracts
indicators of compromise, and produces evidence-grounded threat reports.

Its defining property is **provenance**: every conclusion the interface shows can be
expanded into the exact log line that produced it, and nothing is presented as fact
unless telemetry supports it.

Based on *"Beekeeper: Accelerating Honeypot Analysis With LLM-Driven Feedback"*
(Ilg, Germek, Duplys & Menth, IEEE Access vol. 13, 2025).

---

## The pipeline

```
Cowrie honeypot → Filebeat → Elasticsearch (ECS) → analysis pipeline
                                                        ↓
        attacker classification · ATT&CK mapping · IOC extraction · reports
                                                        ↓
                                    React dashboard (provenance-tagged)
```

---

## Requirements

| | |
|---|---|
| Docker Desktop | runs Cowrie, Filebeat, Elasticsearch, Kibana, Postgres |
| Python | 3.12 |
| Node.js | 20+ |
| [Ollama](https://ollama.com) | on the host, for GPU access |
| GPU | 8 GB VRAM is sufficient (see *Model sizing*) |

---

## Setup

**1. Infrastructure**

```bash
docker compose up -d
```

Brings up Elasticsearch (`:9200`), Kibana (`:5601`), Postgres (`:5432`), Cowrie
(`:2222` SSH, `:2223` Telnet) and Filebeat. Every port binds to `127.0.0.1` only.

**2. Local model**

```bash
ollama pull llama3.1:8b
```

Confirm it runs on the GPU — `ollama ps` must report `100% GPU`. A silent fall back to
CPU makes every analysis several times slower with no error.

**3. Backend**

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"       # Linux/macOS: .venv/bin/python
.venv/Scripts/python -m alembic upgrade head
.venv/Scripts/python -m uvicorn app.main:app --port 8000
```

On first start the backend installs the Elasticsearch ingest pipeline and index
template, then seeds a deterministic corpus so every screen has data before any
attacker connects.

**4. Frontend**

```bash
cd frontend
npm install
echo "VITE_API_BASE_URL=http://localhost:8000" > .env
npm run dev
```

Open <http://localhost:8080>. Without `VITE_API_BASE_URL` the app runs on built-in demo
data instead — useful for a UI-only look, and every surface that renders it is badged.

**5. Generate traffic (optional)**

```bash
ssh -p 2222 root@127.0.0.1     # any password is accepted
```

Type a few commands, then `exit`. They appear in the Log Explorer within seconds.
A scripted generator is also available:

```bash
cd backend && .venv/Scripts/python scripts/generate_traffic.py
```

---

## Tests

```bash
cd backend && .venv/Scripts/python -m pytest
```

217 tests. They run against the live Docker stack and the real local model, so bring
the infrastructure up first.

---

## Layout

```
backend/     FastAPI service — ingest queries, analysis pipeline, 16 endpoints
frontend/    React + TanStack Router dashboard
infra/       Elasticsearch index template and ingest pipeline, Filebeat, Cowrie config
docs/        design spec, implementation plan, per-task engineering reports
```

---

## How provenance works

Everything on screen is tagged with where it came from:

| Badge | Meaning |
|---|---|
| `OBSERVED` | recorded directly in honeypot telemetry |
| `AI INFERENCE` | proposed by the LLM, shown with confidence and evidence |
| `CORRELATED` | derived by correlating across more than one session |

An ATT&CK technique is marked **observed** only when a deterministic regex rule matched
the command — never because a model suggested it. The LLM fills gaps the rulebook
cannot explain, and those mappings are labelled inference.

Three gates enforce this:

- **Schema validation** — a model response naming a technique outside the pinned
  ATT&CK catalog, or citing an event that was never shown to it, is rejected.
- **The evidence write barrier** — no derived claim is stored without at least one
  resolvable pointer to a real Elasticsearch document. Rejections are counted, not
  silently dropped.
- **Enrichment scoping** — ATT&CK identifiers are written back to Elasticsearch only
  for rule-backed mappings, so an inference never becomes indistinguishable from
  observed telemetry in downstream queries.

---

## Model sizing

Two model roles, following the source paper's split:

| Role | Model | Notes |
|---|---|---|
| Analysis | `llama3.1:8b` locally via Ollama | temperature 0.3, `num_ctx` 8192 |
| Evaluator (optional) | BYOK cloud model | narrative and recommendations |

`num_ctx` is 8192 rather than the paper's 32768 because that was measured on an 8 GB
card: at 32768 the model spills to a 34%/66% CPU/GPU split and runs several times
slower, silently. Long sessions are chunked and merged instead of being truncated.

Without a BYOK key the pipeline completes entirely on the local model, and the
resulting analysis is labelled as the lower-confidence tier rather than presented as
equivalent.

---

## Security

Cowrie is deliberately attackable software. Its ports bind to `127.0.0.1` only and it
must not be exposed to the internet in this configuration.

Attacker-controlled text is treated as untrusted throughout: it is never interpolated
into a shell, and inside LLM prompts it is fenced and labelled as data. Captured
malware is referenced by hash only and never executed. Elasticsearch, Postgres and
model credentials stay server-side — the browser knows one API base URL.
