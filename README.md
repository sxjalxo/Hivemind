# Hivemind

**Evidence-grounded honeypot analysis, and automated evaluation of the honeypot itself.**

Hivemind does two things with one honeypot.

It **analyses attacks**: ingesting live telemetry, reconstructing attacker sessions,
classifying behaviour with a local LLM, mapping commands to MITRE ATT&CK, extracting
indicators of compromise, and producing threat reports.

Then it **turns around and attacks the honeypot itself**: an SSH agent and a set of
static probes exercise the decoy across six characteristics and report how convincing it
would look to an intruder, so a developer learns where the illusion breaks before an
attacker does.

Its defining property is **provenance**: every conclusion the interface shows expands
into the exact log line that produced it, and nothing is presented as fact unless
telemetry supports it.

Based on *"Beekeeper: Accelerating Honeypot Analysis With LLM-Driven Feedback"*
(Ilg, Germek, Duplys & Menth, IEEE Access vol. 13, 2025).

> **New to this project?** Read **[`DEMO.md`](DEMO.md)** instead of this file. It assumes
> no prior knowledge and covers what the project is, how to install every prerequisite,
> how to start the three servers, and a screen-by-screen walkthrough. This README is the
> technical reference for someone already working on the code.

---

## The loop

```
                    ┌──────────────── improve ◀───────────────┐
                    ▼                                         │
   Cowrie honeypot ──► Filebeat ──► Elasticsearch (ECS) ──► analysis
        ▲                                                     │
        │                                       classification · ATT&CK
        │                                       IOCs · reports
        │                                                     │
        └──── realism evaluation ◀──── developer feedback ◀────┘
              (SSH agent · nmap · tcpdump · attack chains)
```

Captured attacks feed analysis; analysis and evaluation share one rulebook and one
evidence model; evaluation feeds honeypot improvement; a more convincing honeypot
captures better attacks.

---

## Requirements

| | |
|---|---|
| Docker Desktop | runs Cowrie, Filebeat, Elasticsearch, Kibana, Postgres |
| Python | 3.12 |
| Node.js | 20+ |
| [Ollama](https://ollama.com) | on the host, for GPU access |
| GPU | 8 GB VRAM is sufficient (see *Model sizing*) |
| `nmap` | optional — the service-scan probe reports `unknown` without it |
| packet capture | runs in the honeypot container's own network namespace, from `nicolaka/netshoot`; `docker pull nicolaka/netshoot` once |

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
cp .env.example .env                                  # optional — every value is a default
.venv/Scripts/python -m alembic upgrade head
.venv/Scripts/python -m uvicorn app.main:app --port 8000
```

On first start the backend installs the Elasticsearch ingest pipeline and index
template, then seeds a deterministic corpus so every screen has data before any attacker
connects.

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

## Running a realism evaluation

Open **Realism Evaluation** in the sidebar, pick a honeypot, and start a run. The run is
dispatched to the background: the API returns a run id immediately and the seven stages
stream over a WebSocket while it works.

An evaluation clears the state a previous run created — and nothing else — then
fingerprints the honeypot, runs its modules, and scores six characteristics:

| Characteristic | What it asks |
|---|---|
| `basic_commands` | do ordinary shell commands behave like a real host? |
| `file_system` | does the filesystem hold up under inspection? |
| `services` | do the advertised network services exist? |
| `attack_possibilities` | can a known attack chain actually be carried out? |
| `sanity` | do the honeypot's own answers contradict each other? |
| `context` | is there evidence of a plausible, lived-in system? |

Two **separate** numbers come back per characteristic, and they are never combined:

- **Deterministic assessment** — did the honeypot do the checkable things? Computed from
  facts only, with `unknown` excluded from both sides of the fraction, so a probe that
  failed on our side is never counted against the honeypot.
- **Evaluator assessment** — would an attacker believe it? Produced by a cloud model, and
  reported as *unavailable* rather than guessed when no key is configured.

There is deliberately **no overall score**. A null means "not established" and never
renders as `0`.

### Comparing two runs

Every run stores two fingerprints: one for the honeypot under test, one for the
evaluation configuration. The comparison view uses them asymmetrically, because they mean
opposite things:

- a changed **honeypot** fingerprint is the *point* of the comparison — that change is the
  improvement being measured;
- a changed **evaluation configuration** fingerprint is what breaks attribution, because
  our own probes, chains, rulebook or budget moved underneath the result.

The comparison is never refused; it says plainly whether a delta is attributable.

### The cloud evaluator (optional)

```bash
# backend/.env
BYOK_PROVIDER=anthropic        # or: openai
BYOK_API_KEY=...
BYOK_MODEL=claude-sonnet-4-5
```

Without a key, evaluation runs to completion and reports `evaluator_status: unavailable`.
It **never falls back to the local model** — the source paper measured sub-70b models as
returning only superficial critique in this role, and a shallow-but-plausible realism
verdict is the exact failure this system exists to prevent.

---

## Tests

```bash
cd backend && .venv/Scripts/python -m pytest
```

484 tests. They run against the live Docker stack and the real local model, so bring the
infrastructure up first. **A clean run is `483 passed, 1 skipped` or `484 passed`** — there
are no expected failures.

The skip is the one end-to-end test that depends on whether `llama3.1:8b` infers a
technique on that pass, and on whether its citation survives the evidence barrier. Neither
is a defect in the code, so it skips with a reason rather than failing. The boundary it
protects — an LLM-sourced mapping is never marked `observed` — is pinned separately by a
deterministic test that needs no model at all.

```bash
cd frontend && npx tsc --noEmit && npm run lint && npm run build
```

---

## Layout

```
backend/     FastAPI service — ingest, analysis pipeline, evaluation subsystem
             19 HTTP endpoints + 2 WebSocket progress channels
frontend/    React + TanStack Router dashboard
infra/       Elasticsearch index template and ingest pipeline, Filebeat, Cowrie config
```

Design specs, implementation plans and per-task engineering reports live in `docs/` and
`.superpowers/`, which are deliberately untracked — they are working documents for
whoever is building the system. This file and [`OVERVIEW.md`](OVERVIEW.md) are the
tracked documentation.

---

## How provenance works

Everything on screen is tagged with where it came from:

| Badge | Meaning |
|---|---|
| `OBSERVED` | recorded directly in honeypot telemetry |
| `AI INFERENCE` | proposed by the LLM, shown with confidence and evidence |
| `CORRELATED` | derived by correlating across more than one session |

An ATT&CK technique is marked **observed** only when a deterministic regex rule matched
the command — never because a model suggested it. The LLM fills gaps the 13-rule
rulebook cannot explain, and those mappings are labelled inference.

Four gates enforce this:

- **Schema validation** — a model response naming a technique outside the pinned ATT&CK
  catalog, or citing an event that was never shown to it, is rejected.
- **The evidence write barrier** — no derived claim is stored without at least one
  resolvable pointer to a real Elasticsearch document. Rejections are counted, not
  silently dropped.
- **A database constraint, not just application code** — in the evaluation schema a
  deferred constraint trigger rejects, at commit time, any finding that reaches the
  database without evidence. A finding and its evidence must be written in one
  transaction; ungrounded findings are unrepresentable rather than merely discouraged.
- **Enrichment scoping** — ATT&CK identifiers are written back to Elasticsearch only for
  rule-backed mappings, so an inference never becomes indistinguishable from observed
  telemetry in downstream queries.

The same discipline governs the evaluator: it is handed an evidence package and must cite
from it. A verdict citing evidence it was never given is rejected outright, and a rating
whose citations resolve to nothing is discarded rather than stored ungrounded.

---

## Model sizing

Two model roles, following the source paper's split:

| Role | Model | Notes |
|---|---|---|
| Analysis | `llama3.1:8b` locally via Ollama | temperature 0.3, `num_ctx` 8192 |
| Realism evaluator (optional) | BYOK cloud model | one context per characteristic |

`num_ctx` is 8192 rather than the paper's 32768 because that was measured on an 8 GB
card: at 32768 the model spills to a 34%/66% CPU/GPU split and runs several times slower,
silently. Long sessions are chunked and merged instead of being truncated.

Each pipeline stage gets its own isolated context — seven for analysis, one per
characteristic for evaluation — because merging them into a single prompt was measured to
produce markedly shallower output.

The probe agent uses **no model at all**. It is Paramiko plus a fixed probe list, which is
why a run records `agent_model` as `deterministic-probes@<version>` rather than a model
name: naming one would invite a reader to attribute a run-to-run difference to a model
change that never happened.

---

## Security

Cowrie is deliberately attackable software. Its ports bind to `127.0.0.1` only and it
must not be exposed to the internet in this configuration.

Attacker-controlled text is treated as untrusted throughout: it is never interpolated into
a shell, and inside LLM prompts it is fenced and labelled as data, with line breaks and
delimiter runs neutralised so captured output cannot close the fence and address the model
directly. Captured malware is referenced by hash only and never executed. Elasticsearch,
Postgres and model credentials stay server-side — the browser knows one API base URL.

The evaluation API is **containment-bounded by construction**: `POST /api/evaluations`
accepts a honeypot id from the registry and nothing else. There is no host, port or
command field, and an unexpected field is rejected rather than ignored, so there is no
path from an HTTP request to an arbitrary target. The reset boundary is enforced in code
— a guard rejects any path that reaches the honeypot's identity keys or its logs, and
rejects path traversal outright — rather than documented in a comment.

---

## Current limitations

- **`evaluation_target_host` defaults to the compose service name** `cowrie`, which does
  not resolve from a backend running on the host. Set `EVALUATION_TARGET_HOST=127.0.0.1`
  for a host-run backend.
- **The packet capture needs Docker**, because it runs inside the honeypot container's
  network namespace. Clearing `EVALUATION_CAPTURE_IMAGE` falls back to a host `tcpdump`,
  which is only correct where the host shares the honeypot's network — not when the
  honeypot is a container reached through a published port.
- **Single-worker deployment.** The job queue and WebSocket fan-out are in-process;
  multiple uvicorn workers would need Redis pub/sub.
- **The deterministic scoring code is not fingerprinted** — only its data files are. Two
  runs spanning a change to the rule engine or the probe timeout fingerprint identically,
  so git revision is the extra key when reading a trend.

See [`OVERVIEW.md`](OVERVIEW.md) for the design rationale and the full limitation list,
and [`DEMO.md`](DEMO.md) for the setup guide and a screen-by-screen walkthrough written
for someone seeing the project for the first time — including a troubleshooting section
for everything that commonly goes wrong.
