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
telemetry supports it. An ATT&CK technique is marked *observed* only when a deterministic
rule matched the command — never because a model suggested it — and a fact nobody could
establish is reported as unknown rather than as a zero.

Based on *"Beekeeper: Accelerating Honeypot Analysis With LLM-Driven Feedback"*
(Ilg, Germek, Duplys & Menth, IEEE Access vol. 13, 2025).

> **Why is it built this way?** [`OVERVIEW.md`](OVERVIEW.md) covers the design rationale,
> the full feature list and the technical reference — every operational detail that used
> to live in this file.

---

## Screenshots

**Dashboard** — fleet-wide attacker activity over a selected window.

![Dashboard](assets/screenshots/dashboard.png)

**Attack sessions** — every captured session ranked for triage, with its risk score and
the ATT&CK tactic chain it exercised.

![Attack sessions](assets/screenshots/sessions.png)

**Threat intelligence** — extracted indicators, each carrying its own provenance tier.
`OBSERVED` came straight from telemetry; `CORRELATED` was derived across more than one
session.

![Threat intelligence](assets/screenshots/threat-intel.png)

**MITRE ATT&CK mapping** — techniques positioned on the Enterprise matrix, with the count
of evidence behind each one.

![MITRE ATT&CK mapping](assets/screenshots/mitre.png)

**Realism evaluation** — run history for the half that attacks the honeypot, with both
fingerprints, the evaluator's status and who started each run. The honeypot column shows
the degradation matrix: four arms of one image, each differing in a single declared
respect, carrying four different honeypot fingerprints under one shared configuration
fingerprint.

![Realism evaluation](assets/screenshots/evaluation.png)

**Remediation** — each finding carries the fix for it, beneath the defect it repairs.
`DERIVED` marks a value read from the honeypot's own evidence — here the hostname its
`hostname` command actually returned; `TEMPLATE` marks a starting point to review before
applying. The os-release fix writes `usr/lib/os-release`, the symlink target, because a
patch to the link applies cleanly and does nothing.

![Remediation](assets/screenshots/remediation.png)

**And where there is no fix, it says so.** Cowrie has no HTTP listener to enable, so
nothing in its configuration can satisfy this finding. A refusal is shown with the same
weight as a patch, because a reader who applied everything on screen must not be able to
believe they had addressed the whole run.

![No automated fix](assets/screenshots/remediation-refusal.png)

---

## Installation

Two ways in. **Run it** — everything in containers, one command. **Develop on it** — the
infrastructure in containers and the backend and frontend on the host, with reload.

### Requirements

| | |
|---|---|
| Docker Desktop | runs Cowrie, Filebeat, Elasticsearch, Kibana, Postgres |
| [Ollama](https://ollama.com) | on the host, for GPU access |
| GPU | 8 GB VRAM is sufficient |
| Python | 3.12 — only to develop on it; the container carries its own |
| Node.js | 22.13+ or 24+ — same |
| `nmap` | bundled in the backend image; install it on the host only for a host-run backend |

The packet-capture sidecar (`nicolaka/netshoot`, pinned by digest) is declared in
`docker-compose.yml` and pulled with everything else.

Hivemind runs **next to the honeypot it evaluates, never above it**. The evaluation half
`docker exec`s into the decoy's container, the capture sidecar shares its network
namespace, and the target is resolved from server-side settings so that no request can
ever name an address. That is why there is no hosted backend to point this at: one
install per honeypot host is the design, not a limitation of the packaging.

---

## Run it

```bash
ollama pull llama3.1:8b        # once; confirm `ollama ps` reports 100% GPU
docker compose --profile app up -d
```

Open <http://localhost:8080>. That brings up the infrastructure *plus* the backend
(`:8000`) and the dashboard (`:8080`), applies the database migrations, installs the
Elasticsearch pipeline and template, and seeds the demo corpus. Every port binds to
`127.0.0.1` only.

Ollama stays on the host deliberately — a container would not reach the GPU on Windows,
and the model only fits on an 8 GB card at `num_ctx` 8192. The backend reaches it through
`host.docker.internal`.

Two things worth knowing before you use it in anger:

- **The containerised backend cannot run evaluations, deliberately.** Driving the
  honeypot's container from inside a container would mean sharing the Docker socket, and
  anything that reaches that socket can take the host — so it is not mounted. Analysis is
  completely unaffected: ingest, sessions, the seven-stage pipeline, ATT&CK mapping,
  indicators and reports all work. An evaluation started this way fails at its first
  precondition with a `ResetError` and leaves no record, rather than producing a run whose
  facts are all `unknown`. The status dashboard says so up front — *"no Docker access —
  evaluation runs cannot start; analysis is unaffected"* — so you are not left to discover
  it by starting one. To run evaluations, use the host install below: it calls Docker as
  your own user and shares nothing. `docker-compose.yml` documents the one-line change if
  you would rather accept the trade.
- **Without Clerk configured the API answers every caller**, which it says on startup and
  on the status dashboard. That is defensible bound to `127.0.0.1` and nowhere else. See
  [`OVERVIEW.md`](OVERVIEW.md) for how to turn it on.

---

## Develop on it

### 1. Infrastructure

```bash
docker compose up -d
```

Brings up Elasticsearch (`:9200`), Kibana (`:5601`), Postgres (`:5432`), Cowrie
(`:2222` SSH, `:2223` Telnet) and Filebeat. Every port binds to `127.0.0.1` only.

### 2. Local model

```bash
ollama pull llama3.1:8b
```

Confirm it runs on the GPU — `ollama ps` must report `100% GPU`. A silent fall back to
CPU makes every analysis several times slower with no error.

### 3. Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"       # Linux/macOS: .venv/bin/python
cp .env.example .env                                  # optional — every value is a default
.venv/Scripts/python -m alembic upgrade head
EVALUATION_TARGET_HOST=127.0.0.1 .venv/Scripts/python -m uvicorn app.main:app --port 8000
```

On first start the backend installs the Elasticsearch ingest pipeline and index
template, then seeds a deterministic corpus so every screen has data before any attacker
connects.

`EVALUATION_TARGET_HOST` matters only for the realism evaluation: it defaults to the
compose service name `cowrie`, which does not resolve from a backend running on the host.

### 4. Frontend

```bash
cd frontend
npm install
echo "VITE_API_BASE_URL=http://localhost:8000" > .env
npm run dev
```

Open <http://localhost:8080>. Without `VITE_API_BASE_URL` the app runs on built-in demo
data instead — useful for a UI-only look, and every surface that renders it is badged.

### 5. Generate traffic (optional)

```bash
ssh -p 2222 root@127.0.0.1     # any password is accepted
```

Type a few commands, then `exit`. They appear in the Log Explorer within seconds.
A scripted generator is also available:

```bash
cd backend && .venv/Scripts/python scripts/generate_traffic.py
```

---

## License

Licensed under the [Apache License 2.0](LICENSE).

Cowrie is deliberately attackable software. Its ports bind to `127.0.0.1` only and it
must not be exposed to the internet in this configuration.
