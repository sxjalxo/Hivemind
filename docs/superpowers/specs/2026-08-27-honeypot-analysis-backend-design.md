# Honeypot Intelligence Platform — Phase 1 Backend Design

**Date:** 2026-08-27
**Status:** Approved (design), pending implementation plan
**Base paper:** Ilg, Germek, Duplys, Menth — *"Beekeeper: Accelerating Honeypot Analysis With LLM-Driven Feedback"*, IEEE Access vol. 13, 2025 (DOI 10.1109/ACCESS.2025.3613118)

---

## 1. Scope

The project has two subsystems. This spec covers **Phase 1 only**.

| Phase | Subsystem | Direction | Status |
| --- | --- | --- | --- |
| 1 | **Attack analysis** — ingest honeypot telemetry, analyze attacker sessions, map ATT&CK, extract IOCs, generate reports | Defender-side | **This spec** |
| 2 | **Beekeeper realism evaluation** — LLM agent attacks our own honeypot, static modules, evaluator LLM emits per-category realism critique and developer recommendations | Developer-side | Separate spec |

Phase 1 exists because the frontend is already built against it: `src/services/provider.ts` defines a `DataProvider` interface with 13 endpoints, and `FastAPIProvider` is a stub. Phase 1 makes that stub real. Phase 2 adds the paper's actual contribution and requires new UI routes.

**Non-goals for Phase 1:** the querying LLM agent, OpenVAS/nmap static modules, tcpdump checks, known-attack-chain execution, realism scoring, before/after re-evaluation. All Phase 2.

### 1.1 Success criteria

1. `docker compose up` brings up Cowrie, Filebeat, Elasticsearch, Kibana, Postgres; backend and Ollama run on the host.
2. Frontend with `VITE_API_BASE_URL=http://localhost:8000` renders every route from real data, with **no component changes**.
3. A seeded corpus gives every route non-empty data on first boot, before any live attacker connects.
4. Analysis of a real Cowrie session produces classification, ATT&CK mappings, IOCs and recommendations, each citing at least one real Elasticsearch event document.
5. The analysis stepper animates from real backend progress, not an indeterminate spinner.
6. No LLM-derived claim reaches the UI without provenance and resolvable evidence.

---

## 2. Constraints

**Hardware:** Ryzen 7 250, 24 GB RAM, RTX 5060 8 GB VRAM.

An 8 GB card holds an 8b Q4_K_M model (~5 GB) fully in VRAM. A 14b Q4 (~9 GB) spills to system RAM and becomes unusably slow. **Local model ceiling is 7–8b.**

The RTX 5060 is Blackwell (sm_120). It needs an Ollama build on CUDA 12.8+. Verify with `ollama ps` showing 100% GPU during a test generation before assuming GPU inference works; this is a known failure mode where the model silently runs on CPU.

**Paper finding that shapes the design:** the authors tested Llama3:70b, Mistral Large 2 (123b), Gemini 1.5 Pro and GPT-4o for the evaluator role and found models under 70b return "only superficial results." We cannot run 70b. Therefore the heavy narrative/recommendation role goes to a **BYOK cloud model**, with a local 8b fallback that is explicitly labelled lower-confidence in the UI. This mirrors the paper's own split of a small querying model and a large evaluating model.

**Two further paper findings carried forward:**
- Querying model config: temperature 0.3, 32k context (the authors note in-context reasoning already degrades at 32k, so we do not chase longer windows — we summarize instead).
- **Per-category context isolation.** The authors found that evaluating all categories in one prompt produced markedly less detailed output than one context per category. Phase 1 applies the same rule per analysis stage.

---

## 3. Topology

```
infra/docker-compose.yml
 ├─ cowrie           SSH:2222 / Telnet:2223 → JSON event log (volume)
 ├─ filebeat         tail cowrie.json → ingest pipeline → Elasticsearch
 ├─ elasticsearch    :9200   raw honeypot events (OBSERVED telemetry)
 ├─ kibana           :5601   ops/debug only, not user-facing
 └─ postgres         :5432   analyses, reports, profiles, evidence refs

host:
 ├─ ollama           :11434  llama3.1:8b  (GPU passthrough on Windows is
 │                           simpler on the host than in a container)
 └─ backend          :8000   FastAPI
 └─ frontend         :8080   existing app, VITE_API_BASE_URL=http://localhost:8000
```

### 3.1 The datastore split is a provenance boundary

This is the design's central invariant:

- **Elasticsearch holds what was observed.** Honeypot events, append-only, never mutated by analysis. Everything here is provenance `OBSERVED`.
- **Postgres holds what was derived.** Analyses, technique mappings, indicators, reports, attacker profiles. Everything here is `AI INFERENCE` or `CORRELATED`, and every row carries foreign keys back to the Elasticsearch documents that justify it.

The consequence: a derived claim can never exist without a pointer to observed data. Section 6 enforces this.

### 3.2 Cowrie → ECS mapping

Cowrie emits newline-delimited JSON with an `eventid` discriminator. Mapping to the existing `HoneypotEvent` type:

| Cowrie field | ECS / `HoneypotEvent` |
| --- | --- |
| `src_ip` | `source.ip` |
| `src_port` | `source.port` |
| `dst_port` | `destination.port` |
| `session` | `session.id` |
| `eventid` | `event.action` (e.g. `cowrie.command.input`) |
| `input` | `process.command_line` |
| `username` / `password` | `user.name`, credential IOC |
| `shasum`, `url`, `outfile` | download IOCs |
| `timestamp` | `@timestamp` |

`event.category` is derived from `eventid`: `.session.connect`→`network`, `.login.*`→`authentication`, `.command.*`→`process`, `.session.file_download`→`file`.

`risk.*`, `mitre.*` and `aiClassification` are **not** set at ingest. They are enrichment fields written only after analysis, and their presence is what distinguishes an analyzed from an unanalyzed event.

Implemented as an Elasticsearch **ingest pipeline** rather than Filebeat processors, so the mapping is versioned as JSON in `infra/elasticsearch/pipelines/` and is testable via the `_simulate` API.

### 3.3 Index strategy

Single index `honeypot-events` with an explicit mapping (no dynamic mapping — dynamic field explosion on attacker-controlled strings is a real hazard). `process.command_line` is indexed as `text` with a `keyword` subfield so the Log Explorer can both full-text search and aggregate exactly.

---

## 4. Backend layout

```
backend/
  pyproject.toml
  app/
    main.py              FastAPI app, CORS(:8080), router mount, lifespan
    config.py            pydantic-settings: ES_URL, PG_DSN, OLLAMA_HOST,
                         BYOK provider + key, model names
    deps.py              DI: es client, db session, llm clients

    db/
      models.py          SQLModel tables (§5)
      migrations/        alembic
    es/
      client.py
      queries.py         LogQuery → ES DSL; session aggregation
      pipelines.py       install ingest pipeline + index template on startup

    routers/
      honeypots.py  sessions.py  logs.py  analyze.py  mitre.py
      intel.py      attackers.py reports.py dashboard.py status.py

    services/
      session_builder.py   ES events → AttackSession
      analyzer.py          orchestrates one analysis run (§6)
      mitre/
        rulebook.yaml      regex → technique (deterministic)
        mapper.py          rules first, LLM gap-fill
        attack_data.py     ATT&CK Enterprise technique catalog loader
      intel.py             IOC extraction
      reports.py           ThreatReport assembly
      llm/
        base.py            LLMClient protocol
        ollama.py          local client (llama3.1:8b, temp 0.3)
        byok.py            cloud client (Anthropic / OpenAI / Gemini)
        schemas.py         Pydantic response schemas
        prompts/           one file per stage

    workers/
      queue.py           asyncio job queue + per-job progress pub/sub
    ws/
      progress.py        WS /api/analyze/{session_id}/progress

    seed/
      corpus/            deterministic Cowrie-format session fixtures
      seeder.py          load corpus → ES (§8)
  tests/
```

### 4.1 Endpoint surface

Exactly the set named in the README, unchanged:

```
GET  /api/status                        GET  /api/dashboard?range=
GET  /api/honeypots
GET  /api/sessions                      GET  /api/sessions/{id}
GET  /api/sessions/{id}/timeline        GET  /api/sessions/{id}/events
GET  /api/logs
POST /api/analyze/{session_id}          WS   /api/analyze/{session_id}/progress
GET  /api/analysis                      GET  /api/analysis/{id}
GET  /api/mitre                         GET  /api/threat-intelligence
GET  /api/attackers/{ip}
GET  /api/reports                       POST /api/reports
```

Plus one addition required by §6.3:

```
GET  /api/events/{event_id}             resolve an EvidenceRef to its source event
```

### 4.2 Sessions are derived, not stored

Cowrie has no session document — only events sharing a `session` id. `session_builder` reconstructs `AttackSession` by ES terms-aggregation on `session.id`, computing `commandCount`, `durationSeconds`, `startedAt`/`endedAt`, and `analysisState` (from Postgres). `classificationChain` and `mitreTechniqueIds` are populated only for analyzed sessions; unanalyzed sessions return empty arrays, never invented values.

---

## 5. Postgres schema

```
analyses
  id (uuid pk), session_id, model, analysis_type, status,
  created_at, duration_seconds, classification, confidence,
  risk_score, risk, behavior_summary, model_tier ('local'|'cloud'),
  evaluator_model, prompt_version

technique_mappings
  id, analysis_id fk, technique_id, technique_name, tactic,
  confidence, ai_explanation, source ('rule'|'llm'), rule_id, timestamp

observed_behaviors        id, analysis_id fk, label
suspicious_indicators     id, analysis_id fk, label, severity
recommended_actions       id, analysis_id fk, priority, action, rationale

indicators
  id, type, value, confidence, first_seen, last_seen, source, tags[]
  unique(type, value)
indicator_sessions        indicator_id fk, session_id

evidence_refs                                          -- §6.3
  id, es_event_id, session_id, timestamp, artifact,
  parent_type ('technique_mapping'|'observed_behavior'
              |'suspicious_indicator'|'indicator'),
  parent_id
  index(es_event_id), index(parent_type, parent_id)

reports                   id, session_id, analysis_id fk, title,
                          created_at, generated_by, body (jsonb)
attacker_profiles         ip pk, risk, risk_score, behavior_label,
                          first_seen, last_seen, geo (jsonb), updated_at
```

`evidence_refs` is a single polymorphic table rather than four join tables. Rationale: every consumer query is "give me the evidence for this claim," the shape is identical across parents, and the alternative multiplies near-identical tables. The `parent_type`/`parent_id` pair is always written inside the same transaction as its parent row, so integrity is enforced by the writing service (§6.3), not by a database FK.

---

## 6. The analysis pipeline

`POST /api/analyze/{session_id}` enqueues a job and returns immediately with `status: "queued"`. The worker runs seven stages — exactly the members of the existing `AnalysisStage` union, in order:

| # | Stage | Engine | Provenance of output |
| --- | --- | --- | --- |
| 0 | `parsing_logs` | ES query + normalize | — |
| 1 | `identifying_patterns` | deterministic | `OBSERVED` |
| 2 | `classifying_behavior` | local 8b | `AI INFERENCE` |
| 3 | `extracting_indicators` | regex + local 8b | `OBSERVED` / `AI INFERENCE` |
| 4 | `mapping_mitre` | rules → local 8b gap-fill | `OBSERVED` / `AI INFERENCE` |
| 5 | `generating_intel` | correlation across sessions | `CORRELATED` |
| 6 | `generating_recommendations` | BYOK cloud (fallback local) | `AI INFERENCE` |

Each stage runs in **its own LLM context** with its own prompt file, per the paper's finding on context isolation. Each stage boundary publishes an `AnalysisProgressEvent` (`stageIndex`, `stage`, partial `metrics`) to the WS channel, which drives the existing stepper unchanged.

### 6.1 Context budgeting

A long session can exceed what an 8b model handles well. Before any LLM stage, the session is compacted: deduplicate repeated commands (keeping counts), truncate each command's captured output to its head and tail (`SEED_OUTPUT_HEAD_LINES` / `SEED_OUTPUT_TAIL_LINES`, default 20 each, config-tunable), and drop events carrying no analytic signal. If the compacted payload still exceeds the token budget, the session is chunked and stage results merged.

Compaction is deterministic, so two runs over the same session produce identical prompts. Truncation never discards an event — only output *within* an event — so every retained command keeps its Elasticsearch document id and stays citable under §6.3.

### 6.2 MITRE hybrid mapper

`rulebook.yaml`:

```yaml
- id: T1105
  name: Ingress Tool Transfer
  tactic: Command and Control
  match: '\b(wget|curl|tftp)\b.*\b(https?|ftp)://'
- id: T1222.002
  name: Linux and Mac File and Directory Permissions Modification
  tactic: Defense Evasion
  match: '\bchmod\s+(?:[0-7]{3,4}|[ugoa]*\+[rwx]+)'
- id: T1082
  name: System Information Discovery
  tactic: Discovery
  match: '\buname\b|/etc/os-release|/proc/cpuinfo|\blscpu\b'
- id: T1003.008
  name: /etc/passwd and /etc/shadow
  tactic: Credential Access
  match: '/etc/(passwd|shadow)'
- id: T1098.004
  name: SSH Authorized Keys
  tactic: Persistence
  match: 'authorized_keys'
- id: T1496
  name: Resource Hijacking
  tactic: Impact
  match: '\b(xmrig|minerd|c3pool|cpuminer)\b'
```

The seed rules cover the attack chains the paper documents in §III-C: `cd /tmp` → `wget` → `chmod 777` → execute; `rm -rf .ssh` → write `authorized_keys`; XMRig download → `passwd` lockout. This is deliberate — the same rulebook becomes a Phase 2 asset for checking whether our honeypot emulates known chains correctly.

Flow: every command is tested against all rules. A hit produces a mapping with `source='rule'`, `confidence=1.0`, `observed=true`, provenance `OBSERVED`, and `relatedCommands` set to the literal matching command lines. Commands matching no rule are batched into one LLM call constrained by a Pydantic schema whose `technique_id` field is validated against the loaded ATT&CK catalog — a hallucinated ID is rejected, not stored. LLM mappings get `source='llm'`, `observed=false`, provenance `AI INFERENCE`, and a required `ai_explanation`.

This makes `MitreTechnique.observed` mean something precise: telemetry directly supports it via a deterministic rule. That is the guarantee the README's provenance table already promises the user.

### 6.3 Evidence as a first-class citizen

**Requirement:** every derived claim resolves to specific Elasticsearch event documents. Not a copied string — a pointer.

Enforcement is threefold:

1. **`eventId` becomes required.** The current `EvidenceRef` has `eventId?: string | undefined`. It becomes required, as does `timestamp`. `artifact` remains the human-readable excerpt but is now a *denormalized convenience*, not the identity of the evidence. This is a frontend type change (§9).

2. **Schema-level citation.** Every LLM response schema that yields a claim carries a non-empty `evidence: list[EvidenceRef]`. The model is given the candidate events *with their ES document ids* and must cite by id. A response whose evidence list is empty, or which cites an id absent from the input set, fails validation.

3. **Write barrier.** `analyzer` refuses to persist any `technique_mapping`, `observed_behavior`, `suspicious_indicator` or `indicator` with zero evidence rows. A claim that survives model validation but cannot be grounded is dropped and counted in the run's `rejected_claims` metric, surfaced on the Settings/status page. Silent dropping without a counter would hide model quality problems.

`GET /api/events/{event_id}` resolves a ref back to its full `HoneypotEvent`, so the UI can expand any AI conclusion into the exact log line, session and timestamp that produced it — which is precisely what the existing `EvidenceList` component was built to do.

**Consequence worth stating plainly:** claim volume will be lower than an ungrounded design would produce. That is the intent. An uncited claim is not a finding.

### 6.4 Model tiering and BYOK

The BYOK key is submitted from the Settings page, held in backend process memory and env, and never returned to the browser. `GET /api/status` reports whether a cloud evaluator is configured, and `analyses.model_tier` records which tier produced each run so the UI can mark local-fallback runs as lower-confidence.

If no key is configured the pipeline still completes end to end on the local 8b model. Degraded output, never a failed run.

---

## 7. Threat intelligence and attacker profiles

`generating_intel` correlates the current session against prior ones: shared IOCs, command-sequence overlap, credential reuse. Indicators are upserted on `(type, value)` so `firstSeen`/`lastSeen`/`sessionIds` accumulate across sessions — this is what makes them `CORRELATED` rather than `OBSERVED`.

`AttackerProfile.similarity` is computed as Jaccard similarity over each IP's normalized command set. Deterministic, explainable, and defensible in a viva — no embedding model needed for the scale involved.

---

## 8. Deterministic seeder

**Purpose:** every route has meaningful data on first boot, and analysis output is reproducible for demos and tests.

`backend/app/seed/corpus/` holds hand-authored Cowrie-format session fixtures with fixed session ids, source IPs and timestamps relative to a pinned base time. Coverage:

- a botnet-style chain (brute force → `uname`/`cat /proc/cpuinfo` → `cd /tmp` → `wget` → `chmod 777` → execute)
- an SSH persistence chain (`rm -rf .ssh` → `authorized_keys` write)
- a cryptomining chain (XMRig download → execute → `passwd`)
- a slow manual reconnaissance session (low risk, sparse)
- a failed brute force with no successful login (informational)
- a session containing commands matching **no** rulebook entry, to exercise the LLM gap-fill path

`python -m app.seed.seeder --reset` writes these through the same ingest pipeline as live Cowrie traffic. Same code path, no special case — a fixture is indistinguishable from live telemetry downstream, which is the point.

Seeded events are marked with `labels.seeded: true` in Elasticsearch. The frontend already renders a **DEMO DATA** badge; `GET /api/status` reports seeded-event count so the badge can reflect real backend state rather than provider mode alone.

Seeding runs on first startup only when the index is empty, and is idempotent — fixed document ids mean re-running overwrites rather than duplicates.

---

## 9. Frontend changes

The architecture goal is zero component changes. Making evidence first-class costs us that goal in exactly one place, which is stated here rather than discovered during implementation.

1. **`EvidenceRef.eventId` and `.timestamp` become required** (`src/types/analysis.ts`). Consumers already read both defensively; making them required is a tightening, and TypeScript will flag any fixture that omits them. The demo provider's fixtures need `eventId` values added.

2. **`ServiceStatus` gains seeded-corpus and evaluator-tier rows** — no new type, just additional entries in the existing array rendered by the Settings page.

3. **`DataProvider` gains `getEvent(eventId): Promise<HoneypotEvent>`** — a contract change, implemented by both providers (`FastAPIProvider` calls `GET /api/events/{event_id}`; `DemoProvider` looks up its fixture set). This is what turns an `EvidenceRef` from a copied string into a resolvable pointer.

4. **`EvidenceList` becomes expandable** — one component change, consuming `getEvent` so an AI conclusion opens into the full source event. Without this the backend's evidence guarantee exists but the user cannot see it. Scoped as the last item of Phase 1; the rest of the phase is testable without it.

Everything else — `DashboardData`, `SessionAnalysis`, `MitreCoverage`, `ThreatReport` — is satisfied as-is by the backend.

`FastAPIProvider` gains the `subscribeAnalysisProgress` implementation over the WS channel. Per the README this is currently and deliberately absent; implementing it lights up the stepper with no UI change.

**Conventions to honor, from the README:** confidence is a 0–1 fraction; risk score is 0–100. The backend serializes camelCase to match the existing types.

---

## 10. Testing

- **Ingest:** ES `_simulate` against recorded Cowrie lines asserting the ECS mapping.
- **Rulebook:** table-driven — each rule gets positive and negative command cases. Guards against a broadened regex silently over-matching.
- **Schema validation:** fed deliberately malformed and hallucinated LLM responses (invalid technique ids, empty evidence, cited ids absent from input), asserting each is rejected and counted.
- **Evidence barrier:** assert no claim persists with zero evidence rows.
- **Pipeline:** end-to-end over the seeded corpus with a stubbed LLM client, asserting deterministic stages (patterns, rule mappings, IOC regex) produce byte-identical output across runs.
- **Contract:** each endpoint's response validated against a schema mirroring the TypeScript types, so provider drift fails CI rather than the browser.

LLM-dependent assertions test *shape and grounding*, never exact prose.

---

## 11. Security boundaries

- Elasticsearch, Postgres, Ollama and BYOK credentials never reach the browser. The frontend knows one API base URL.
- Cowrie is the deliberate exception to normal hardening — it exists to be attacked. It binds to non-privileged ports on the local network only. **It must not be exposed to the public internet during development.** Phase 2 involves attacking it from inside the same compose network.
- Attacker-controlled strings (commands, filenames, credentials) are treated as untrusted throughout: no dynamic ES field creation, and command text is never interpolated into a shell. Command text placed in LLM prompts is fenced and prefixed as untrusted data — a honeypot log is an obvious prompt-injection vector, since an attacker who suspects analysis can write instructions into a command line.
- Downloaded malware samples are referenced by hash only. Phase 1 never executes or unpacks a captured artifact.

---

## 12. Phase 2 preview (not in scope)

Recorded so Phase 1 does not foreclose it: querying LLM agent over Paramiko SSH with per-module command budgets across the paper's six characteristics (basic commands, file system, services, attack possibilities, sanity, context); static modules (nmap/OpenVAS, tcpdump traffic presence, known attack chain execution); evaluator LLM producing per-category critique and improvement recommendations; before/after re-evaluation comparison; new frontend routes.

Phase 1 assets that Phase 2 reuses directly: the rulebook (for verifying known-chain emulation), the LLM client abstraction and tiering, the evidence model, the job queue and WS progress channel, and the Cowrie compose service as the target under test.

---

## 13. Open items for the implementation plan

- Filebeat versus a small Python tailer — decide at implementation time based on which handles Cowrie's log rotation more cleanly.
- ATT&CK catalog source: bundle a pinned Enterprise JSON versus fetching `mitre/cti` at build. Pinned is likely, for offline reproducibility.
- Exact local model choice benchmarked on the target GPU: `llama3.1:8b` per the paper versus `qwen2.5:7b`. The paper's choice is the default; deviation requires a measured reason.
