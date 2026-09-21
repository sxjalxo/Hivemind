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
| packet capture | runs in the honeypot container's own network namespace, from `nicolaka/netshoot`, pinned by digest like every other image here — `docker pull $(grep EVALUATION_CAPTURE_IMAGE backend/.env.example \| cut -d= -f2)` once |

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

## Retention and index lifecycle

`honeypot-events` is a **rollover alias**, not a single index. An index lifecycle
policy rolls it over at 5 GB per primary shard or 30 days, whichever comes first,
so no one index grows without bound.

**Nothing is ever deleted.** The policy has no delete phase, deliberately, and
adding one is a decision rather than a tidy-up: captured attacker telemetry is
this project's research data, a delete phase runs on a timer against data nobody
is watching, and the first sign it was wrong is a gap in a paper. What rollover
buys instead is that old indices become individually droppable *by hand*, once
you have decided you don't need them:

```bash
curl -s "http://localhost:9200/_cat/indices/honeypot-events*?v&h=index,docs.count,store.size"
curl -s -X DELETE "http://localhost:9200/honeypot-events-000001"   # only when you mean it
```

Disk still fills eventually — slowly, and visibly in that first command.

**Existing deployments are not converted automatically.** A backend that finds a
concrete index where the alias should be logs a warning and carries on unchanged;
converting means reindexing and deleting the original, which is not something to
do unattended to telemetry. Do it deliberately, with the backend stopped:

```bash
cd backend && .venv/Scripts/python -m scripts.migrate_to_rollover          # dry run
cd backend && .venv/Scripts/python -m scripts.migrate_to_rollover --apply
```

It verifies document counts before it removes anything, and refuses to delete the
source if the copy is short.

Two couplings had to be fixed before rollover was safe, and both are load-bearing
if you touch this area:

- **`es.update(index, id)` only ever reaches the write index.** Through an alias,
  every document older than the current write index answers
  `document_missing_exception` — which the caller caught and logged as a warning,
  so the dashboard's technique filter would have silently stopped covering
  anything but the newest index. Enrichment uses one `update_by_query` instead,
  which resolves the alias across all of its indices.
- **Document ids are unique per index, not per alias.** The seed corpus uses fixed
  ids and relied on overwrite for idempotency; after a rollover that writes a
  *second* copy into the new index while the original survives in the old one.
  `seed()` now always deletes by query before indexing.

Postgres has no retention policy at all. Growth there is one row per analysis and
per evaluation run, which is slow enough to ignore for now.

---

## Docker privilege

The backend talks to the Docker daemon, and that access has no gradations of
its own: whoever can reach it can create a container, and
`docker run -v /:/host --privileged` is root on the host with no exploit
required. No socket proxy, seccomp profile or API policy makes that call safe.
It can only be not made.

So the application does not make it. Three verbs are permitted, enforced by an
allowlist every docker invocation passes through
(`app/services/evaluation/container.py`):

| | |
|---|---|
| `inspect` | read-only metadata |
| `exec` | root *inside* a container that mounts nothing from the host but a read-only config file |
| `kill` | signals a container this deployment declared |

`run` and `create` are absent, and their absence is the point. The packet
capture was the only thing that needed one; it now `exec`s tcpdump into the
`capture` sidecar, which docker-compose declares with
`network_mode: service:cowrie` so it sits in the honeypot's own network
namespace. Which namespace a capture sees is therefore a property of the
compose file rather than of an argument the backend assembles — which is also
where a run against one honeypot could previously attach to another's.

**What this does and does not buy.** It does not stop an attacker who already
has code execution in the backend: they would call the docker CLI directly, and
the daemon would oblige. What it does is make the set of Docker operations this
application performs small, enumerable and enforced, so the blast radius of a
*bug* — a careless new caller, a path built from the wrong variable — is a
container rather than the host. Tests hold the line, including one that fails
if any module builds a docker argv and spawns it itself.

**The residual risk is the daemon socket, and it is not removed.** A backend
with code execution is still a backend that can reach Docker. If that matters
for your deployment, the options in order of effort are: run the backend as a
user outside the `docker` group and give the evaluation subsystem its own
privileged helper; or put a socket proxy in front of the daemon exposing only
`GET /containers/*/json` and the exec endpoints — now feasible precisely
because nothing here needs container creation any more. Neither is configured
here, and neither is worth doing while the backend and the honeypot share a
laptop.

## Authentication

**Unset, the API is open.** Every route and both WebSocket channels answer any
caller that can reach the port. That is what this backend has always done and it
is defensible only while it is bound to `127.0.0.1`. It is never silent: the
backend logs a warning naming the setting on every start, and `GET /api/status`
carries an `authentication` row reading `OPEN — every route answers any caller`.

Set `CLERK_ISSUER` and every `/api` route requires a valid Clerk session token:

```bash
# backend/.env
CLERK_ISSUER=https://your-instance.clerk.accounts.dev
CLERK_AUTHORIZED_PARTIES=["http://localhost:8080"]
```

The frontend is wired by `clerk init` and needs nothing further — it attaches
the token to every request, and to both WebSockets as a subprotocol, because a
browser cannot set an `Authorization` header on a handshake and a session token
must not travel in a query string where access logs would keep it.

Tokens are verified locally against Clerk's published JWKS, so a request costs a
signature check and nothing on the network. Four things are checked and each one
matters:

| Check | Without it |
|---|---|
| signature (RS256, against the instance's JWKS) | anyone can mint a token |
| `iss` | a valid token from someone else's Clerk instance is accepted |
| `azp` vs `CLERK_AUTHORIZED_PARTIES` | a token for a *different app on your own instance* is accepted |
| `exp`/`nbf`, with leeway | either replay forever, or reject everything when the host clock drifts |

`aud` is deliberately not checked — Clerk does not set it on session tokens, so
verifying it would reject every real token.

### Roles

Two roles, and they are **per honeypot**. The session token carries a global
`role` (from `public_metadata.role`) and an optional per-honeypot map
(`public_metadata.roles`):

```bash
clerk api /users/<id> -X PATCH -d '{"public_metadata":{
  "role": "viewer",
  "roles": {"cowrie-01": "admin", "vm-baseline": "viewer"}
}}'
```

Resolution is most-specific-first: an explicit entry wins, otherwise the global
role, otherwise `viewer`. **An explicit entry wins even when it is lower** —
naming a honeypot `viewer` while holding a global `admin` has to mean something,
or the map could only ever widen access and would not be an access-control list.

Scoping is **write-only**. It decides who may start an evaluation or an analysis
against a honeypot; it does not decide who may read one. Every authenticated
caller still sees every session, every run and every report. That is a
deliberate boundary and not a confidentiality one — say so out loud rather than
letting the word "roles" imply otherwise.

The two roles themselves:

| | |
|---|---|
| `admin` | everything |
| `viewer` | read-only: every `GET`, and both progress WebSockets |

Three operations require `admin`, and they are the ones that cost something or
touch a honeypot: `POST /api/analyze/{id}` (one LLM pipeline on the one GPU),
`POST /api/reports` (which runs an analysis when the session has none), and
`POST /api/evaluations` — which **resets the honeypot's container and executes
attack chains against it**. That last one is the reason this is not cosmetic.

**A token with no role, or an unrecognised one, is a viewer — not a rejection.**
Failing closed entirely is the reflex and it is wrong here: the role is a Clerk
claim, so anything that stops it propagating would lock out every account at
once, yours included, with the recovery being to turn authentication off.
Degrading to read-only cannot *grant* anything, because every admin route
demands the role explicitly.

The UI hides the controls a viewer cannot use, but that is courtesy, not the
boundary — the backend answers 403 regardless of what was rendered.

Assign a role:

```bash
clerk users list --json | jq '.data[] | {id, email_addresses, public_metadata}'
clerk api /users/<user_id> -X PATCH -d '{"public_metadata":{"role":"admin"}}'
```

Each mutating route is gated twice: a coarse dependency refuses anyone who is
admin on *nothing*, then the handler checks the specific honeypot. The coarse
half matters because `/api/analyze/{id}` and `/api/reports` only learn their
honeypot by resolving the session — without it, a viewer probing session ids
would get 404 for one that does not exist and 403 for one that does, which is an
existence oracle.

*(On Git Bash, prefix with `MSYS_NO_PATHCONV=1` or the leading `/users` is
rewritten into a Windows path.)*

**Sign-up is restricted**, so an account cannot be created without an
invitation — `auth_access_control.sign_up_mode` is `restricted` on the instance.
Invite from the Clerk dashboard, then set the new user's role; until you do,
they can read and nothing else.

### Who ran what

Every evaluation run records who started it, because a run resets a honeypot's
container and executes attack chains against it. `GET /api/evaluations` and the
run detail both carry it, and the history table shows it.

`started_by` is NOT NULL and prefixed, so three situations stay three values
instead of collapsing into one null:

| | |
|---|---|
| `user:<clerk_id>` | an authenticated caller; `started_by_label` holds the email the token asserted at the time |
| `unauthenticated` | `CLERK_ISSUER` was unset, so no identity existed to record |
| `unrecorded` | the run predates the audit trail (backfilled by migration `c7d3e1a95b42`) |

"Nobody was authenticated" and "we never asked" are different facts. An audit
trail that answers the same way for both lets a gap read as an anonymous
action — the same collapse `undetermined` prevents for findings.

The actor is derived from the verified token, never from the request:
`StartEvaluationRequest` forbids extra fields, so a caller cannot name itself.

Session analyses carry the same audit columns as evaluation runs
(`analyses.started_by`, migration `d2f8b4c61e07`), on the same three-valued
scheme, and a report credits the analysis it triggers to whoever asked for the
report.

**What this still does not do.** Read paths are not scoped, per above. Roles
are per honeypot but not per session or per report. And the roles map is edited
by hand through the Clerk API — there is no UI for granting access.

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

It also reports **what happened to each individual defect** — `new`, `persisting`,
`fixed`, `regressed`, or `undetermined` — so the question "is the flaw you reported last
week actually fixed?" has an answer, not just "the score moved".

`undetermined` is the one that earns the other four their credibility. A finding is
absent from a run for two unrelated reasons: the fact came back `observed`, or the fact
was never established. Reporting the second as `fixed` would manufacture good news out
of an infrastructure failure, so resolution joins the underlying fact status rather than
differencing finding keys. The same rule covers the evaluator: run one evaluation with a
BYOK key and the next without, and every evaluator finding is `undetermined`, never
`fixed`.

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

635 tests. They run against the live Docker stack and the real local model, so bring the
infrastructure up first. **A clean run is `635 passed, 1 skipped`** — there
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
infra/       Elasticsearch index template, ingest pipeline and lifecycle policy,
             Filebeat and Cowrie config
```

The evaluation subsystem is the largest piece, split by concern rather than by
layer — each module fails differently, which is the line the split follows:

```
services/evaluation/
  runs.py          orchestration: preconditions, stages, scoring, persistence,
                   reconciliation. The seams the test suite replaces live here.
  chain_runner.py  execute the attack chains, verify them from the honeypot's own log
  read.py          hydration and the list/detail endpoints — never writes
  findings.py      turning established facts into defects a developer can act on
  comparison.py    lifecycle resolution and compare_runs
  state.py         the few types the others share
  container.py     the ONLY place that talks to Docker, behind a verb allowlist
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
  for a host-run backend. A run now refuses to start when nothing accepts a connection
  there, naming the setting — rather than spending the full agent budget producing a run
  in which every fact is `unknown`.
- **The packet capture needs Docker**, because it runs inside the honeypot container's
  network namespace. Clearing `EVALUATION_CAPTURE_IMAGE` falls back to a host `tcpdump`,
  which is only correct where the host shares the honeypot's network — not when the
  honeypot is a container reached through a published port.
- **One honeypot per target entry.** `EVALUATION_TARGETS` maps honeypot ids to targets
  (JSON, snake_case keys: `{"cowrie-degraded": {"host": "127.0.0.1", "ssh_port": 2322,
  "container_name": "hivemind-degraded-1"}}`). Leave it empty and the single `EVALUATION_*` target serves
  every honeypot, which is what a one-decoy deployment wants. Once it holds anything, an
  unmapped id is refused rather than quietly sent to the default — evaluating one
  honeypot under another's label would file every score, finding and fingerprint against
  the wrong decoy.
- **A target that is not Cowrie must say so**, with `"kind": "generic"`. Three things
  only work against this Cowrie image: the container reset, the `cowrie.cfg` digest in
  `honeypot_fingerprint`, and chain verification, which reads commands back out of
  Cowrie's own log. A `generic` target skips all three. It is also the flag that keeps
  the attack chains off a real machine — every step is emulated on Cowrie and real
  anywhere else, so a chain marked `destructive` in `chains.yaml` is refused against a
  target that does not simulate commands. All three shipped chains are destructive, so a
  generic target scores no `attack_possibilities` at all: it is reported unestablished,
  never as a zero. `kind` defaults to `cowrie`, but every field that makes a target
  dangerous defaults the safe way — a target with no `container_name` is rejected rather
  than guessed at, and the internal `EvaluationTarget` defaults to `generic`.
- **A generic target's fingerprint covers where it is, not what it contains.** There is
  no image id to read and no config to digest, so reinstalling or reconfiguring one
  between two runs moves nothing and the comparison will call the delta attributable.
  Two runs against a generic target are comparable only insofar as you did not change
  it, and nothing in the system can check that for you.
- **Single-worker deployment.** The job queue and WebSocket fan-out are in-process;
  multiple uvicorn workers would need Redis pub/sub.
- **The scoring and compaction algorithms are not fingerprinted.** `scoring.py` is pure
  functions with no constants to hash, so two runs spanning a change to how a fraction is
  computed fingerprint identically — git revision is the extra key when reading a trend.
  The result-deciding *constants* elsewhere (the agent's per-command timeout and output
  cleaning patterns, nmap's expected services, the rulebook's text filters) are hashed by
  value; regex compile flags are not.

See [`OVERVIEW.md`](OVERVIEW.md) for the design rationale and the full limitation list,
and [`DEMO.md`](DEMO.md) for the setup guide and a screen-by-screen walkthrough written
for someone seeing the project for the first time — including a troubleshooting section
for everything that commonly goes wrong.
