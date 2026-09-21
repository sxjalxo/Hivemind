# Hivemind — Project Overview

*Companion to [`README.md`](README.md), the technical reference, and
[`DEMO.md`](DEMO.md), the setup and demo guide for someone new to the project.*

This file explains **why** the system is built the way it is. Read one of the other two
first if you want to run it rather than reason about it.

---

## 1. The problem

A honeypot is a decoy system left exposed so that attackers will attack it. Every
command an intruder types, every file they download, every credential they try is
recorded. The recording is the easy part.

The hard part is that a honeypot produces **volume without meaning**. A week of
exposure on the public internet yields tens of thousands of log lines, overwhelmingly
from automated botnets replaying the same handful of intrusion scripts. Buried in that
noise are the sessions worth knowing about. Finding them, and explaining what happened,
is manual work that requires an analyst who knows what a compromised Linux host looks
like from the inside.

That creates three specific difficulties.

**Interpretation does not scale.** Raw telemetry says an attacker ran `wget`, then
`chmod 777`, then `sh`. It does not say "this is a botnet dropper installing a
cryptocurrency miner". Producing that sentence requires reading the whole session in
order and recognising a pattern. Doing it for every session is not feasible by hand.

**Structured intelligence has to be extracted, not just read.** To be useful beyond a
single incident, a session has to yield things other systems can consume: MITRE ATT&CK
technique identifiers, indicators of compromise (IPs, URLs, file hashes), a risk
assessment. Each of those is a judgement call about ambiguous evidence.

**And here the obvious fix creates a worse problem.** Pointing a language model at
honeypot logs and asking "what happened?" produces fluent, plausible, immediate output.
It also produces confident claims about attacks that did not occur, technique IDs that
do not exist, and evidence citations pointing at nothing. In a security context this is
worse than no automation at all: an analyst cannot distinguish a model's guess from a
recorded fact, and a false ATT&CK mapping propagates into every downstream report and
dashboard as though it were ground truth.

So the real problem is not "can a model summarise logs". It is **how do you use a
language model on security telemetry without laundering its guesses into facts**.

---

## 2. Our solution

Hivemind is built around a single organising rule:

> **Nothing is presented as fact unless telemetry supports it, and every conclusion can
> be expanded into the exact log line that produced it.**

Everything else follows from that.

The system has two halves, and they share that rule, one rulebook, one evidence model
and one job queue. The first analyses attacks the honeypot captured. The second turns
the same machinery around and attacks the honeypot itself, to measure how convincing it
would look to an intruder — because a decoy an attacker sees through yields nothing, and
credibility feedback is otherwise the slowest, most expensive step in building one.

### Deterministic first, model second

MITRE ATT&CK mapping runs in two passes. A YAML rulebook of 13 regular expressions
matches commands whose meaning is unambiguous — `wget http://…` is Ingress Tool
Transfer, `chmod 777` is a permissions modification, writing to `authorized_keys` is
SSH key persistence. A rule match is deterministic and reproducible, so it earns the
label **observed** at confidence 1.0.

Only commands the rulebook cannot explain go to the LLM, and whatever it proposes is
labelled **AI inference** with `observed = false`, carrying a required explanation.
The interface renders those differently. An analyst can always tell which techniques
the telemetry proves and which a model suggested.

Making that boundary trustworthy took real work. The rulebook went through four
rounds of hardening against a specific failure: a regex matching a trigger token that
appears as *data* rather than as an executed command. `echo "download with wget
http://x"` prints a string; it does not transfer a tool. Early versions flagged it as
observed ingress. The fix anchors patterns to command position, allows wrapper binaries
(`sudo`, `nohup`, `timeout`, `bash -c`), respects shell quoting and comments, and models
backslash escapes — validated against real `sh` semantics.

### Three gates between the model and the database

**Schema validation.** Every model response is parsed into a strict schema. A proposed
technique ID absent from the pinned ATT&CK catalog is rejected. A citation naming an
event that was never shown to the model is rejected. An empty evidence list fails
validation outright.

**The evidence write barrier.** All claim persistence funnels through one function that
refuses to store any derived claim without at least one resolvable pointer to a real
Elasticsearch document, writing evidence in the same transaction as its parent. Rejected
claims are *counted*, not silently dropped — the count surfaces in the interface, because
a model quietly producing ungrounded output is exactly what an operator needs to see.

The deliberate consequence: Hivemind produces fewer claims than an ungrounded design
would. That is the intent. An uncited claim is not a finding.

**Enrichment scoping.** After analysis, results are projected back into Elasticsearch so
the dashboard can aggregate them. ATT&CK identifiers are written back **only** for
rule-backed mappings. Projecting an inference would make it indistinguishable from
observed telemetry in every subsequent query.

### Two assessments, never one number

The evaluation half produces two quantities per characteristic and refuses to merge them:
a **deterministic assessment** ("did the honeypot do the checkable things?") computed from
facts alone, and an **evaluator assessment** ("would an attacker believe it?") from a cloud
model. There is deliberately no composite. Averaging a measurement with an opinion produces
a number that means neither.

Facts are tri-state — `observed`, `not_observed`, `unknown` — and the third value is
load-bearing. A probe that timed out yields `unknown`, which is excluded from *both* the
numerator and the denominator, so **our own failure is never counted as evidence against
the honeypot**. The same instinct runs through the layer above: a failed reset aborts the
run rather than degrading it, because a reset that did not happen means run B may still
hold run A's residue and any comparison drawn from it is unsound.

### Honest about what it does not know

Unanalysed sessions report `not_analyzed` with empty technique lists and zero risk,
never invented placeholder values. Dashboard panels that depend on analysis show zeros
until an analysis runs. Where a field genuinely has no source — a file size Cowrie never
records — the field is omitted rather than reported as `0`, because "never recorded" and
"recorded as zero" are different claims.

---

## 3. Setup

Full instructions are in [`README.md`](README.md). In brief:

```bash
docker compose up -d                                    # infrastructure
ollama pull llama3.1:8b                                 # local model
cd backend && python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"
.venv/Scripts/python -m alembic upgrade head
.venv/Scripts/python -m uvicorn app.main:app --port 8000
cd ../frontend && npm install
echo "VITE_API_BASE_URL=http://localhost:8000" > .env
npm run dev                                             # http://localhost:8080
```

The backend installs its Elasticsearch pipeline and index template on first start and
seeds a deterministic corpus, so the interface has data immediately. SSH to
`127.0.0.1:2222` with any password to generate live traffic.

**One check worth not skipping:** after pulling the model, confirm `ollama ps` reports
`100% GPU`. If it falls back to CPU everything still works but runs several times
slower, and nothing warns you.

---

## 4. What the project offers

**Live honeypot ingest.** Cowrie SSH/Telnet feeding Elasticsearch through Filebeat and
a versioned ingest pipeline that maps Cowrie's native JSON onto ECS field names. The
index mapping is strict, so an unrecognised field fails loudly rather than being
silently dropped.

**Session reconstruction.** Cowrie has no session record — only events sharing an id.
Sessions are rebuilt by aggregation, with command counts, durations, and an ordered
timeline classifying each event as connection, authentication, command, download or
disconnect.

**A seven-stage analysis pipeline** — parse, identify patterns, classify behaviour,
extract indicators, map ATT&CK, correlate intelligence, generate recommendations. Each
stage runs in its own model context, because the source paper found that merging them
produces markedly shallower output. Progress streams to the interface over a WebSocket,
so the stepper reflects real backend state rather than an animated guess.

**Hybrid ATT&CK mapping** against a pinned 21-technique catalog, with the observed
versus inferred distinction preserved end to end — through the database, through the
Elasticsearch projection, and into the matrix the analyst reads.

**Threat intelligence** with three provenance tiers. An indicator's *value* is observed;
its accumulation across sessions is derived, so an indicator seen in more than one
session becomes `CORRELATED`. Extraction is deterministic regex and direct field reads —
no model involvement — covering IPs, URLs, file hashes, filenames, usernames and commands.

**Attacker profiles** with Jaccard similarity over normalised command sets. Deterministic and
explainable rather than embedding-based: a reviewer can verify why two attackers were
called similar.

**Threat reports** stored as immutable JSONB snapshots. Re-analysing a session later
does not rewrite a report already issued.

**An automated realism evaluation.** A Paramiko SSH agent under hard command and
wall-clock budgets, an nmap service scan, a tcpdump traffic-presence check and three
scripted attack chains, run against the honeypot and scored across six characteristics.
Chain verification reuses the same ATT&CK rulebook the analysis half uses, and reads the
result back out of Cowrie's own log — scoped to the SSH session the harness itself opened,
so a concurrent real attacker's commands can never be attributed to a run.

**Run-to-run comparison** with separate honeypot and evaluation-configuration
fingerprints, so a developer can tell whether a delta is the honeypot improving or merely
the test harness moving. The two are surfaced asymmetrically, because a changed honeypot
is the point of the exercise and a changed configuration is what invalidates the
comparison.

**Finding lifecycle across runs**, which answers the question a score delta cannot: *the
missing `/etc/os-release` you reported last week — is it fixed?* Every finding carries a
structured key derived from what it is about (`probe:os_release:os.identity`,
`chain:dropper:T1105`, `sanity:host.name:hostname_cmd+hostname_file`) rather than a hash
of its text, because the evaluator's prose varies run to run while describing an unchanged
flaw. A comparison then reports each defect as `new`, `persisting`, `fixed`, `regressed`
or `undetermined`.

That fifth status is what makes the other four trustworthy. A finding is absent from a run
for two unrelated reasons — the fact came back `observed`, or the fact was never
established — and reporting the second as `fixed` would manufacture good news out of an
infrastructure failure. So resolution joins the underlying fact status rather than
differencing finding keys, and `regressed` reads history only from runs that both
completed and actually established the fact. The evaluator has the same hazard by a
different route: run one evaluation with a BYOK key and the next without, and without the
rule every evaluator finding would report `fixed` — six characteristics of fabricated
progress produced by an absent API key.

A negative fact is a finding now, which is what gives the lifecycle anything to track. A
probe that came back `not_observed`, an expected service the scan did not find, a chain
step whose technique never appeared: each was already collected, scored and
evidence-backed, and was simply never expressed as a finding. On the normal no-BYOK
configuration a run against a self-consistent honeypot used to produce zero.

**Per-honeypot evaluation targets.** `EVALUATION_TARGETS` maps honeypot ids to addresses,
so more than one decoy can be evaluated from one backend — the prerequisite for comparing
a degraded honeypot against a stock one. Empty by default, and while empty the single
target serves every id. Once it holds anything an unmapped id is refused rather than
defaulted: evaluating one honeypot under another's label would file every score, finding
and fingerprint against the wrong decoy. Containment is unchanged — the map is
server-side settings, and a caller still names an id, never an address.

**Targets that are not Cowrie.** An entry may declare `"kind": "generic"` — a real Linux
VM, a bare host, another team's decoy — which is what makes the discrimination experiment
possible at all. Three things only work against this Cowrie image and are skipped for a
generic target: the container reset, the `cowrie.cfg` digest in the honeypot fingerprint,
and chain verification, which reads commands back out of Cowrie's own log. What the
generic target gets instead is an honest absence: its fingerprint covers where it is and
not what it contains, and `attack_possibilities` is left unestablished rather than
scored from chains that never ran.

That last one is also a safety boundary. Cowrie emulates every command, which is the only
reason the attack chains are safe to execute: `rm -rf /root/.ssh` and
`bash malicious_script.sh` touch nothing there and do exactly what they say on a real
host. Chains declare `destructive` in `chains.yaml`, and a destructive chain is refused
against a target that does not simulate commands. Containment kept a *caller* from
choosing an address; this keeps the system from attacking a machine an operator
configured.

**Authentication, and roles scoped to a honeypot.** Unset, the API is open — which is
what it always was, and defensible only bound to localhost. It is never quiet about it:
a warning on every start and a row on the status dashboard reading *"OPEN — every route
answers any caller"*. Configured, every route and both WebSocket channels require a
verified Clerk session token, checked locally against the published JWKS so a request
costs a signature check and nothing on the network.

Roles are per honeypot and gate three actions: running an analysis, generating a report,
and starting an evaluation — the last of which resets a container and executes attack
chains. An explicit per-honeypot role beats the global one *including when it is lower*,
because a map that could only ever widen access would not be an access-control list. A
token carrying no role reads as `viewer`, not as a rejection: the role is a Clerk claim,
so anything that stopped it propagating would otherwise lock out every account at once,
and read-only cannot grant anything.

**An audit trail that distinguishes three kinds of silence.** Every evaluation run and
every analysis records who started it, as `user:<id>`, `unauthenticated` (no identity
existed to record) or `unrecorded` (predates the trail). The three stay distinct because
"nobody was authenticated" and "we never asked" are different claims, and a single null
would let a gap in the history read as an anonymous action — the same reasoning that
keeps `undetermined` out of `fixed`.

**Bounded growth, nothing deleted.** Captured telemetry rolls over at 5 GB or 30 days
and the lifecycle policy has no delete phase, deliberately: this is the research output,
and a delete phase runs on a timer against data nobody is watching. Old indices become
individually droppable by hand instead.

**A provenance-tagged dashboard** — nineteen HTTP endpoints, two WebSocket progress
channels, fourteen routes, every AI conclusion expandable into its source event.

---

## 5. Worth knowing

### Scope: two problem statements, both implemented

This project sits on two candidate problem statements sharing the same research papers.
The first is honeypot log analysis and threat intelligence. The second — Beekeeper's own
contribution, where an agent attacks your honeypot and *judges its realism* to give the
developer feedback — was originally deferred on a measured hardware constraint, and has
since been built as Phase 2.

The constraint was real and shaped the design rather than being worked around. The
Beekeeper paper evaluated Llama3:70b, Mistral Large 2 (123b), Gemini 1.5 Pro and GPT-4o
for the evaluator role and found models under 70b return "only superficial results".
Measured on this hardware, an 8 GB card holds an 8b model at 8192 context; 32768 spills
to a 34%/66% CPU/GPU split.

So the roles are **tiered rather than compromised**. The querying agent needs no model at
all — it is Paramiko plus a fixed probe list — and neither do the static modules or the
attack chains, which reuse the rulebook the analysis half already built. Only the realism
evaluator needs scale, and it is bring-your-own-key. When no key is configured the run
completes and reports the evaluator as *unavailable*; it never substitutes the local
model. Shipping a shallow-but-plausible realism verdict would contradict the project's
own premise, so the system reports the gap instead of filling it.

### What the failures looked like

Thirty-four build stages across the two phases produced a consistent and slightly
uncomfortable pattern: **almost every substantive defect was silent.** Not one crashed.
All passed their tests.

A health probe reported "disconnected" regardless of cluster state, because a dependency
was missing an async extra. Filebeat's own metadata destroyed the attacker's command text
before it reached the pipeline. A time-range filter returned all 96 documents instead of
filtering, because a framework did not honour a field alias in query binding. A risk level
of "medium" was hardcoded onto attackers nothing had assessed. A timezone-naive datetime
shifted stored evidence timestamps by five and a half hours. An indicator was marked
`CORRELATED` after re-analysing a *single* session. Hash extraction was structurally
impossible — the field was discarded before extraction ran — behind a test named
`test_extraction_finds_urls_hashes_and_ips` that never asserted a hash.

That last one is the sharpest lesson in the project: **a test named for a behaviour it does
not assert is worse than no test**, because it manufactures confidence. Several of these
were found only by adversarial probing — feeding inputs the original author had not
imagined — rather than by the test suite.

A later review pass found the same pattern again, twice over, and both instances are
worth recording because they generalise.

**A dashboard test asserted `uname -a` appeared in the top commands.** It passed for
months. The corpus contains that command exactly once, as it does all 25 of its
commands, and the aggregation takes the top ten with ties broken alphabetically — so it
could *never* have passed on corpus data. It passed because live honeypot traffic shared
the index and the evaluation agent's own probes run `uname -a` thousands of times. The
test was measuring the agent. The same review found the seed corpus had been pinned to a
fixed calendar date and had silently aged out of every dashboard window, which the three
sibling tests had been hiding for the same reason.

**A dependency broke both WebSocket channels and no test noticed.** The auth dependency
attached to the router declared `Request`, which FastAPI cannot satisfy on a WebSocket
scope, so it was called with no arguments and the handshake died — with authentication
on *or* off. Eighteen unit tests of the checker passed throughout, because they called
it directly. Only driving the route through the ASGI stack showed it.

The generalisation: **a test that exercises a component in isolation says nothing about
whether its caller uses it.** Several mutation checks in that pass initially "passed"
against deliberately broken code for exactly this reason, and the fix each time was to
drive the real path rather than the seam.

Phase 2 repeated the pattern with a twist: the silent defects were increasingly *in the
plan*, not in its execution. The Cowrie container is distroless, so a step that shelled out
to `rm` — and, in a later task, to `cat` — failed with exit 127. Because both call sites
discarded the return code, the reset became a permanent no-op and the honeypot fingerprint
collapsed to a constant, meaning two entirely different honeypots would have fingerprinted
identically and been declared comparable. Neither failed a test; both were caught by running
the command against the real container before writing any code.

Three more worth recording, because each inverted a rule the system exists to enforce:

- A path-traversal `..` passed the reset boundary guard, because `PurePosixPath` normalises
  `.`, trailing slashes and interior `//` but **not** `..` — so the guard looked complete
  while permitting a value that deletes the honeypot's SSH host keys.
- An orchestration-frame exception discarded a run's scores and reported the run `failed`
  while persisting, in the same transaction, probe rows containing `observed` facts. Our
  failure, relabelled as the honeypot's.
- A progress WebSocket never noticed a client disconnect, leaking a subscriber per viewed
  run and — because the handler task never completed — making the backend impossible to shut
  down gracefully once anyone had opened one.

The recurring shape: **a failure that reports success is worse than a crash.** Every one of
these was found by adversarial probing or by running the thing against reality, not by the
suite, and each fix is now pinned by a test that fails on the old behaviour.

### Known limitations

- **Single-worker deployment.** The job queue and WebSocket fan-out are in-process; running
  multiple uvicorn workers would require Redis pub/sub.
- **Read paths are not access-scoped.** Roles are per honeypot and gate *writing*:
  who may run an analysis, generate a report or start an evaluation. Any signed-in
  account reads everything. It is an authorisation boundary, not a confidentiality one,
  and threat intelligence correlates IOCs across honeypots by design — scoping that
  would break the feature rather than secure it.
- **Similarity normalises only the literals that vary between runs of one campaign** — IPv4
  addresses and file hashes become placeholders, so two runs of a dropper pointed at different
  C2 hosts match. Arguments are deliberately not stripped further: `cat /etc/passwd` and
  `cat /tmp/notes` map to different techniques, and `chmod 777` is not `chmod 644`. Attacks that
  differ by some other volatile literal still score lower than they should.
- **Attacker profile queries are O(sessions) per request** — fine at this corpus size,
  needing an aggregation if live traffic grows into the thousands.
- **Prompt-injection fencing is a mitigation, not a guarantee.** Honeypot commands are
  attacker-authored, and an attacker who suspects analysis can write instructions into a
  command line. Attacker text is fenced and labelled as data, but the schema gates and the
  evidence barrier are what actually make that survivable — they are load-bearing, not
  decorative.
**Analysis half — resolved since the previous revision.** The full live loop *is* now
verified end to end in one continuous pass: a real SSH session against the honeypot
produced sixteen events reaching Elasticsearch in under three seconds, and the resulting
analysis completed in forty-one seconds with all seven stages streaming to the interface
over a WebSocket. That pass also exposed two live-only defects invisible to the seeded
corpus — unknown Cowrie event types rendering as attacker commands, and a fabricated
port `0` where the honeypot had recorded none — both since fixed.

**Evaluation half.**

- **The packet capture runs in a long-lived sidecar** declared in docker-compose with
  `network_mode: service:cowrie`, because a capture anywhere else does not see a
  containerised honeypot's traffic. Measured on this machine: a WSL distro saw 0 packets
  for the same SSH session the container's namespace counted 30. A capture that cannot
  see the traffic would report `not_observed` — a confident "no traffic occurred" — so
  where it cannot run, reporting nothing at all is the only honest answer.

  The sidecar is also why the backend never calls `docker run`. Creating a container is
  the one Docker operation unconditionally equivalent to root on the host, and the
  capture was the only thing that needed one; every remaining docker call passes an
  allowlist of `exec`, `inspect` and `kill`.
- **The scoring and compaction *algorithms* are not fingerprinted.** `scoring.py` holds
  no constants to hash — it is pure functions — so two runs spanning a change to how a
  fraction is computed fingerprint identically, and git revision is the extra key when
  reading a trend. Narrower than it used to be: the result-deciding constants in
  `rules.py`, `static/nmap.py` and `agent.py` are now hashed by value, so editing the
  per-command timeout or the expected service list does move the fingerprint. Regex
  compile flags still do not.
- **`EvaluationRun` has no `detail` column**, so a null `evaluator_rating` cannot say
  *why*: no key configured, no evidence gathered, a provider error and a rejected verdict
  all collapse to one blank. The reason is logged but not queryable.
- **The target and the measurement apparatus ARE fingerprinted now**, and each sits in
  the fingerprint that means it. The target — host, port, SSH user, container — is part of
  `honeypot_fingerprint`, because it names the thing under test. The capture interface,
  capture sidecar and module timeouts are part of `evaluation_config_fingerprint`, because
  they change what a run can *find* without changing the honeypot. The SSH password is in
  neither: it does not change what the honeypot is, and fingerprints are stored and
  displayed.
- **One paid API call per characteristic**, by design — the paper found merged prompts
  markedly shallower — with no retry or backoff, so a rate limit ends that characteristic's
  evaluation permanently rather than deferring it.
- **A stale `RUNNING` row is cleared at startup, not while a process is live.** Within a
  single process the reconciliation is age-based (45 minutes) precisely so it can never
  terminate a genuinely running evaluation in another worker.
