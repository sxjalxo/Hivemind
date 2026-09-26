# Hivemind — Project Overview

*Companion to [`README.md`](README.md), which is the short introduction, the screenshots
and the installation steps.*

This file explains **why** the system is built the way it is, and — from section 6 — is
the technical reference for someone already working on the code. Start with the README
if you want to run it rather than reason about it.

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

Setup is in [`README.md`](README.md).

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

**Remediation — the loop's last arrow.** A finding says what is wrong; until now nothing
said what to do about it, and the `recommendation` column wrote `None` for every
deterministic finding. `GET /api/evaluations/{run_id}/remediation` now returns, for each
finding, a concrete patch: files to place in the honeypot's honeyfs overlay, or cowrie.cfg
options to set. It is a read — computing a patch touches nothing, and applying one stays
the operator's deliberate act.

It is a lookup table, not a model call. The finding key already encodes what a finding is
*about*, and the set of things a Cowrie decoy can be wrong about in a way a probe detects
is small and enumerable, so a table is exact where a model would be plausible. Where the
run's own evidence determines the fix it is derived from it — the hostname written into
`/etc/hostname` is the one the honeypot's `hostname` command actually printed, and a
generated `/etc/os-release` describes the distribution the honeypot's own `uname -a`
reports, read through the same extract contradiction detection uses, so a fix cannot close
one finding by opening another. Where it cannot be derived — nobody can recover the
accounts an emptied `/etc/passwd` should hold from the fact that it is empty — the body is
a template and is flagged as one.

**What it refuses to do is the part that matters.** A finding with no mechanical fix gets
a reason and no patch at all: no half-fix, no plausible-looking cowrie.cfg stanza. Chain
findings, evaluator prose and `service.http` are all refused, the last because nmap expects
an HTTP service and Cowrie has no HTTP listener to enable — which is why it is reported by
every arm of the degradation matrix including the best one, and is a finding about the
question rather than the answer. Every finding gets an entry, refusals included, so a
caller who applies the whole response cannot believe they addressed the whole run.

Two Cowrie constraints are baked into the generated paths and neither is guessable: the
fix for `/etc/os-release` writes `usr/lib/os-release`, because the former is a symlink and
Cowrie attaches honeyfs content only to real files — a patch to the link applies cleanly
and does nothing — and an overlay can replace content but never remove a node.

Measured end to end: the remediation generated from the stock honeypot's own findings is
byte-identical to the hand-built `hardened` arm of the matrix, which is independently
measured at sanity 0.667 → 1.000 with contradictions 1 → 0.

**In the interface**, a fix is rendered directly beneath the finding it repairs, on the
run detail page — a patch read away from the defect it fixes is a patch applied without
reading the defect. Each one carries the file path it belongs at, its contents with a copy
button, and a badge saying whether the content was *derived* from this run's own evidence
or is a *template* to review first. Refusals are rendered with the same weight rather than
filtered out, for the same reason the API returns them: a reader who applied everything on
screen must not be able to believe they had addressed the whole run. Nothing is shown at
all until the fixes have actually loaded, because "we have not asked yet" and "there is no
fix" are different claims, and if the request fails the page says so instead of leaving a
silence that reads as the second.

**A degradation matrix, which is how the evaluation is shown to discriminate.** The
claim that matters about a realism evaluation is that it separates a better honeypot from
a worse one. Proving that needs decoys of known, differing quality, and the obvious way to
get them — a second machine, a VPS, a lab — costs money and produces a *worse* experiment:
two dissimilar hosts differ in dozens of uncontrolled ways, so a delta between them is not
attributable to any one of them.

The `matrix` compose profile instead runs several containers from the same pinned image,
each differing from the stock decoy in exactly one declared respect, so a delta has one
candidate cause. Degradation is applied through Cowrie's `contents_path` overlay, so every
arm's defect is a file in `infra/cowrie/matrix/` visible in a diff — no rebuilt image, no
container mutated by hand. Four arms ship: `hardened`, stock, `degraded-sanity` and
`degraded-fs`. `docker compose --profile matrix up -d` starts them and a plain
`docker compose up -d` is unchanged, so the default stack and the test suite never see
them.

`scripts/run_degradation_matrix.py` evaluates every arm and prints the comparison. The
measured result on this machine:

```
arm                      basic_c file_sy service attack_  sanity context   contradictions
matrix-hardened            1.000   1.000   0.667   1.000   1.000   1.000        0
cowrie-01  (stock)         1.000   1.000   0.667   1.000   0.667   1.000        1
matrix-degraded-sanity     1.000   1.000   0.667   1.000   1.000   1.000        2
matrix-degraded-fs         1.000   0.333   0.667   1.000   0.667   1.000        1
```

Read the `degraded-sanity` row against the `hardened` row: **identical scores, twice the
contradictions.** That arm answers every probe, so every fact is observed and its sanity
score is a perfect 3/3 — and it says it is Ubuntu while its kernel says Debian, and gives
two different hostnames. An evaluation reporting scores alone would call it as good as the
hardened decoy. The two axes are separate measurements of separate questions — *did it
answer* and *do its answers agree* — and the matrix exists partly to keep anyone from
quietly averaging them into one number.

All four arms share one `evaluation_config_fingerprint` and carry four different
`honeypot_fingerprint`s, which is the precondition that makes the comparison mean
anything: the same question, asked of four different things.

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

**A provenance-tagged dashboard** — twenty-two HTTP endpoints, two WebSocket progress
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
- **Contradiction detection compares claims, not raw output — and only where a probe
  says how to read its claim.** Two probes can establish one fact in two formats:
  `uname -a` prints a kernel string and `cat /etc/os-release` prints key=value lines, and
  those can never be equal even when both correctly describe the same Debian. Compared
  raw, a *correct* honeypot was reported as contradicting itself, so an operator who
  populated an empty `/etc/os-release` — a real defect, and the very one the docs use as
  an example — was handed a fresh false defect for fixing it. Probes now declare an
  optional `extract` regex and are compared on the captured value; `load_probes` refuses a
  probe set where two probes for one fact disagree about declaring one, because comparing
  an extracted token against a raw dump would reintroduce the bug silently. A probe whose
  extract does not match is dropped from the comparison rather than treated as agreeing —
  a claim nobody could read is not evidence of agreement. The remaining limitation is that
  the distribution list in the pattern is finite: a honeypot claiming a distribution not
  named there has its `os.identity` cross-check silently skipped rather than failed.
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

- **`evaluation_target_host` defaults to the compose service name** `cowrie`, which does
  not resolve from a backend running on the host. Set `EVALUATION_TARGET_HOST=127.0.0.1`
  for a host-run backend. A run refuses to start when nothing accepts a connection there,
  naming the setting — rather than spending the full agent budget producing a run in
  which every fact is `unknown`.
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
- **The scoring and compaction *algorithms* are fingerprinted now, by structure.**
  `scoring.py` holds no constants to hash — it is pure functions — so hashing values was
  never going to reach it, and two runs spanning a change to how a fraction is computed
  used to fingerprint identically with git revision as the only thing separating them: a
  side channel that is not stored with the run and is gone by the time anyone reads a
  comparison out of the database. `scoring.py`, `compaction.py` and `rules.py` are now
  hashed as parsed syntax trees with docstrings stripped. Hashing the `.py` bytes was
  rejected and stays rejected — a digest that moves on a comment trains people to ignore
  it — but comments and formatting never enter a Python AST, while an operator, a branch
  or a boundary does. A pure rename does move it, which is the cheap direction of wrong:
  one lost comparison, rather than two incomparable runs silently sharing a trend line.
  The result-deciding constants in `rules.py`, `static/nmap.py` and `agent.py` are hashed
  by value as before. Regex compile flags still are not, and `nmap.py` and `agent.py` are
  still covered by their constants rather than by their structure — deliberately, because
  those two produce evidence and degrade to `unknown` when they fail, where the other
  three silently produce a different number.

  **Upgrading past this invalidates every stored `evaluation_config_fingerprint`.** Runs
  recorded before it cannot be compared against runs recorded after, which is the correct
  answer — the question genuinely changed — but it is a one-time break in every existing
  trend line, not a silent one.
- **A blank `evaluator_rating` now says why, per characteristic.**
  `evaluation_category_scores` carries `evaluator_status` and `evaluator_detail`, so "no
  BYOK key", "no evidence gathered", "a provider error" and "a verdict whose citations did
  not resolve" are four distinguishable states rather than one blank. This closes a
  lifecycle bug: a mixed run — one characteristic assessed, another never assessed — used
  to aggregate to `completed`, so the unassessed characteristic resolved `absent` and,
  against an earlier run that had reported it, came out `fixed` — a finding nobody
  re-established, reported repaired. `state()` now keeps three cases apart: a
  characteristic with its own recorded status resolves directly from it; a characteristic
  with no row at all in an otherwise-populated run resolves `undetermined` without
  consulting the run-level aggregate, for the same reason; and a genuinely historic or
  `unrecorded` row — a gap in the record, never a claim — falls back to the old run-level
  rule, since no better information was ever written for it. The run's own
  `evaluator_status` remains a worst-case aggregate and is a header summary only.
- **The target and the measurement apparatus ARE fingerprinted now**, and each sits in
  the fingerprint that means it. The target — host, port, SSH user, container, and the
  honeypot's own capture sidecar — is part of `honeypot_fingerprint`, because it names the
  thing under test. The capture interface and module timeouts are part of
  `evaluation_config_fingerprint`, because they change what a run can *find* without
  changing the honeypot.

  The capture sidecar moved out of the apparatus and into the target when the degradation
  matrix was built, and the reason is worth keeping. A sidecar is declared
  `network_mode: service:<honeypot>`, so it is pinned to one honeypot's network namespace
  and is one-to-one with its container: there is no configuration in which honeypot A's
  traffic can be captured from honeypot B's sidecar. Naming it does not describe *how* a
  run measured, it describes *whose* traffic it measured. Filed as apparatus, it made a
  fleet incomparable with itself — every honeypot necessarily has its own sidecar, so
  every cross-honeypot comparison differed on the configuration fingerprint and
  `compare_runs` reported each delta as **not attributable to the honeypot**, which is the
  exact opposite of the truth on the comparison the matrix exists to make. The preferred
  direction of error is unchanged: the value still moves a fingerprint whenever it
  changes, now the one meaning "a different thing was under test". The SSH password is in
  neither: it does not change what the honeypot is, and fingerprints are stored and
  displayed.
- **One paid API call per characteristic**, by design — the paper found merged prompts
  markedly shallower — now with a bounded retry behind it. A 429, a 5xx or a transport
  failure is retried twice, waiting 1s then 4s, honouring `Retry-After` up to 30 seconds.
  Every other 4xx is not: a wrong or expired key is settled, and re-asking spends the same
  call to receive the same answer while delaying the `evaluator_failed` the operator needs
  to see. A schema rejection is not retried either — the model answered, it answered in
  the wrong shape, and re-asking that is a decision about paid calls rather than a
  transport concern. Without this a single rate limit ended a characteristic's evaluation
  permanently and filed the result as an evaluator failure, which put a gap in the record
  that the provider caused and the honeypot got blamed for. Retries are logged at warning
  level, because a key that is rate-limited on every run must not hide behind a run that
  merely looks slow.
- **A stale `RUNNING` row is cleared at startup, not while a process is live.** Within a
  single process the reconciliation is age-based (45 minutes) precisely so it can never
  terminate a genuinely running evaluation in another worker.

---

## 6. Technical reference

*Section 4 says what these features are for; this is the operational detail — the
commands, the tables and the settings.*

### The loop

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

### Layout

```
backend/     FastAPI service — ingest, analysis pipeline, evaluation subsystem
             22 HTTP endpoints + 2 WebSocket progress channels
frontend/    React + TanStack Router dashboard
infra/       Elasticsearch index template, ingest pipeline and lifecycle policy,
             Filebeat and Cowrie config
             cowrie/matrix/  one directory per degradation-matrix arm
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
whoever is building the system. This file and `README.md` are the tracked documentation.

### Tests

```bash
cd backend && .venv/Scripts/python -m pytest
```

They run against the live Docker stack and the real local model, so bring the
infrastructure up first. **A clean run is `653 passed, 1 skipped`** — there are no
expected failures.

The skip is the one end-to-end test that depends on whether `llama3.1:8b` infers a
technique on that pass, and on whether its citation survives the evidence barrier. Neither
is a defect in the code, so it skips with a reason rather than failing. The boundary it
protects — an LLM-sourced mapping is never marked `observed` — is pinned separately by a
deterministic test that needs no model at all.

```bash
cd frontend && npx tsc --noEmit && npm run lint && npm run build
```

### How provenance works

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

### Running a realism evaluation

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

#### Comparing two runs

Every run stores two fingerprints: one for the honeypot under test, one for the
evaluation configuration. The comparison view uses them asymmetrically, because they mean
opposite things:

- a changed **honeypot** fingerprint is the *point* of the comparison — that change is the
  improvement being measured;
- a changed **evaluation configuration** fingerprint is what breaks attribution, because
  our own probes, chains, rulebook or budget moved underneath the result.

The comparison is never refused; it says plainly whether a delta is attributable. It also
reports **what happened to each individual defect** — `new`, `persisting`, `fixed`,
`regressed`, or `undetermined`.

#### The cloud evaluator (optional)

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

### Model sizing

Two model roles, following the source paper's split:

| Role | Model | Notes |
|---|---|---|
| Analysis | `llama3.1:8b` locally via Ollama | temperature 0.3, `num_ctx` 8192 |
| Realism evaluator (optional) | BYOK cloud model | one context per characteristic |

`num_ctx` is 8192 rather than the paper's 32768 — see section 5 for the measurement
behind that. Long sessions are chunked and merged instead of being truncated.

Each pipeline stage gets its own isolated context — seven for analysis, one per
characteristic for evaluation — because merging them into a single prompt was measured to
produce markedly shallower output.

The probe agent uses **no model at all**. It is Paramiko plus a fixed probe list, which is
why a run records `agent_model` as `deterministic-probes@<version>` rather than a model
name: naming one would invite a reader to attribute a run-to-run difference to a model
change that never happened.

### Authentication

**Unset, the API is open.** Every route and both WebSocket channels answer any caller that
can reach the port. That is defensible only while it is bound to `127.0.0.1`, and it is
never silent: the backend logs a warning naming the setting on every start, and
`GET /api/status` carries an `authentication` row reading `OPEN — every route answers any
caller`.

Set `CLERK_ISSUER` and every `/api` route requires a valid Clerk session token:

```bash
# backend/.env
CLERK_ISSUER=https://your-instance.clerk.accounts.dev
CLERK_AUTHORIZED_PARTIES=["http://localhost:8080"]
```

The frontend is wired by `clerk init` and needs nothing further — it attaches the token to
every request, and to both WebSockets as a subprotocol, because a browser cannot set an
`Authorization` header on a handshake and a session token must not travel in a query
string where access logs would keep it.

Tokens are verified locally against Clerk's published JWKS, so a request costs a signature
check and nothing on the network. Four things are checked and each one matters:

| Check | Without it |
|---|---|
| signature (RS256, against the instance's JWKS) | anyone can mint a token |
| `iss` | a valid token from someone else's Clerk instance is accepted |
| `azp` vs `CLERK_AUTHORIZED_PARTIES` | a token for a *different app on your own instance* is accepted |
| `exp`/`nbf`, with leeway | either replay forever, or reject everything when the host clock drifts |

`aud` is deliberately not checked — Clerk does not set it on session tokens, so verifying
it would reject every real token.

#### Roles

Two roles, and they are **per honeypot**. The session token carries a global `role` (from
`public_metadata.role`) and an optional per-honeypot map (`public_metadata.roles`):

```bash
clerk api /users/<id> -X PATCH -d '{"public_metadata":{
  "role": "viewer",
  "roles": {"cowrie-01": "admin", "vm-baseline": "viewer"}
}}'
```

Resolution is most-specific-first: an explicit entry wins, otherwise the global role,
otherwise `viewer`. **An explicit entry wins even when it is lower** — naming a honeypot
`viewer` while holding a global `admin` has to mean something, or the map could only ever
widen access and would not be an access-control list.

| | |
|---|---|
| `admin` | everything |
| `viewer` | read-only: every `GET`, and both progress WebSockets |

Three operations require `admin`, and they are the ones that cost something or touch a
honeypot: `POST /api/analyze/{id}` (one LLM pipeline on the one GPU), `POST /api/reports`
(which runs an analysis when the session has none), and `POST /api/evaluations` — which
**resets the honeypot's container and executes attack chains against it**.

**A token with no role, or an unrecognised one, is a viewer — not a rejection.** Failing
closed entirely is the reflex and it is wrong here: the role is a Clerk claim, so anything
that stops it propagating would lock out every account at once, yours included, with the
recovery being to turn authentication off. Degrading to read-only cannot *grant* anything,
because every admin route demands the role explicitly.

The UI hides the controls a viewer cannot use, but that is courtesy, not the boundary —
the backend answers 403 regardless of what was rendered.

Assign a role:

```bash
clerk users list --json | jq '.data[] | {id, email_addresses, public_metadata}'
clerk api /users/<user_id> -X PATCH -d '{"public_metadata":{"role":"admin"}}'
```

Each mutating route is gated twice: a coarse dependency refuses anyone who is admin on
*nothing*, then the handler checks the specific honeypot. The coarse half matters because
`/api/analyze/{id}` and `/api/reports` only learn their honeypot by resolving the session —
without it, a viewer probing session ids would get 404 for one that does not exist and 403
for one that does, which is an existence oracle.

*(On Git Bash, prefix with `MSYS_NO_PATHCONV=1` or the leading `/users` is rewritten into a
Windows path.)*

**Sign-up is restricted**, so an account cannot be created without an invitation —
`auth_access_control.sign_up_mode` is `restricted` on the instance. Invite from the Clerk
dashboard, then set the new user's role; until you do, they can read and nothing else.

#### Who ran what

`started_by` is NOT NULL and prefixed, so three situations stay three values instead of
collapsing into one null:

| | |
|---|---|
| `user:<clerk_id>` | an authenticated caller; `started_by_label` holds the email the token asserted at the time |
| `unauthenticated` | `CLERK_ISSUER` was unset, so no identity existed to record |
| `unrecorded` | the run predates the audit trail (backfilled by migration `c7d3e1a95b42`) |

The actor is derived from the verified token, never from the request:
`StartEvaluationRequest` forbids extra fields, so a caller cannot name itself. Session
analyses carry the same audit columns (`analyses.started_by`, migration `d2f8b4c61e07`),
and a report credits the analysis it triggers to whoever asked for the report.

**What this still does not do.** Read paths are not scoped. Roles are per honeypot but not
per session or per report. And the roles map is edited by hand through the Clerk API —
there is no UI for granting access.

### Docker privilege

The backend talks to the Docker daemon, and that access has no gradations of its own:
whoever can reach it can create a container, and `docker run -v /:/host --privileged` is
root on the host with no exploit required. No socket proxy, seccomp profile or API policy
makes that call safe. It can only be not made.

So the application does not make it. Three verbs are permitted, enforced by an allowlist
every docker invocation passes through (`app/services/evaluation/container.py`):

| | |
|---|---|
| `inspect` | read-only metadata |
| `exec` | root *inside* a container that mounts nothing from the host but a read-only config file |
| `kill` | signals a container this deployment declared |

`run` and `create` are absent, and their absence is the point. Which namespace a capture
sees is therefore a property of the compose file rather than of an argument the backend
assembles — which is also where a run against one honeypot could previously attach to
another's.

**What this does and does not buy.** It does not stop an attacker who already has code
execution in the backend: they would call the docker CLI directly, and the daemon would
oblige. What it does is make the set of Docker operations this application performs small,
enumerable and enforced, so the blast radius of a *bug* — a careless new caller, a path
built from the wrong variable — is a container rather than the host. Tests hold the line,
including one that fails if any module builds a docker argv and spawns it itself.

**The residual risk is the daemon socket, and it is not removed.** If that matters for
your deployment, the options in order of effort are: run the backend as a user outside the
`docker` group and give the evaluation subsystem its own privileged helper; or put a
socket proxy in front of the daemon exposing only `GET /containers/*/json` and the exec
endpoints — now feasible precisely because nothing here needs container creation any more.
Neither is configured here, and neither is worth doing while the backend and the honeypot
share a laptop.

### Retention and index lifecycle

`honeypot-events` is a **rollover alias**, not a single index. An index lifecycle policy
rolls it over at 5 GB per primary shard or 30 days, whichever comes first.

**Nothing is ever deleted** (section 4). What rollover buys instead is that old indices
become individually droppable *by hand*, once you have decided you don't need them:

```bash
curl -s "http://localhost:9200/_cat/indices/honeypot-events*?v&h=index,docs.count,store.size"
curl -s -X DELETE "http://localhost:9200/honeypot-events-000001"   # only when you mean it
```

Disk still fills eventually — slowly, and visibly in that first command.

**Existing deployments are not converted automatically.** A backend that finds a concrete
index where the alias should be logs a warning and carries on unchanged; converting means
reindexing and deleting the original, which is not something to do unattended to
telemetry. Do it deliberately, with the backend stopped:

```bash
cd backend && .venv/Scripts/python -m scripts.migrate_to_rollover          # dry run
cd backend && .venv/Scripts/python -m scripts.migrate_to_rollover --apply
```

It verifies document counts before it removes anything, and refuses to delete the source
if the copy is short.

Two couplings had to be fixed before rollover was safe, and both are load-bearing if you
touch this area:

- **`es.update(index, id)` only ever reaches the write index.** Through an alias, every
  document older than the current write index answers `document_missing_exception` — which
  the caller caught and logged as a warning, so the dashboard's technique filter would have
  silently stopped covering anything but the newest index. Enrichment uses one
  `update_by_query` instead, which resolves the alias across all of its indices.
- **Document ids are unique per index, not per alias.** The seed corpus uses fixed ids and
  relied on overwrite for idempotency; after a rollover that writes a *second* copy into
  the new index while the original survives in the old one. `seed()` now always deletes by
  query before indexing.

Postgres has no retention policy at all. Growth there is one row per analysis and per
evaluation run, which is slow enough to ignore for now.

### Security

Cowrie is deliberately attackable software. Its ports bind to `127.0.0.1` only and it must
not be exposed to the internet in this configuration.

Attacker-controlled text is treated as untrusted throughout: it is never interpolated into
a shell, and inside LLM prompts it is fenced and labelled as data, with line breaks and
delimiter runs neutralised so captured output cannot close the fence and address the model
directly. Captured malware is referenced by hash only and never executed. Elasticsearch,
Postgres and model credentials stay server-side — the browser knows one API base URL.

The evaluation API is **containment-bounded by construction**: `POST /api/evaluations`
accepts a honeypot id from the registry and nothing else. There is no host, port or
command field, and an unexpected field is rejected rather than ignored, so there is no path
from an HTTP request to an arbitrary target. The reset boundary is enforced in code — a
guard rejects any path that reaches the honeypot's identity keys or its logs, and rejects
path traversal outright — rather than documented in a comment.

### Per-honeypot evaluation targets

`EVALUATION_TARGETS` maps honeypot ids to targets (JSON, snake_case keys):

```json
{"cowrie-degraded": {"host": "127.0.0.1", "ssh_port": 2322, "container_name": "hivemind-degraded-1"}}
```

Leave it empty and the single `EVALUATION_*` target serves every honeypot, which is what a
one-decoy deployment wants. Once it holds anything, an unmapped id is refused rather than
quietly sent to the default.

**A target that is not Cowrie must say so**, with `"kind": "generic"`. Three things only
work against this Cowrie image: the container reset, the `cowrie.cfg` digest in
`honeypot_fingerprint`, and chain verification, which reads commands back out of Cowrie's
own log. A `generic` target skips all three. It is also the flag that keeps the attack
chains off a real machine — every step is emulated on Cowrie and real anywhere else, so a
chain marked `destructive` in `chains.yaml` is refused against a target that does not
simulate commands. All three shipped chains are destructive, so a generic target scores no
`attack_possibilities` at all: it is reported unestablished, never as a zero.

`kind` defaults to `cowrie`, but every field that makes a target dangerous defaults the
safe way — a target with no `container_name` is rejected rather than guessed at, and the
internal `EvaluationTarget` defaults to `generic`.

### Running the degradation matrix

```bash
docker compose --profile matrix up -d
cd backend && .venv/Scripts/python scripts/run_degradation_matrix.py
```

`EVALUATION_TARGETS` must map all four arms first; `backend/.env.example` has the entry
ready to paste. **It must include `cowrie-01` too** — the moment that map holds anything,
an unmapped id is refused, so leaving the stock decoy out does not fall back to the single
default, it makes the honeypot you already have un-evaluable.

Each arm runs a full evaluation — reset, nmap, the agent's budget, the chains and their
read-back, plus one evaluator call per characteristic if a BYOK key is set — so budget a
few minutes per arm. The runs are ordinary evaluation runs, stored as such, so every
number the script prints is also in the UI and any two arms can be opened in the
comparison view afterwards. The script takes the same per-honeypot advisory lock
`POST /api/evaluations` takes, so it cannot interleave with a run started from the UI.

Arms are defined by `infra/cowrie/matrix/<arm>/`: a `cowrie.cfg` declaring
`contents_path: /honeyfs`, and a `honeyfs/` tree whose files overlay the image's pickled
filesystem. Two constraints on that overlay are worth knowing before adding an arm:

- **Overlay the symlink target, never the link.** Cowrie attaches honeyfs content only to
  nodes of type `T_FILE`; a symlink is skipped in silence, with no error and no log line.
  `/etc/os-release` is a symlink to `usr/lib/os-release` in the image exactly as on real
  Debian, so an overlay written at the `/etc` path does nothing at all. That is also *why*
  stock's `/etc/os-release` is empty: the link resolves to a node the image ships with no
  contents behind it.
- **An overlay can only replace content, not remove a node.** Degrading a fact is done
  with an empty file, which makes `cat` exit 0 with no output — recorded as `not_observed`,
  a genuine absence, rather than as `unknown`.

**Restarting an arm orphans its capture sidecar.** `network_mode: service:<arm>` joins the
arm's network namespace at start; restarting the arm destroys that namespace, and the
sidecar stays attached to the old one. It keeps running and `docker exec` still succeeds,
so tcpdump reports from an interface the honeypot's traffic no longer crosses, and the run
records traffic as `unknown`. Honest rather than a false "no traffic" — but it silently
costs a characteristic, and it is what made two arms report `context` as unestablished on
this matrix's first run. After restarting any arm, restart its sidecar too. A plain
`docker compose --profile matrix up -d` orders them correctly by itself.
