# Hivemind — Setup and Demo Guide

**For someone who has never seen this project before.** It assumes no prior knowledge:
Part 1 gets it running on a fresh machine, Part 2 starts it day to day, Part 3 walks the
demo screen by screen with what to say at each one.

Every command and every expected value here was run against the live system. Where
something is fragile or known to fail, it says so rather than leaving you to find out in
front of an audience.

| | |
|---|---|
| First-time setup | 30–45 min, mostly downloads |
| Starting up after that | ~3 min |
| Full demo | 20–25 min |
| Short demo | ~8 min ([Part 6](#part-6--the-eight-minute-version)) |

---

## Part 0 — What this project is

Read this once before demoing; the whole walkthrough depends on it.

**A honeypot is a decoy computer left exposed on a network so attackers will attack it.**
Everything an intruder types is recorded. We run **Cowrie**, a honeypot that pretends to
be a Linux server over SSH — an attacker logs in, gets what looks like a real shell, and
every command is captured.

Two problems follow, and **Hivemind does one thing about each**.

**Problem 1: the recordings are unreadable at scale.** A honeypot produces tens of
thousands of log lines, mostly automated bots running the same scripts. Somebody has to
read them and say "this one is a botnet installing a crypto miner". Doing that by hand
does not scale.

> **Hivemind's first half** reconstructs each attacker session, classifies what happened
> using a local AI model, maps the commands to **MITRE ATT&CK** (the industry-standard
> catalogue of attacker techniques), and extracts indicators like malicious URLs.

**Problem 2: an AI that guesses is worse than no AI at all.** Point a language model at
security logs and it will produce confident, fluent, plausible claims about attacks that
never happened. An analyst then cannot tell a recorded fact from a model's guess.

> **This is the project's core idea.** Every claim on screen carries a pointer back to
> the exact log line that produced it, and you can click it. Anything the model cannot
> ground in real evidence is **rejected, not displayed**. Techniques matched by a
> deterministic rule are labelled `OBSERVED`; anything the AI proposed is labelled
> `AI INFERENCE`. The two never blur together.

**Problem 3: a decoy only works if it's convincing.** If an attacker realises it's a fake
within ten seconds, they leave and you learn nothing. Finding out *why* your honeypot is
unconvincing normally means weeks of waiting, or paying experts to test it by hand.

> **Hivemind's second half** attacks our own honeypot automatically — an SSH agent, a port
> scan, a packet capture and scripted attack chains — and scores how convincing it is
> across six characteristics, so the developer gets feedback in about twenty seconds.

**One sentence for the audience:** *a honeypot is only worth what it can convince an
attacker of, and this shortens the loop that makes it convincing — without ever letting
an AI's guess get mistaken for a fact.*

The project is based on the paper *"Beekeeper: Accelerating Honeypot Analysis With
LLM-Driven Feedback"* (IEEE Access, 2025).

---

## Part 1 — One-time setup

Do this once per machine. If someone else already set the machine up, skip to
[Part 2](#part-2--starting-it-up).

### 1.1 What you need installed

| Tool | Version | Why | Check with |
|---|---|---|---|
| **Docker Desktop** | any current | Runs the honeypot, database and search engine | `docker --version` |
| **Python** | 3.12 or newer | The backend | `python --version` |
| **Node.js** | 20 or newer | The web interface | `node --version` |
| **Ollama** | any current | Runs the AI model locally on your GPU | `ollama --version` |
| **Git** | any | To clone the repo | `git --version` |
| **nmap** | optional | Port-scan probe. Without it that probe reports "unknown" | `nmap --version` |

**Hardware:** a GPU with **8 GB VRAM** is enough. The model is deliberately sized for it.
Without a GPU everything still works but AI analysis takes several times longer.

**Reference machine** (what this guide was verified on): Windows 11, Docker 29.7,
Python 3.12.13, Node 24.13, nmap 7.99.

> **Windows note.** Commands below show Windows paths (`.venv/Scripts/python`). On
> Linux/macOS use `.venv/bin/python` instead. Everything else is identical.

### 1.2 Get the code

```bash
git clone <your-repo-url> Hivemind
cd Hivemind
```

### 1.3 Start the infrastructure

This downloads and starts five containers: the honeypot, Elasticsearch (search engine
holding raw events), Kibana, PostgreSQL (database holding everything derived) and
Filebeat (ships logs from the honeypot into Elasticsearch).

```bash
docker compose up -d
```

First run pulls several GB — give it time. Then check everything came up:

```bash
docker compose ps
```

**Wait until `elasticsearch` and `postgres` both say `healthy`.** The others say `Up`.

Ports, all bound to `127.0.0.1` only so nothing is exposed to your network:

| Port | What |
|---|---|
| 2222 | Honeypot SSH (the decoy attackers connect to) |
| 2223 | Honeypot Telnet |
| 9200 | Elasticsearch |
| 5601 | Kibana |
| 5432 | PostgreSQL |

### 1.4 Pull the AI model

```bash
ollama pull llama3.1:8b
```

Then confirm it runs **on the GPU**:

```bash
ollama ps
```

You want `100% GPU`. If it says CPU, everything still works but analysis is roughly four
times slower — and nothing warns you, so check.

### 1.5 Pull the packet-capture image

The demo's packet capture runs inside the honeypot's own container. Pull it now or the
first evaluation spends a minute downloading it:

```bash
docker pull nicolaka/netshoot
```

### 1.6 Set up the backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -e ".[dev]"      # Linux/macOS: .venv/bin/python
cp .env.example .env                                  # optional; every value has a default
.venv/Scripts/python -m alembic upgrade head          # creates the database tables
```

### 1.7 Set up the frontend

```bash
cd ../frontend
npm install
```

Create a file called `.env` in the `frontend` folder containing exactly this line:

```
VITE_API_BASE_URL=http://localhost:8000
```

> **Why this matters.** Without that line the interface runs on **built-in demo data**
> and never talks to the backend. That mode is genuinely useful (see
> [Part 5](#part-5--demo-mode-no-backend-needed)) but it is not the live system, so if
> you are showing real analysis, make sure this file exists.

Setup is done.

---

## Part 2 — Starting it up

Every time you demo. **You need three terminals.**

### Terminal 1 — infrastructure

```bash
cd Hivemind
docker compose up -d
docker compose ps        # wait for elasticsearch + postgres = healthy
```

Also make sure Ollama is running (it usually starts with your machine):

```bash
ollama ps
```

### Terminal 2 — backend

```bash
cd Hivemind/backend
EVALUATION_TARGET_HOST=127.0.0.1 .venv/Scripts/python -m uvicorn app.main:app --port 8000
```

On Windows PowerShell the environment variable goes on its own line first:

```powershell
$env:EVALUATION_TARGET_HOST = "127.0.0.1"
.venv\Scripts\python -m uvicorn app.main:app --port 8000
```

> **Do not skip `EVALUATION_TARGET_HOST`.** It defaults to `cowrie`, a name that only
> resolves *inside* Docker's network. Running the backend on your own machine, it has to
> be `127.0.0.1` or the realism evaluation cannot reach the honeypot. See
> [Part 7](#part-7--troubleshooting).

Leave it running. First start also installs the Elasticsearch pipeline and loads a small
set of realistic pre-recorded attacks, so every screen has data immediately.

### Terminal 3 — frontend

```bash
cd Hivemind/frontend
npm run dev
```

Open **<http://localhost:8080>**.

### The one check worth not skipping

Click **Settings** in the sidebar, or run:

```bash
curl -s http://localhost:8000/api/status
```

You should see:

```
elasticsearch    connected      cluster status: green
postgres         connected
ollama           connected      llama3.1:8b
evaluator        disconnected   no API key configured
seed-corpus      running        51 seeded events
```

> **`evaluator: disconnected` is correct and expected.** That is an *optional* cloud AI
> model. Without it the system says "unavailable" instead of inventing a score — which is
> itself one of the better things to demonstrate. Do not treat it as broken.

If anything else is not `connected`, go to [Part 7](#part-7--troubleshooting) before
starting the demo.

---

## Part 3 — The demo walkthrough

Ten screens in the left sidebar. Go in this order; it builds.

---

### Screen 1 · Dashboard

**Sidebar → Dashboard**

**What it is:** the fleet-level view — total events captured, sessions, risk breakdown,
an activity timeline, top attackers and top commands.

**What to say:** *"This is everything the honeypot has recorded."*

**Point out:** panels that depend on AI analysis show **zero** until an analysis has run.
They are not broken and they are not placeholders — an unanalysed session genuinely has
no classification, and the system refuses to invent one. You will watch these numbers
move in a moment.

---

### Screen 2 · Honeypots

**Sidebar → Honeypots**

The deployed decoy: `cowrie-01`, pretending to be a Linux workstation called
`med-ws-04`, with its health.

**What to say:** *"One sensor here, but the design is fleet-shaped — everything downstream
is scoped by which honeypot it came from."*

---

### Screen 3 · Log Explorer

**Sidebar → Log Explorer**

**What it is:** raw, unprocessed events straight from the honeypot. This is the
"before" picture — what an analyst would otherwise have to read by hand.

**What to say:** *"Thousands of lines like this is the problem the project starts from."*

#### Optional: generate live traffic in front of them

This is worth doing — it makes the system visibly live. In a **fourth** terminal:

```bash
ssh -p 2222 root@127.0.0.1
```

**Any password is accepted** (it is a decoy — it wants you to get in). Then type a few
commands and leave:

```
whoami
uname -a
ls /tmp
exit
```

Refresh the Log Explorer. **Your commands appear within a few seconds.** That is the full
ingest path running live: honeypot → Filebeat → Elasticsearch → API → browser.

---

### Screen 4 · Attack Sessions — the core loop

**Sidebar → Attack Sessions**

A session is one attacker's whole visit, rebuilt from individual events. The list shows
about 25; seven have enough commands to be interesting.

**Open `seed-botnet-01`.** Use this one — it is rule-backed, so it gives the same answer
every time.

You will see the risk score, session facts (attacker IP, duration, command count) and an
**Attack Timeline** classifying each event: connection, login attempt, command, download,
execution, disconnect.

#### Run the analysis

**Click `AI Analyze`** (top right).

Watch the **seven-stage stepper**. It advances from real progress messages sent by the
backend over a WebSocket — it is not an animation on a timer. Each stage gets its own
separate AI context, because the source paper found that asking for everything in one
prompt produces noticeably shallower answers.

**Takes about 25 seconds.** Expected result, measured:

| | |
|---|---|
| Classification | **Automated botnet dropper** |
| Risk | **critical, 90** |
| Techniques | **3**, all `OBSERVED`, confidence **1.0** |
| Indicators | **5** |

#### ★ The provenance demo — this is the centrepiece of the whole project

Scroll to the techniques and **click one to open it**.

You will see the technique, its confidence, and an **EVIDENCE** list. **Expand an evidence
row.** It opens into the actual recorded event — timestamp, action, and the exact command
the attacker typed.

**Say this out loud:**

> *"Nothing on this screen is asserted without a pointer back to the log line that
> produced it. And the pointer is live — this resolves through the same API the raw Log
> Explorer uses. If the AI produces a claim it cannot ground in a real event, the claim is
> rejected and counted, not shown."*

Also point at the badges: these three techniques say **`OBSERVED`** with confidence 1.0
because a deterministic rule matched the command. That is not the AI's opinion — the rule
either matched or it did not. Anything the AI proposed instead would be labelled
**`AI INFERENCE`** and rendered differently.

#### ★ Optional: the most convincing thirty seconds available

Go back and analyse **`seed-unmapped-01`** instead. Its commands are deliberately chosen
so **no rule matches**, meaning any technique could only come from the AI.

Frequently the result is **zero techniques**. The model inferred nothing, so the system
reported nothing — it did not invent a plausible-looking answer to fill the gap.

> ⚠️ **This one is genuinely random.** Sometimes the model does propose a technique, and
> then it appears clearly marked `AI INFERENCE` with an explanation. **Either outcome
> makes the point** — just don't promise the audience a specific result beforehand.

---

### Screen 5 · AI Analysis

**Sidebar → AI Analysis**

History of every analysis run, with model used and duration. Useful for showing this is a
repeatable pipeline rather than a one-off.

---

### Screen 6 · MITRE ATT&CK

**Sidebar → MITRE ATT&CK**

**What it is:** MITRE ATT&CK is the standard catalogue of attacker techniques. This matrix
shows which ones this honeypot has actually observed, against a pinned 21-technique set.

**Click a highlighted technique.** Note the badge next to *Mapping confidence*: it says
**`OBSERVED`** for rule-backed techniques and `AI INFERENCE` for model-proposed ones.

**What to say:** *"That distinction survives the entire path — from the rule that matched,
through the database, back into the search index, and onto this screen. An AI guess never
gets promoted into a recorded fact."*

---

### Screen 7 · Threat Intelligence

**Sidebar → Threat Intelligence**

Indicators pulled out of the sessions — malicious IPs, URLs, file hashes, usernames.

**Two things to point out:**

- Extraction is **pure pattern matching, no AI involved at all.** These are facts read
  directly out of the telemetry.
- Each carries a provenance tier. An indicator seen in more than one session is marked
  `CORRELATED` — derived by connecting sessions, which is a different kind of claim from a
  directly observed one.

**Attacker profiles:** open an attacker (e.g. `185.220.101.44`). It shows their sessions,
commands, and **behavioural similarity** to other attackers — computed by comparing command
sets, not by an AI embedding, so you can always explain *why* two attackers were called
similar.

---

### Screen 8 · Reports

**Sidebar → Reports**

Generate a report from `seed-botnet-01` — it produces *"Automated botnet dropper —
185.220.101.44"*.

**Point out:** reports are **immutable snapshots**. Re-analysing that session later does
not rewrite a report you already issued.

---

### Screen 9 · Realism Evaluation — the second half ★

**Sidebar → Realism Evaluation**

**What it is — explain before clicking:**

> *"Everything so far analysed attacks that came in. This does the opposite: it attacks
> our own honeypot, to measure how convincing it would look to a real intruder."*

Pick **`Cowrie SSH (med-ws-04)`** from the dropdown and click **Run evaluation**.

#### What happens

The button flips to "Evaluation in flight" **immediately** and you get a run id. The work
happens in the background — the seven stages stream in live. **Takes about 20 seconds.**

Behind those stages: it clears leftovers from the last run, fingerprints the honeypot,
port-scans it, starts a packet capture, logs in over SSH and runs a set of probes, then
replays three known attack chains (downloading malware, installing a crypto miner,
planting an SSH backdoor).

#### The result — four things to show, in this order

Open the finished run.

**1. Two separate scores, never combined.**

Every characteristic has a **Deterministic assessment** ("did the honeypot do the
checkable things?") and an **Evaluator assessment** ("would an attacker believe it?").

> *"There is deliberately no single overall score. One is a measurement, the other is a
> judgement — averaging them produces a number that means neither."*

Expected, measured:

```
attack_possibilities  100%     file_system  100%
basic_commands        100%     sanity        67%
context               100%     services      67%
```

The Evaluator column reads **"unavailable — no cloud model configured"** throughout, and
the header states it plainly: **"Absent is not zero."**

**2. The honeypot contradicts itself — a real defect, found automatically.**

Scroll to **Findings**. There is one, severity HIGH:

```
hostname_cmd and hostname_file disagree about host.name: 'med-ws-04' vs 'svr04'
```

The `hostname` command says one thing; the `/etc/hostname` file says another. **A real
intruder would notice that immediately.** Expand the evidence — both probe results are
there, showing the two disagreeing values.

> *"No AI was involved in finding that. Two probes established the same fact and
> disagreed, and that contradiction is detected deterministically."*

**3. The attack chains were recognised.**

Scroll to **Chain steps**. Seven steps, each showing: the command run, the ATT&CK
technique expected, the rule that matched, and a **Cowrie event id**.

**Click an event id.** It expands into the real captured event.

> *"This is the same provenance idea as the first half, running in the other direction. We
> attacked the honeypot, the attack was recognised by the same rulebook that classifies
> real intrusions, and the claim points at the log line proving it happened."*

**4. `sanity` and `services` scored 67%, not 100%.**

Those are *real* verdicts — two out of three each. The honeypot genuinely has gaps. That
is the entire point: the developer now has something specific to fix.

#### Comparing two runs

Run a **second** evaluation, then click **Compare runs** and pick both.

Each run records two fingerprints — one for the honeypot, one for the test setup — and the
comparison treats them **differently on purpose**:

- **The honeypot changed** → shown as *positive*. That change is the improvement being
  measured.
- **The test configuration changed** → shown as a *warning*. Our own probes moved, so any
  difference can no longer be blamed on the honeypot.

With two identical runs you get both "did not change" notices and deltas of `±0 pp`.

**Want to show the "not established" case?** Stop the backend, restart it with
`EVALUATION_CAPTURE_IMAGE=` (empty), and run again — the packet capture can no longer look,
so `context` reports *"not established"* in words instead of a number. That is the
tri-state doing its job: "we could not measure" is not "the honeypot failed".

---

### Screen 10 · Settings

**Sidebar → Settings**

Live health of every dependency, plus the security boundaries: no infrastructure
credentials ever reach the browser, and the AI model in use is read from the backend
rather than hardcoded.

---

## Part 4 — The single most important point

If the audience remembers one thing, make it this:

> **Fewer claims reach the screen than an ungrounded system would produce — and that is
> the design working, not a limitation.** Every claim opens into the exact log line behind
> it. A model's guess is labelled as a guess. And where the system could not measure
> something, it says *"not established"* rather than showing you a zero — because a zero
> looks like a verdict, and "we couldn't check" is not a verdict.

---

## Part 5 — Demo mode (no backend needed)

A **fallback if the stack misbehaves**, and useful on a laptop with nothing installed.

```bash
cd frontend
# Windows:      ren .env .env.bak
# Linux/macOS:  mv .env .env.bak
npm run dev
```

Every screen renders from a clearly-labelled built-in dataset. It also contains three
cases that are hard to produce live:

| Fixture | Shows |
|---|---|
| Run B | Evaluator unavailable, every rating null — nothing renders as `0.0` |
| Run C | Status `failed` while every module `completed` — *our* orchestration failed, not the honeypot |
| Run A | A null score **and** an entirely missing characteristic — "not established" and "not measured" are different things |

Restore afterwards: `ren .env.bak .env` (or `mv`).

---

## Part 6 — The eight-minute version

If you are short on time:

1. **Settings** — everything connected.
2. **Attack Sessions → `seed-botnet-01` → AI Analyze** — watch the seven stages (~25 s).
3. **Expand a piece of evidence** → the real log line. ★ *This is the project's whole thesis.*
4. **MITRE ATT&CK** — `OBSERVED` vs `AI INFERENCE`, rendered differently.
5. **Realism Evaluation → Run evaluation** (~20 s) — two separate scores, no overall score.
6. **Open the sanity finding** — the honeypot disagrees with itself about its own hostname.
7. **Expand a chain step's event id** — it resolves to the real captured command.

---

## Part 7 — Troubleshooting

### "getaddrinfo failed" / the evaluation cannot reach the honeypot

You started the backend without `EVALUATION_TARGET_HOST=127.0.0.1`. The default (`cowrie`)
is a name that only exists inside Docker's network. Stop the backend and restart it as
shown in [Part 2](#terminal-2--backend).

### Elasticsearch or Postgres not `healthy`

Give them another minute — Elasticsearch is slow to start. If they stay down:

```bash
docker compose down
docker compose up -d
```

### Docker Desktop won't start / "cannot find the pipe"

Start Docker Desktop from the Start menu and wait for the whale icon to stop animating.
`docker info` succeeding is the real signal. This can take a couple of minutes.

### The honeypot's ports are refused (2222 / 2223)

On Windows these sometimes fall inside a reserved port range after a reboot. Check:

```powershell
netsh int ipv4 show excludedportrange protocol=tcp
```

If `2222` falls inside a listed range, release it (elevated PowerShell):

```powershell
net stop winnat
net start winnat
```

Then `docker compose up -d` again.

### Analysis is very slow

`ollama ps` is probably showing CPU rather than `100% GPU`. It still works, just slowly.

### The evaluation's packet capture fails

Pull the image: `docker pull nicolaka/netshoot`. The capture runs inside the honeypot's
container network, which is the only place it can actually see the honeypot's traffic.

### Interface shows data but nothing updates / analysis does nothing

`frontend/.env` is probably missing, so the app is in demo mode. It must contain
`VITE_API_BASE_URL=http://localhost:8000`. Restart `npm run dev` after creating it.

### One test fails when I run the test suite

`test_intel.py::test_coverage_marks_llm_inferred_technique_as_not_observed` depends on
whether the local model happens to infer a technique on that pass. **A run showing only
that failure is a clean run.**

---

## Part 8 — Running the tests

```bash
cd backend && .venv/Scripts/python -m pytest
```

**459 tests**, about 7 minutes. They run against the live Docker stack and the real AI
model, so start the infrastructure first. Expect `459 passed`, or 458 with the one
nondeterministic test above.

```bash
cd frontend
npx tsc --noEmit      # type check — expect no output
npm run lint          # expect 9 warnings, 0 errors (that is the baseline)
npm run build
```

---

## Part 9 — Reset and shut down

### Clear evaluation runs between demos

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

This does **not** touch the honeypot. An evaluation only ever clears state a previous
evaluation created — the honeypot's identity keys, configuration and logs are protected in
code, and a path-traversal attempt is rejected outright.

### Shut down

Stop the backend and frontend with `Ctrl+C` in their terminals, then:

```bash
docker compose down
```

### Start completely fresh

```bash
docker compose down -v && docker compose up -d
```

`-v` deletes the stored data. The backend rebuilds its search index and reloads the sample
attacks on next start.

---

## Appendix — Where things live

```
backend/     The API and all analysis logic (Python / FastAPI)
frontend/    The web interface (React)
infra/       Honeypot, Filebeat and Elasticsearch configuration
README.md    Technical overview and architecture
OVERVIEW.md  The design reasoning — why it is built this way
DEMO.md      This file
```

For the engineering rationale behind any design decision here, read
[`OVERVIEW.md`](OVERVIEW.md).
