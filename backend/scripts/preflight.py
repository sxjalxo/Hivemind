"""Check a running stack is ready for the demo, and optionally warm the model.

Reads the stack the way the demo will -- over HTTP -- and prints one line per
condition. It exists because the run-sheet's startup checklist is six rows to
eyeball against a page, and every miss costs a minute in front of a panel.

    python -m scripts.preflight            # check
    python -m scripts.preflight --warm     # check, then load the model at the
                                           # backend's context size

Exit status is 1 if anything FAILed. WARN is "the demo works but not as
scripted" and never fails the run. Standard library only, so it needs no venv
and cannot itself be broken by a missing dependency.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass

# What the backend asks Ollama for (`app.services.llm.ollama._NUM_CTX`). A
# model warmed at any other context size is reloaded by the first real call,
# so warming at the wrong one buys nothing.
NUM_CTX = 8192

# The two sessions the run-sheet tells the driver to open by name.
DEMO_SESSIONS = ("seed-botnet-01", "seed-unmapped-01")

# Rows that must be up for the analysis half to work at all.
REQUIRED = {
    "elasticsearch": "connected",
    "postgres": "connected",
    "ollama": "connected",
    "seed-corpus": "running",
}


@dataclass(frozen=True)
class Result:
    level: str  # PASS | WARN | FAIL
    text: str


def judge_status(rows: list[dict]) -> list[Result]:
    """Turn `/api/status` rows into verdicts. Pure, so it is testable."""
    by_id = {row["id"]: row for row in rows}
    out: list[Result] = []
    for key, want in REQUIRED.items():
        row = by_id.get(key)
        if row is None:
            out.append(Result("FAIL", f"{key}: no such row in /api/status"))
        elif row["state"] != want:
            out.append(
                Result("FAIL", f"{key}: {row['state']} - {row.get('detail') or ''}".rstrip(" -"))
            )
        else:
            out.append(Result("PASS", f"{key}: {row['state']} {row.get('detail') or ''}".rstrip()))

    # The run-sheet marks these three as expected; reporting them as faults
    # would send someone hunting for a problem that is the design.
    for key, expected in (("evaluator", "disconnected"), ("authentication", "disconnected")):
        row = by_id.get(key)
        if row is not None and row["state"] != expected:
            out.append(Result("WARN", f"{key} is {row['state']}; the run-sheet expects {expected}"))
    docker = by_id.get("docker")
    if docker is not None and docker["state"] == "connected":
        out.append(
            Result(
                "WARN",
                "docker is connected: 'Run evaluation' is live. The run-sheet says do not click it",
            )
        )
    rejected = by_id.get("rejected-events")
    if rejected is not None and rejected["state"] != "running":
        out.append(
            Result("WARN", f"rejected-events: {rejected.get('detail') or rejected['state']}")
        )
    return out


def judge_dashboard(dashboard: dict) -> list[Result]:
    """Verdicts on what the dashboard shows at its default range. Pure.

    The seed corpus is anchored to the moment it was seeded and startup leaves
    an existing one where it is, so a stack that has been up for a day opens on
    an EMPTY dashboard: every counter zero before the demo has begun. Reading
    the panel itself catches that, and catches the opposite too -- panels the
    run-sheet says start at zero that earlier analyses have already filled.
    """
    kpis = {k["id"]: k["value"] for k in dashboard.get("kpis", [])}
    if not kpis.get("total_events"):
        return [
            Result(
                "FAIL",
                "dashboard shows 0 events at its default 24h range: the seed corpus is "
                "older than the window. Re-seed: python -m app.seed.seeder",
            )
        ]
    out = [Result("PASS", f"dashboard shows {kpis['total_events']} events at 24h")]
    filled = bool(dashboard.get("classifications")) or bool(kpis.get("techniques"))
    if filled:
        out.append(
            Result(
                "WARN",
                "the classification and technique panels are already populated; the "
                "run-sheet's 'watch these move' step assumes they start at zero. "
                "Re-seed, then do not analyse until the demo (re-seeding clears them)",
            )
        )
    else:
        out.append(Result("PASS", "classification and technique panels start at zero"))
    return out


def judge_ollama(ps: dict, model: str) -> Result:
    """`/api/ps` verdict. A model only partly in VRAM spills to CPU silently."""
    for loaded in ps.get("models", []):
        if loaded.get("name") == model:
            size, vram = loaded.get("size", 0), loaded.get("size_vram", 0)
            if size and vram < size:
                return Result(
                    "FAIL", f"{model} is {100 * vram // size}% on GPU - the rest runs on CPU"
                )
            return Result("PASS", f"{model} loaded, 100% GPU")
    return Result("WARN", f"{model} is not loaded: the first AI Analyze pays the load. Use --warm")


def _get(url: str, timeout: float = 5):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return response.status, response.read()


def _json(url: str):
    return json.loads(_get(url)[1])


def check(api: str, web: str, ollama: str, model: str, warm: bool) -> list[Result]:
    out: list[Result] = []
    try:
        out += judge_status(_json(f"{api}/api/status"))
    except Exception as exc:  # noqa: BLE001
        return [Result("FAIL", f"backend {api} unreachable: {exc}")]

    for sid in DEMO_SESSIONS:
        try:
            _get(f"{api}/api/sessions/{sid}")
            out.append(Result("PASS", f"{sid} present"))
        except urllib.error.HTTPError as exc:
            out.append(
                Result("FAIL", f"{sid}: HTTP {exc.code} - re-seed: python -m app.seed.seeder")
            )
        except Exception as exc:  # noqa: BLE001
            out.append(Result("FAIL", f"{sid}: {exc}"))

    try:
        out += judge_dashboard(_json(f"{api}/api/dashboard?range=24h"))
    except Exception as exc:  # noqa: BLE001
        out.append(Result("FAIL", f"dashboard data: {exc}"))

    try:
        status, _ = _get(web)
        out.append(Result("PASS" if status == 200 else "FAIL", f"dashboard {web}: HTTP {status}"))
    except Exception as exc:  # noqa: BLE001
        out.append(Result("FAIL", f"dashboard {web} unreachable: {exc}"))

    try:
        if warm:
            started = time.monotonic()
            request = urllib.request.Request(
                f"{ollama}/api/generate",
                data=json.dumps(
                    {
                        "model": model,
                        "prompt": "ok",
                        "stream": False,
                        "keep_alive": "30m",
                        "options": {"num_ctx": NUM_CTX},
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
            )
            urllib.request.urlopen(request, timeout=300).read()
            out.append(Result("PASS", f"warmed {model} in {time.monotonic() - started:.0f}s"))
        out.append(judge_ollama(_json(f"{ollama}/api/ps"), model))
    except Exception as exc:  # noqa: BLE001
        out.append(Result("FAIL", f"ollama {ollama}: {exc}"))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--api", default="http://127.0.0.1:8000")
    parser.add_argument("--web", default="http://127.0.0.1:8080")
    parser.add_argument("--ollama", default="http://localhost:11434")
    parser.add_argument("--model", default="llama3.1:8b")
    parser.add_argument("--warm", action="store_true", help="load the model before checking it")
    args = parser.parse_args()

    results = check(args.api, args.web, args.ollama, args.model, args.warm)
    for r in results:
        print(f"{r.level:<5} {r.text}")
    failed = sum(r.level == "FAIL" for r in results)
    warned = sum(r.level == "WARN" for r in results)
    print(f"\n{failed} failed, {warned} warnings")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
