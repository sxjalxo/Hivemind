"""The demo preflight's verdicts. Pure functions only: no stack needed."""

import importlib.util
import sys
from pathlib import Path

_SPEC = importlib.util.spec_from_file_location(
    "preflight", Path(__file__).resolve().parents[1] / "scripts" / "preflight.py"
)
preflight = importlib.util.module_from_spec(_SPEC)
# A dataclass resolves its own module through sys.modules, so register first.
sys.modules["preflight"] = preflight
_SPEC.loader.exec_module(preflight)


def _rows(**states: str) -> list[dict]:
    base = {
        "elasticsearch": "connected",
        "postgres": "connected",
        "ollama": "connected",
        "seed-corpus": "running",
        "evaluator": "disconnected",
        "authentication": "disconnected",
        "docker": "disconnected",
    }
    base.update(states)
    return [{"id": key, "state": state} for key, state in base.items()]


def _levels(results) -> dict[str, str]:
    return {r.text.split(":")[0].split(" ")[0]: r.level for r in results}


def test_the_documented_demo_state_has_no_failures_and_no_warnings():
    results = preflight.judge_status(_rows())
    assert {r.level for r in results} == {"PASS"}


def test_every_required_service_failing_is_a_fail_not_a_warning():
    for key in preflight.REQUIRED:
        results = preflight.judge_status(_rows(**{key: "disconnected"}))
        assert _levels(results)[key] == "FAIL", key


def test_a_missing_required_row_fails_rather_than_passing_by_omission():
    rows = [r for r in _rows() if r["id"] != "postgres"]
    assert any(r.level == "FAIL" and "postgres" in r.text for r in preflight.judge_status(rows))


def test_the_expected_disconnected_rows_are_not_reported_as_faults():
    # evaluator/authentication disconnected is the run-sheet's own "expected".
    assert all(r.level == "PASS" for r in preflight.judge_status(_rows()))


def test_a_live_docker_row_warns_because_the_run_button_would_work():
    results = preflight.judge_status(_rows(docker="connected"))
    assert any(r.level == "WARN" and "docker" in r.text for r in results)


def test_a_model_part_in_vram_fails_because_it_spills_to_cpu_silently():
    ps = {"models": [{"name": "m", "size": 100, "size_vram": 66}]}
    verdict = preflight.judge_ollama(ps, "m")
    assert verdict.level == "FAIL" and "66%" in verdict.text


def test_a_fully_resident_model_passes_and_an_unloaded_one_only_warns():
    full = {"models": [{"name": "m", "size": 100, "size_vram": 100}]}
    assert preflight.judge_ollama(full, "m").level == "PASS"
    assert preflight.judge_ollama({"models": []}, "m").level == "WARN"
    # A different model being resident says nothing about this one.
    other = {"models": [{"name": "x", "size": 100, "size_vram": 100}]}
    assert preflight.judge_ollama(other, "m").level == "WARN"


def _dash(events: int, classified: bool = False, techniques: int = 0) -> dict:
    return {
        "kpis": [
            {"id": "total_events", "value": events},
            {"id": "techniques", "value": techniques},
        ],
        "classifications": [{"name": "Automated botnet dropper", "value": 1}] if classified else [],
    }


def test_an_empty_dashboard_at_the_default_range_fails():
    # Seeded corpus older than 24h: the demo would open on all zeros.
    verdicts = preflight.judge_dashboard(_dash(0))
    assert [v.level for v in verdicts] == ["FAIL"] and "seeder" in verdicts[0].text


def test_a_fresh_unanalysed_dashboard_passes_cleanly():
    assert {v.level for v in preflight.judge_dashboard(_dash(51))} == {"PASS"}


def test_prefilled_panels_warn_whichever_panel_is_filled():
    for dash in (_dash(51, classified=True), _dash(51, techniques=3)):
        assert [v.level for v in preflight.judge_dashboard(dash)] == ["PASS", "WARN"]


def test_events_the_mapping_refused_warn():
    rows = _rows()
    rows.append(
        {"id": "rejected-events", "state": "degraded", "detail": "3 captured events refused"}
    )
    assert any(r.level == "WARN" and "3 captured" in r.text for r in preflight.judge_status(rows))
    rows[-1] = {"id": "rejected-events", "state": "running", "detail": "0 events rejected"}
    assert all(r.level == "PASS" for r in preflight.judge_status(rows))
