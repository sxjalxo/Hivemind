"""The persona deploy (R1): the remote step sequence against a fake, no VM."""

import pytest

from app.services import persona_deployments
from scripts import deploy_persona as deploy
from scripts.build_persona import (
    IMAGE_FILES,
    PERSONAS_DIR,
    bundle_digest,
    load_image_files,
    load_persona,
    render,
)

FILES = render(
    load_persona(PERSONAS_DIR / "web-server" / "persona.yaml"),
    load_image_files(IMAGE_FILES),
    "root",
    role="vm",
)
DIGEST = bundle_digest(FILES)


class FakeRemote:
    def __init__(self, run_script: str = "... /opt/hivemind/personas/current ...", fail_on=None):
        self.run_script = run_script
        self.fail_on = fail_on  # a command whose run() raises, like a failed restart
        self.puts: dict[str, bytes] = {}
        self.commands: list[str] = []
        self.events: list[tuple[str, str]] = []  # everything, in the order it happened

    def read(self, path: str) -> str:
        assert path == "/opt/hivemind/run-cowrie.sh"
        self.events.append(("read", path))
        return self.run_script

    def put(self, path: str, data: bytes) -> None:
        self.events.append(("put", path))
        self.puts[path] = data

    def run(self, command: str) -> None:
        self.events.append(("run", command))
        self.commands.append(command)
        if command == self.fail_on:
            raise OSError("connection reset")


def test_deployment_rows_are_only_ever_for_the_two_gcp_sensors() -> None:
    # Fixed on purpose: a local arm with a deployment row would change its
    # fingerprint, so no CLI argument may widen this.
    assert deploy.SENSORS == ("gcp-wild-01", "gcp-eval-01")


def test_the_bundle_lands_under_its_digest_then_switches_then_restarts() -> None:
    remote = FakeRemote()
    deploy.apply(remote, FILES, DIGEST)
    folder = deploy.remote_dir(DIGEST)
    assert folder == "/opt/hivemind/personas/" + DIGEST.removeprefix("sha256:")[:12]
    assert set(remote.puts) == {f"{folder}/{path}" for path in FILES}
    assert remote.puts[f"{folder}/honeyfs/etc/hostname"] == FILES["honeyfs/etc/hostname"].encode()
    assert remote.commands == deploy.steps(DIGEST)[-2:]  # switch, then restart
    switch, restart = remote.commands
    assert "ln -sfn" in switch and "mv -T" in switch
    assert restart == "/opt/hivemind/run-cowrie.sh"


def test_the_switch_runs_only_after_every_upload() -> None:
    remote = FakeRemote()
    deploy.apply(remote, FILES, DIGEST)
    kinds = [kind for kind, _ in remote.events]
    assert kinds[0] == "read"
    first_run = kinds.index("run")
    assert kinds[1:first_run] == ["put"] * len(FILES)
    assert [value for kind, value in remote.events if kind == "run"] == deploy.steps(DIGEST)[-2:]
    assert remote.events[-1] == ("run", deploy.RUN_SCRIPT)  # the restart is last


def test_a_failed_restart_after_the_switch_is_still_recorded() -> None:
    switch = deploy.steps(DIGEST)[-2]
    remote = FakeRemote(fail_on=deploy.RUN_SCRIPT)
    with pytest.raises(deploy.PersonaSwitched) as caught:
        deploy.apply(remote, FILES, DIGEST)
    assert switch in remote.commands  # `current` now points at the new bundle
    assert deploy.should_record(caught.value)
    assert deploy.should_record(None)  # the clean run


def test_nothing_is_recorded_when_the_switch_never_ran() -> None:
    refused = FakeRemote(run_script="#!/bin/sh")
    with pytest.raises(deploy.DeployError) as caught:
        deploy.apply(refused, FILES, DIGEST)
    assert not deploy.should_record(caught.value)
    switch_fails = FakeRemote(fail_on=deploy.steps(DIGEST)[-2])
    with pytest.raises(OSError) as caught:
        deploy.apply(switch_fails, FILES, DIGEST)
    assert not deploy.should_record(caught.value)
    assert deploy.RUN_SCRIPT not in switch_fails.commands


def test_an_old_run_script_is_refused_before_anything_is_uploaded() -> None:
    remote = FakeRemote(run_script="#!/bin/sh\n# no persona support\n")
    with pytest.raises(deploy.DeployError, match="run-cowrie.sh"):
        deploy.apply(remote, FILES, DIGEST)
    assert remote.puts == {} and remote.commands == []


def test_a_path_escaping_the_bundle_is_refused() -> None:
    with pytest.raises(deploy.DeployError, match="escapes"):
        deploy.apply(FakeRemote(), {**FILES, "../run-cowrie.sh": "x"}, DIGEST)


def test_the_twin_check_compares_what_an_attacker_sees_with_the_bundle() -> None:
    persona = load_persona(PERSONAS_DIR / "web-server" / "persona.yaml")
    expected = deploy.expected_view(persona, FILES)
    assert deploy.twin_mismatches(expected, dict(expected)) == []
    stale = {**expected, "hostname": "svr04"}
    assert deploy.twin_mismatches(expected, stale) == ["hostname"]


def test_the_refusal_prints_the_sed_command_with_a_backslash_r_not_a_carriage_return() -> None:
    with pytest.raises(deploy.DeployError) as caught:
        deploy.apply(FakeRemote(run_script="#!/bin/sh\n"), FILES, DIGEST)
    message = str(caught.value)
    assert "s/\\r$//" in message  # the two characters backslash, r
    assert "\r" not in message  # not the control character


# --- the orchestration: main() with the VM, the database and the twin all faked ---------------

PERSONA = load_persona(PERSONAS_DIR / "web-server" / "persona.yaml")
ROLL_BACK_BOTH = ("deploy the previous persona", "deploy_persona --revert --apply")


def _rig(monkeypatch, *, db_down=False, record_error=None, fail_on=None, twin_wrong=False):
    """Fake every outside thing `main --apply` touches; `calls` is what happened, in order."""

    class Calls(list):
        twin_hosts: list

    calls = Calls()
    calls.twin_hosts = []
    records: list = []

    class Admin(FakeRemote):
        def __init__(self, env):
            super().__init__(fail_on=fail_on)
            calls.append("admin")

        def run(self, command):
            calls.append(f"run:{command}")
            super().run(command)

        def close(self):
            calls.append("close")

    async def active(honeypot_id, at=None):
        calls.append("preflight")
        if db_down:
            raise ConnectionRefusedError("postgres.internal:5432")

    async def record(sensors, persona, digest, deployed_by, at=None):
        calls.append("record")
        records.append((tuple(sensors), persona, digest))
        if record_error:
            raise record_error

    async def twin(host, expected, wait_seconds=90):
        calls.append("twin")
        calls.twin_hosts.append(host)
        return {**expected, "hostname": "wrong"} if twin_wrong else dict(expected)

    monkeypatch.setattr(deploy, "load_dotenv", lambda *a, **k: None)  # never the repo-root .env
    monkeypatch.setenv("WILD_HOST", "vm.invalid")
    monkeypatch.delenv("WILD_EVAL_HOST", raising=False)
    monkeypatch.setattr(deploy, "_Admin", Admin)
    monkeypatch.setattr(deploy, "_look_at_twin", twin)
    monkeypatch.setattr(persona_deployments, "active", active)
    monkeypatch.setattr(persona_deployments, "record", record)
    return calls, records


def test_a_clean_deploy_checks_the_database_then_deploys_then_records_then_checks_the_twin(
    monkeypatch, capsys
) -> None:
    calls, records = _rig(monkeypatch)
    assert deploy.main(["web-server", "--apply"]) == 0
    switch, restart = deploy.steps(DIGEST)[-2:]
    assert calls == [
        "preflight",
        "admin",
        f"run:{switch}",
        f"run:{restart}",
        "close",
        "record",
        "twin",
    ]
    assert records == [(deploy.SENSORS, "web-server", DIGEST)]
    assert "the evaluation twin shows the persona" in capsys.readouterr().out


def test_the_twin_is_checked_at_its_own_address_when_it_has_one(monkeypatch) -> None:
    # With IAP tunnels the admin tunnel is 127.0.0.1 and the evaluation Cowrie's is 127.0.0.2.
    calls, _ = _rig(monkeypatch)
    monkeypatch.setenv("WILD_HOST", "127.0.0.1")
    monkeypatch.setenv("WILD_EVAL_HOST", "127.0.0.2")
    assert deploy.main(["web-server", "--apply"]) == 0
    assert calls.twin_hosts == ["127.0.0.2"]


def test_the_twin_is_checked_at_the_admin_address_without_an_eval_address(monkeypatch) -> None:
    calls, _ = _rig(monkeypatch)
    monkeypatch.setenv("WILD_HOST", "127.0.0.1")
    assert deploy.main(["web-server", "--apply"]) == 0
    assert calls.twin_hosts == ["127.0.0.1"]


def test_an_unreachable_database_stops_the_apply_before_the_vm_is_touched(
    monkeypatch, capsys
) -> None:
    calls, _ = _rig(monkeypatch, db_down=True)
    assert deploy.main(["web-server", "--apply"]) == 1
    assert calls == ["preflight"]  # _Admin was never constructed
    err = capsys.readouterr().err
    assert "nothing was changed" in err and "ConnectionRefusedError" in err
    assert "postgres.internal" not in err  # class name only


def test_a_failed_restart_is_recorded_skips_the_twin_and_says_what_state_the_vm_is_in(
    monkeypatch, capsys
) -> None:
    calls, records = _rig(monkeypatch, fail_on=deploy.RUN_SCRIPT)
    assert deploy.main(["web-server", "--apply"]) == 1
    assert "record" in calls and "twin" not in calls
    assert len(records) == 1
    err = capsys.readouterr().err
    assert "current` points at the new bundle" in err
    assert "may be down" in err and "sudo docker ps" in err
    assert all(way in err for way in ROLL_BACK_BOTH)
    assert "PersonaSwitched" not in err and "connection reset" not in err


def test_a_record_failure_after_a_clean_restart_still_checks_the_twin(monkeypatch, capsys) -> None:
    calls, _ = _rig(monkeypatch, record_error=OSError("secret path"))
    assert deploy.main(["web-server", "--apply"]) == 1
    assert calls[-2:] == ["record", "twin"]
    err = capsys.readouterr().err
    assert "recording the deployment failed: OSError" in err and "secret path" not in err
    assert all(way in err for way in ROLL_BACK_BOTH)


def test_a_record_failure_after_a_failed_restart_says_current_points_at_the_bundle(
    monkeypatch, capsys
) -> None:
    calls, _ = _rig(monkeypatch, fail_on=deploy.RUN_SCRIPT, record_error=OSError("x"))
    assert deploy.main(["web-server", "--apply"]) == 1
    assert "twin" not in calls
    assert "current points at the new bundle, but recording" in capsys.readouterr().err


def test_a_twin_that_does_not_show_the_persona_fails_and_offers_both_ways_back(
    monkeypatch, capsys
) -> None:
    _rig(monkeypatch, twin_wrong=True)
    assert deploy.main(["web-server", "--apply"]) == 1
    err = capsys.readouterr().err
    assert "does not show the persona" in err
    assert all(way in err for way in ROLL_BACK_BOTH)


def test_revert_removes_current_restarts_and_records_the_pre_persona_for_both_sensors(
    monkeypatch, capsys
) -> None:
    calls, records = _rig(monkeypatch)
    assert deploy.main(["--revert", "--apply"]) == 0
    assert calls == [
        "preflight",
        "admin",
        "run:rm -f /opt/hivemind/personas/current && /opt/hivemind/run-cowrie.sh",
        "close",
        "record",
    ]  # no twin check: there is no bundle to compare against
    assert records == [(deploy.SENSORS, deploy.PRE_PERSONA, deploy.PRE_PERSONA)]
    assert "reverted to the pre-persona setup" in capsys.readouterr().out


def test_a_failed_revert_records_nothing(monkeypatch, capsys) -> None:
    calls, _ = _rig(monkeypatch, fail_on=deploy.REVERT_COMMAND)
    assert deploy.main(["--revert", "--apply"]) == 1
    assert "record" not in calls
    assert "may be down" in capsys.readouterr().err


def test_the_dry_runs_contact_nothing(monkeypatch, capsys) -> None:
    calls, _ = _rig(monkeypatch)
    assert deploy.main(["web-server"]) == 0
    assert deploy.main(["--revert"]) == 0
    assert calls == []
    out = capsys.readouterr().out
    assert "rm -f /opt/hivemind/personas/current" in out and "run-cowrie.sh" in out


@pytest.mark.parametrize("argv", [[], ["web-server", "--revert"]])
def test_exactly_one_of_a_persona_or_revert(argv) -> None:
    with pytest.raises(SystemExit) as caught:
        deploy.main(argv)
    assert caught.value.code == 2
