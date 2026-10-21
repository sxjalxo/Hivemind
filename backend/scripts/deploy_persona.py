"""Deploy a persona to the GCP honeypots: the live Cowrie and its evaluation twin (R1).

    python -m scripts.deploy_persona web-server            # dry run: what would happen
    python -m scripts.deploy_persona web-server --apply    # do it
    python -m scripts.deploy_persona --revert [--apply]    # back to the pre-persona setup

--apply uploads the rendered bundle to /opt/hivemind/personas/<digest12>/,
switches personas/current to it atomically, recreates BOTH Cowries through the
VM's run-cowrie.sh (live attacker sessions drop), records the deployment for
both sensors, then checks the evaluation twin as an attacker would see it.
Never the live honeypot: our own logins would land in gcp-wild-01's data.
Rollback is deploying the previous persona (earlier bundles stay on the VM), or
--revert: remove personas/current, restart, record "pre-persona" for both sensors.

Reads WILD_HOST, WILD_PORT, WILD_USER, WILD_HOST_KEY and WILD_KEY_FILE from the
repo-root .env -- the admin key and pinned host key wild-pull already uses.
The dry run connects to nothing.
"""

import argparse
import asyncio
import contextlib
import getpass
import os
import posixpath
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from app.services.persona_deployments import PRE_PERSONA
from scripts.build_persona import (
    IMAGE_FILES,
    PERSONAS_DIR,
    Persona,
    bundle_digest,
    load_image_files,
    load_persona,
    render,
)

# Fixed on purpose, never taken from the command line: a deployment row on a
# local arm would change that arm's fingerprint.
SENSORS = ("gcp-wild-01", "gcp-eval-01")
REMOTE_ROOT = "/opt/hivemind/personas"
RUN_SCRIPT = "/opt/hivemind/run-cowrie.sh"
TWIN_PORT = 2222
# Without personas/current, run-cowrie.sh falls back to the legacy config and honeyfs.
REVERT_STEPS = [f"rm -f {REMOTE_ROOT}/current", RUN_SCRIPT]
REVERT_COMMAND = " && ".join(REVERT_STEPS)
ROLL_BACK = (
    "Roll back: deploy the previous persona, or "
    "`python -m scripts.deploy_persona --revert --apply` for the pre-persona setup."
)


class DeployError(RuntimeError):
    """The deploy stopped before changing anything it could not undo."""


class PersonaSwitched(DeployError):
    """`current` already points at the new bundle, but the restart failed."""


def should_record(error: BaseException | None) -> bool:
    """A deployment is recorded once `current` points at the bundle, restart or not."""
    return error is None or isinstance(error, PersonaSwitched)


def remote_dir(digest: str) -> str:
    return f"{REMOTE_ROOT}/{digest.removeprefix('sha256:')[:12]}"


def steps(digest: str) -> list[str]:
    """Every remote command, in order: for the dry run and for --apply."""
    folder = remote_dir(digest)
    name = posixpath.basename(folder)
    return [
        f"grep -q personas/current {RUN_SCRIPT}",
        f"(upload the bundle to {folder}/)",
        f"cd {REMOTE_ROOT} && ln -sfn {name} current.new && mv -T current.new current",
        RUN_SCRIPT,
    ]


def apply(remote, files: dict[str, str], digest: str) -> None:
    """Upload, switch, restart. `remote` has read(path), put(path, bytes), run(cmd)."""
    if "personas/current" not in remote.read(RUN_SCRIPT):
        raise DeployError(
            f"the VM's {RUN_SCRIPT} predates personas; copy infra/wild-vm/run-cowrie.sh "
            "there first (scp -P 50022 -i KEY infra/wild-vm/run-cowrie.sh USER@VM:/opt/hivemind/, "
            "then sed -i 's/\\r$//' and chmod 755 on the VM)"
        )
    folder = remote_dir(digest)
    for path in files:
        target = posixpath.normpath(posixpath.join(folder, path))
        if not target.startswith(folder + "/"):
            raise DeployError(f"{path!r} escapes the bundle folder")
    for path, content in sorted(files.items()):
        remote.put(f"{folder}/{path}", content.encode())
    switch, restart = steps(digest)[-2:]
    remote.run(switch)
    try:
        remote.run(restart)
    except Exception as exc:
        raise PersonaSwitched("run-cowrie.sh failed after the switch") from exc


def expected_view(persona: Persona, files: dict[str, str]) -> dict[str, str]:
    return {
        "hostname": persona.hostname,
        "uname -r": persona.kernel.release,
        "cat /etc/os-release": files["honeyfs/usr/lib/os-release"].strip(),
    }


def twin_mismatches(expected: dict[str, str], seen: dict[str, str]) -> list[str]:
    return [
        command for command, value in expected.items() if seen.get(command, "").strip() != value
    ]


class _Admin:
    """The VM's admin account over the pinned key: what `apply` needs, nothing more."""

    def __init__(self, env: dict[str, str]):
        from app.services.wild_pull import _Ssh

        self._ssh = _Ssh(
            env["WILD_HOST"],
            int(env.get("WILD_PORT", "50022")),
            env["WILD_USER"],
            env["WILD_KEY_FILE"],
            env["WILD_HOST_KEY"],
        )
        self._sftp = self._ssh.client.open_sftp()

    def read(self, path: str) -> str:
        with self._sftp.open(path) as handle:
            return handle.read().decode(errors="replace")

    def put(self, path: str, data: bytes) -> None:
        self._ssh._exec(f"mkdir -p {posixpath.dirname(path)}")
        with self._sftp.open(path, "wb") as handle:
            handle.write(data)

    def run(self, command: str) -> None:
        self._ssh._exec(command)

    def close(self) -> None:
        self._sftp.close()
        self._ssh.close()


async def _look_at_twin(
    host: str, expected: dict[str, str], wait_seconds: int = 90
) -> dict[str, str]:
    from app.config import get_settings
    from app.services.evaluation.agent import EvaluationTarget, _execute, _open_session

    settings = get_settings()
    target = EvaluationTarget(
        host=host,
        port=TWIN_PORT,
        username=settings.evaluation_ssh_username,
        password=settings.evaluation_ssh_password,
    )
    deadline = time.monotonic() + wait_seconds
    while True:  # the recreated Cowrie takes a few seconds to listen
        try:
            async with _open_session(target) as session:
                return {command: (await _execute(session, command))[0] for command in expected}
        except Exception:
            if time.monotonic() > deadline:
                raise
            await asyncio.sleep(5)


def _fail(message: str) -> int:
    print(f"{message} {ROLL_BACK}", file=sys.stderr)
    return 1


def _detail(exc: BaseException) -> str:
    """Our own DeployError text is safe to print. Any other exception is named by class
    only: its message or traceback can carry the VM's address or key path."""
    return str(exc) if type(exc) is DeployError else type(exc).__name__


def _on_vm(env: dict[str, str], action) -> Exception | None:
    """Run `action(remote)` over the admin key; return what it raised, or None."""
    remote = None
    try:
        remote = _Admin(env)
        action(remote)
    except Exception as exc:  # noqa: BLE001 -- any failure is reported by class only
        return exc
    finally:
        if remote is not None:
            with contextlib.suppress(Exception):  # the deploy's own outcome matters more
                remote.close()
    return None


async def _revert(env: dict[str, str]) -> int:
    failure = await asyncio.to_thread(_on_vm, env, lambda remote: remote.run(REVERT_COMMAND))
    if failure is not None:
        print(
            f"the revert failed: {_detail(failure)}. The honeypot may be down: check "
            "`sudo docker ps` on the VM and run --revert --apply again.",
            file=sys.stderr,
        )
        return 1
    from app.services import persona_deployments

    try:
        await persona_deployments.record(
            SENSORS, PRE_PERSONA, PRE_PERSONA, f"operator:{getpass.getuser()}"
        )
    except Exception as exc:  # noqa: BLE001
        print(
            "the VM is back on the pre-persona setup, but recording it failed: "
            f"{type(exc).__name__}. Evaluations will still fingerprint the old persona.",
            file=sys.stderr,
        )
        return 1
    print("reverted to the pre-persona setup")  # no bundle, so no twin to check
    return 0


async def _deploy(
    env: dict[str, str], name: str, persona: Persona, files: dict[str, str], digest: str
) -> int:
    from app.services import persona_deployments

    failure = await asyncio.to_thread(_on_vm, env, lambda remote: apply(remote, files, digest))
    if isinstance(failure, PersonaSwitched):
        print(
            "the switch ran, so `current` points at the new bundle, but restarting the "
            "Cowries failed: the honeypot may be down. Check `sudo docker ps` on the VM. "
            + ROLL_BACK,
            file=sys.stderr,
        )
    elif failure is not None:
        return _fail(f"the deploy failed: {_detail(failure)}.")
    exit_code = 0 if failure is None else 1
    try:
        await persona_deployments.record(SENSORS, name, digest, f"operator:{getpass.getuser()}")
    except Exception as exc:  # noqa: BLE001
        exit_code = 1
        live = "current points at the new bundle" if failure else "the persona is live"
        print(
            f"{live}, but recording the deployment failed: {type(exc).__name__}. "
            f"Re-run this deploy once the local database is back. {ROLL_BACK}",
            file=sys.stderr,
        )
    else:
        print(f"recorded {name} on {', '.join(SENSORS)}")
    if failure is not None:
        return 1  # the Cowries were not restarted: no twin to check

    expected = expected_view(persona, files)
    try:
        seen = await _look_at_twin(env["WILD_HOST"], expected)
    except Exception as exc:  # noqa: BLE001
        return _fail(f"the persona is live, but the twin check failed: {_detail(exc)}.")
    wrong = twin_mismatches(expected, seen)
    if wrong:
        return _fail(f"the evaluation twin does not show the persona: {wrong}.")
    print("the evaluation twin shows the persona")
    return exit_code


async def _main(
    args: argparse.Namespace,
    env: dict[str, str],
    persona: Persona | None,
    files: dict[str, str],
    digest: str,
) -> int:
    """All async work of one run in ONE event loop: the pooled engine is bound to it."""
    from app.db.session import get_engine
    from app.services import persona_deployments

    try:
        try:  # local Postgres is the first thing --apply needs after the VM: check it first
            await persona_deployments.active(SENSORS[0])
        except Exception as exc:  # noqa: BLE001
            print(
                "the local database is not reachable (or not migrated): "
                f"{type(exc).__name__}; nothing was changed",
                file=sys.stderr,
            )
            return 1
        if args.revert:
            return await _revert(env)
        return await _deploy(env, args.persona, persona, files, digest)
    finally:
        with contextlib.suppress(Exception):
            await get_engine().dispose()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("persona", nargs="?", help="a folder under infra/cowrie/personas/")
    parser.add_argument(
        "--revert", action="store_true", help="back to the pre-persona setup, not a persona"
    )
    parser.add_argument("--apply", action="store_true", help="act; without it, a dry run")
    args = parser.parse_args(argv)
    if bool(args.persona) == args.revert:
        parser.error("give exactly one of <persona> or --revert")

    persona = files = None
    digest = ""
    if args.revert:
        print(f"revert to the pre-persona setup  -> {', '.join(SENSORS)}")
        for command in REVERT_STEPS:
            print(f"  $ {command}")
    else:
        from app.config import get_settings

        persona = load_persona(PERSONAS_DIR / args.persona / "persona.yaml")
        files = render(
            persona,
            load_image_files(IMAGE_FILES),
            get_settings().evaluation_ssh_username,
            role="vm",
        )
        digest = bundle_digest(files)
        print(f"persona {args.persona}  {digest}  -> {', '.join(SENSORS)}")
        for path in sorted(files):
            print(f"  {path}")
        for command in steps(digest):
            print(f"  $ {command}")
    if not args.apply:
        print(
            "dry run: nothing changed, nothing contacted. --apply restarts both Cowries "
            "(live sessions drop)."
        )
        return 0

    load_dotenv(Path(__file__).resolve().parents[2] / ".env")
    return asyncio.run(_main(args, dict(os.environ), persona, files, digest))


if __name__ == "__main__":
    sys.exit(main())
