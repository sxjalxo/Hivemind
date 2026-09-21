"""What this application is permitted to ask Docker to do.

The backend can reach the Docker daemon, and that access has no gradations of
its own: whoever can talk to it can create a container, and
`docker run -v /:/host --privileged` is root on the host with no exploit
required. No socket proxy, seccomp profile or API policy makes that call safe
-- it can only be not made.

So the defence is that the application does not create containers at all. The
packet capture was the only thing that needed to; it execs into a sidecar
compose declares instead. These tests hold that line, because it is the kind
of thing a future change reintroduces casually.
"""

import pathlib

import pytest

from app.services.evaluation import container

# app/services/evaluation/container.py -> backend/
BACKEND = pathlib.Path(container.__file__).resolve().parents[3]
REPO = BACKEND.parent


def test_the_allowlist_is_the_three_bounded_verbs() -> None:
    """Each is bounded by what the target container already is.

    `inspect` reads metadata. `exec` is root INSIDE a container that mounts
    nothing from the host but a read-only config file. `kill` signals a
    container this deployment declared. None of them reaches the host.
    """
    assert container._ALLOWED_VERBS == {"exec", "inspect", "kill"}


@pytest.mark.parametrize("verb", ["run", "create", "cp", "build", "load", "commit"])
@pytest.mark.asyncio
async def test_container_creating_verbs_are_refused(verb) -> None:
    """`run` and `create` are the host-root ones. `cp`, `build`, `load` and
    `commit` are refused by the same allowlist rather than by a blocklist that
    would need extending every time Docker grows a verb."""
    with pytest.raises(container.DockerPolicyError):
        await container.run(["docker", verb, "whatever"], timeout_seconds=1)

    with pytest.raises(container.DockerPolicyError):
        await container.spawn_checked(["docker", verb, "whatever"])


@pytest.mark.asyncio
async def test_a_non_docker_command_is_refused() -> None:
    """This module is the docker seam; it is not a general subprocess runner."""
    with pytest.raises(container.DockerPolicyError):
        await container.run(["sh", "-c", "echo hi"], timeout_seconds=1)
    with pytest.raises(container.DockerPolicyError):
        await container.run([], timeout_seconds=1)


def test_no_module_spawns_docker_outside_the_audited_seam() -> None:
    """The allowlist is worth nothing if a caller bypasses it.

    A module that both builds a docker argv and calls
    `create_subprocess_exec` itself is a second, unaudited route to the
    daemon sitting next to the one that is audited. `container.py` is the
    seam and is the only place allowed to do both.

    This caught `reset.py`, which had its own `_spawn` -- justified, because
    a deletion carries an in-container deadline nothing else needs, but the
    verb still has to pass the allowlist. It now delegates.

    Crude on purpose: a test that only exercised today's callers would not
    notice a NEW module doing its own thing, which is exactly how this comes
    back.
    """
    offenders = []
    for path in (BACKEND / "app").rglob("*.py"):
        if path.name == "container.py":
            continue  # the seam itself
        text = path.read_text(encoding="utf-8")
        # The CALL form, so a docstring explaining why this module does not
        # spawn docker itself does not read as it doing so.
        if "create_subprocess_exec(" in text and '"docker"' in text:
            offenders.append(str(path.relative_to(BACKEND)))

    assert offenders == [], (
        "these build a docker argv and spawn it directly, bypassing the "
        "allowlist: " + ", ".join(offenders)
    )


def test_nothing_in_the_application_spells_docker_run() -> None:
    """The blunt version of the check above, and the one that would have
    caught the capture before it was rewritten."""
    offenders = []
    for path in (BACKEND / "app").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith('"'):
                continue
            if stripped in ('"run",', '"create",'):
                offenders.append(f"{path.relative_to(BACKEND)}:{number}")
    assert offenders == [], "container-creating argv found at " + ", ".join(offenders)


def test_the_compose_file_declares_the_capture_sidecar() -> None:
    """The sidecar is what makes `docker run` unnecessary.

    Without it the capture has nowhere to exec into, and the pressure to
    reintroduce `docker run` comes straight back.
    """
    compose = (REPO / "docker-compose.yml").read_text(encoding="utf-8")

    assert "capture:" in compose
    assert 'network_mode: "service:cowrie"' in compose, (
        "the sidecar must share the honeypot's network namespace, or tcpdump "
        "watches an interface the honeypot's traffic never crosses"
    )
