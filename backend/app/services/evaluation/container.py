"""The facts about talking to the Cowrie container, in one place.

This module exists because the same defect has now been written twice
against this container: a `docker exec ... cat <file>` that cannot possibly
work, whose failure was then swallowed. Both halves are container facts,
not caller policy, so they live here rather than being re-derived by every
module that needs to look inside the honeypot.

`reset.py` was the first caller and keeps its own exec flow -- it carries an
in-container deadline that only a deletion needs, and its argv is built
around that script. It imports the two constants below so the distroless
fact has exactly one definition; the discipline in `run` below is the same
discipline `reset._clear_one` already applies.
"""

import asyncio
import contextlib
import re

# The Cowrie image is distroless. `cat`, `rm`, `sh`, `bash`, `ls`, `head` and
# `find` are all absent -- every one of them returns exit 127 with
# `executable file not found in $PATH`. The interpreter Cowrie itself runs on
# is the only executable in the image, and `docker exec` does NOT apply the
# image entrypoint, so it must be named by absolute path.
CONTAINER_PYTHON = "/cowrie/cowrie-env/bin/python3"

# Docker's own container-name grammar. Checking it here turns an unusable
# name into a clear error instead of an obscure `docker exec` failure.
CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


class ContainerExecError(RuntimeError):
    """`docker` could not be run, or the process it started failed."""


class ContainerExecTimeout(ContainerExecError):
    """The docker CLI did not finish inside its deadline."""


async def _spawn(argv: list[str]):
    """Start a docker CLI process. The seam tests replace."""
    return await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def run(argv: list[str], *, timeout_seconds: float) -> bytes:
    """Run a docker command and return its stdout, or raise.

    Three things this deliberately does that the obvious version does not:
    stderr is captured rather than sent to DEVNULL, the return code is
    inspected, and the wait is bounded. Dropping any one of them turns a
    failed command into empty output that the caller cannot distinguish
    from a real, empty result.
    """
    try:
        process = await _spawn(argv)
    except OSError as exc:
        raise ContainerExecError(f"could not run {argv[0]!r}: {exc}") from exc

    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds
        )
    except TimeoutError as exc:
        # This reaps the local docker CLI only. Anything already started
        # inside the container is not signalled by it and runs to
        # completion; the kill just avoids leaving a stray client behind.
        with contextlib.suppress(ProcessLookupError, OSError):
            process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        raise ContainerExecTimeout(
            f"{' '.join(argv[:3])} timed out after {timeout_seconds}s"
        ) from exc

    if process.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        if not detail:
            # Some docker CLI failures (a failed `exec`, for one) report on
            # stdout, so an empty stderr is not proof there is no message.
            detail = stdout.decode("utf-8", "replace").strip()
        raise ContainerExecError(
            f"{' '.join(argv[:3])} failed with exit code {process.returncode}: {detail}"
        )

    return stdout
