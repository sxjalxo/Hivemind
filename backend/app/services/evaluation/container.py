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

# How much of a failed command's output survives into the exception message.
# A command inside the container can emit megabytes on a bad day, and these
# messages are not only read by a human at a terminal -- an evaluation run
# persists its failure and logs it. An unbounded message turns one broken
# `docker exec` into a multi-megabyte DB row and a log line nothing will
# render. The HEAD is kept rather than the tail: the cause is what the
# process printed first (`OCI runtime exec failed: ... not found in $PATH`,
# a traceback's `SystemExit` line), and a scrolling wall of output after it
# adds nothing a longer excerpt would recover.
ERROR_DETAIL_LIMIT = 500


def error_detail(stdout: bytes, stderr: bytes) -> str:
    """The best available diagnostic from a failed docker call, bounded.

    stderr first, then stdout. Falling back is not defensive padding: a
    failed `docker exec` against this image reports on STDOUT with stderr
    empty. Observed against the live container --
    `docker exec hivemind-cowrie-1 /no/such/bin` exits 127 with 141 bytes on
    stdout and 0 on stderr. Reading stderr alone yields an empty detail on
    precisely the failure this project keeps hitting, and the honeypot is
    distroless so there is no shell to go and look with afterwards.
    """
    detail = stderr.decode("utf-8", "replace").strip()
    if not detail:
        detail = stdout.decode("utf-8", "replace").strip()
    if len(detail) > ERROR_DETAIL_LIMIT:
        detail = detail[:ERROR_DETAIL_LIMIT] + f"... [{len(detail)} chars truncated]"
    return detail


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
        raise ContainerExecError(
            f"{' '.join(argv[:3])} failed with exit code {process.returncode}: "
            f"{error_detail(stdout, stderr)}"
        )

    return stdout
