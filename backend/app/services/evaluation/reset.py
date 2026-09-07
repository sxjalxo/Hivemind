"""Clear the state a *previous evaluation* created, and nothing else.

Two evaluation runs are only comparable if run B does not observe residue
that run A left behind -- otherwise the report blames the honeypot for our
own leftovers. That is this module's entire purpose.

The opposing constraint is equally load-bearing: it must never touch
operator-authored state (the config) or the honeypot's identity (its SSH
host keys, its sensor uuid). That state is what the developer is actively
trying to improve; resetting it would mean every run evaluates a pristine
default honeypot instead of the one under development, which makes the
whole feedback loop meaningless.

Failure model -- deliberately different from the other evaluation modules.
`nmap` and `tcpdump` degrade a failure into an `unknown` fact because they
produce evidence, and our inability to look is not evidence. Reset produces
no evidence: it establishes the *precondition* under which the run's
evidence means anything. A reset that did not happen invalidates the
comparison itself, so it raises `ResetError` rather than returning quietly.
The run orchestrator decides what to do with that; what it must never do is
proceed as though the state were clean.
"""

import asyncio
import contextlib
import re
from pathlib import PurePosixPath

# The Cowrie image is distroless. There is no `rm`, `sh`, `bash`, `ls` or
# `find` -- all four were probed and all four return exit 127 with
# `executable file not found in $PATH`. The interpreter Cowrie itself runs
# on is the only executable in the image, and `docker exec` does not apply
# the image entrypoint, so it must be named by absolute path.
CONTAINER_PYTHON = "/cowrie/cowrie-env/bin/python3"

# Directories whose *contents* an evaluation creates. These name directories,
# not globs: `asyncio.create_subprocess_exec` runs no shell, so a `*` would
# be passed through literally and match only a file actually named `*`.
# Cowrie expects these directories to exist, so the contents go and the
# directory stays.
RESET_PATHS: tuple[str, ...] = (
    # Files an attacker uploaded or fetched during a session, named by
    # SHA-256. Carrying these into the next run means run B sees run A's
    # malware.
    "/cowrie/cowrie-git/var/lib/cowrie/downloads",
    # Recorded TTY sessions. `ttylog` is currently false in our cowrie.cfg
    # so nothing is written here today, but upstream's default is true and
    # the operator may flip it while tuning realism -- at which point stale
    # recordings would leak between runs.
    "/cowrie/cowrie-git/var/lib/cowrie/tty",
)

# Entries inside a reset directory that ship with the image rather than
# being created by an evaluation. Cowrie's tree is a git checkout and these
# placeholders are what keep the otherwise-empty directories in it. Deleting
# them would drift the container's filesystem away from the image a little
# more on every run -- the exact non-comparability this module exists to
# prevent. Cowrie's own artefacts are never named this: downloads are
# SHA-256 hex, tty logs are timestamped.
PRESERVED_NAMES: tuple[str, ...] = (".gitignore",)

# State that must survive a reset. Every path here was confirmed to exist in
# the running container; a boundary that lists absent files reads as
# protection that is not there.
PRESERVED_PATHS: tuple[str, ...] = (
    # Operator-authored. Also bind-mounted read-only from the host
    # (`./infra/cowrie/cowrie.cfg:...:ro`), so the container physically
    # cannot delete it -- `os.access(W_OK)` is False inside the container
    # even though the mode bits read 0o777. That is defence in depth, not a
    # reason to leave it off this list.
    "/cowrie/cowrie-git/etc/cowrie.cfg",
    # The honeypot's cryptographic identity, sitting in the SAME directory
    # as the reset targets above. A careless glob over var/lib/cowrie would
    # regenerate the SSH host fingerprint on every run -- itself a realism
    # tell an attacker could notice -- and change what the honeypot *is*
    # between two runs we are trying to compare. `assert_boundary_holds`
    # below turns that from a comment into a check.
    "/cowrie/cowrie-git/var/lib/cowrie/uuid",
    "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_rsa_key",
    "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_rsa_key.pub",
    "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ecdsa_key",
    "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ecdsa_key.pub",
    "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ed25519_key",
    "/cowrie/cowrie-git/var/lib/cowrie/ssh_host_ed25519_key.pub",
    # Holds cowrie.json, which Filebeat tails into Elasticsearch. This is the
    # single most tempting thing to "clean between runs" and doing so would
    # be catastrophic: it is the source of every session the entire system
    # analyses, including the one the evaluation is about to read back.
    "/cowrie/cowrie-git/var/log/cowrie",
    # The fake filesystem an attacker walks -- part of what the honeypot
    # *is*. Note this is NOT at share/cowrie/fs.pickle; that path does not
    # exist in this image (the whole share/ tree is absent).
    "/cowrie/cowrie-git/src/cowrie/data/fs.pickle",
    # Written only by the libvirt/QEMU `backend_pool`, which creates qcow2
    # disk snapshots for real VM guests. Our cowrie.cfg resolves to
    # `backend = shell` and `save_snapshots = false`, so nothing in this
    # deployment ever writes here -- clearing it would buy zero comparability
    # while creating a way to delete a running guest's disk out from under
    # it if the backend were ever switched. Preserved, not reset.
    "/cowrie/cowrie-git/var/lib/cowrie/snapshots",
)

# Docker's own container-name grammar. An invalid name would otherwise turn
# into a `docker exec` failure at a point where it is harder to read.
_CONTAINER_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")

_DEFAULT_TIMEOUT_SECONDS = 30.0


class ResetError(RuntimeError):
    """A reset that could not be completed. The run is not comparable."""


class ResetBoundaryError(ValueError):
    """A reset path would destroy state that must be preserved."""


def assert_boundary_holds(
    *, reset_paths: tuple[str, ...], preserved_paths: tuple[str, ...]
) -> None:
    """Prove in code that no reset path can reach preserved state.

    Uses real path containment, not substring matching. A substring check
    passes `/cowrie/cowrie-git/etc/*` -- which contains neither the string
    "cowrie.cfg" nor "userdb" -- while that path deletes the config.
    """
    for path in reset_paths:
        if not path.startswith("/"):
            raise ResetBoundaryError(f"reset path must be absolute: {path!r}")
        if "*" in path or "?" in path:
            # No shell is involved, so a glob is never expanded. It would be
            # passed through literally, match a file named `*`, and quietly
            # do nothing.
            raise ResetBoundaryError(
                f"reset path must name a directory, not a glob: {path!r}"
            )

    for reset_path in reset_paths:
        parent = PurePosixPath(reset_path)
        for preserved in preserved_paths:
            child = PurePosixPath(preserved)
            if child == parent or parent in child.parents:
                raise ResetBoundaryError(
                    f"reset path {reset_path!r} covers preserved path {preserved!r}"
                )


# Enforced at import time: an edit that widens RESET_PATHS over preserved
# state cannot even be loaded, let alone run against the container.
assert_boundary_holds(reset_paths=RESET_PATHS, preserved_paths=PRESERVED_PATHS)


# Fixed source, executed by the container's own interpreter. Paths arrive via
# `sys.argv` and are never concatenated into this text -- building Python
# source out of a path is how a path with a quote in it becomes arbitrary
# code.
#
# Missing directory is treated as a failure, not as "nothing to do": a reset
# target that is not there means this is not the honeypot we think it is, and
# reporting that as a clean reset is the same silent no-op this module exists
# to eliminate. An empty directory is a legitimate success.
_CLEAR_SCRIPT = """
import os
import shutil
import stat
import sys

keep = {name for name in sys.argv[1].split(",") if name}
root = sys.argv[2]

if os.path.islink(root):
    raise SystemExit("reset target is a symlink, refusing to clear: " + root)
if not os.path.isdir(root):
    raise SystemExit("reset target is not a directory: " + root)

removed = 0
for name in sorted(os.listdir(root)):
    if name in keep:
        continue
    path = os.path.join(root, name)
    # lstat, so a symlink to a directory is unlinked rather than followed --
    # recursing through one would delete state outside the reset root.
    if stat.S_ISDIR(os.lstat(path).st_mode):
        shutil.rmtree(path)
    else:
        os.unlink(path)
    removed += 1

print(removed)
"""


async def _spawn(argv: list[str]):
    """Start `docker exec`. Replaced in tests."""
    return await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )


async def _clear_one(container: str, path: str, timeout_seconds: float) -> None:
    argv = [
        "docker",
        "exec",
        container,
        CONTAINER_PYTHON,
        "-c",
        _CLEAR_SCRIPT,
        ",".join(PRESERVED_NAMES),
        path,
    ]

    try:
        process = await _spawn(argv)
    except OSError as exc:
        raise ResetError(
            f"could not run docker exec against {container!r} for {path}: {exc}"
        ) from exc

    try:
        _, stderr = await asyncio.wait_for(
            process.communicate(), timeout=timeout_seconds
        )
    except TimeoutError as exc:
        # A hung docker exec left running holds a process against the
        # container for the rest of the session.
        with contextlib.suppress(ProcessLookupError, OSError):
            process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        raise ResetError(
            f"reset of {path} in {container!r} timed out after {timeout_seconds}s"
        ) from exc

    if process.returncode != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        raise ResetError(
            f"reset of {path} in {container!r} failed with exit code "
            f"{process.returncode}: {detail}"
        )


async def reset_target(
    container: str, timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS
) -> None:
    """Clear evaluation-created state in `container`, or raise.

    Returns only when every path in `RESET_PATHS` was actually cleared.
    Raises `ResetError` otherwise -- the caller must not treat the next run
    as comparable to the previous one.
    """
    if not _CONTAINER_NAME.fullmatch(container):
        raise ResetError(f"invalid container name: {container!r}")

    for path in RESET_PATHS:
        await _clear_one(container, path, timeout_seconds)
