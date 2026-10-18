"""infra/wild-vm/eval-gate.sh, the only thing the evaluation key can run on the
VM -- the real script, with a stub `docker` mapping volume names to temp dirs."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[2] / "infra" / "wild-vm" / "eval-gate.sh"
SH = shutil.which("sh")
pytestmark = pytest.mark.skipif(SH is None, reason="needs a POSIX sh")

VOLUMES = ["cowrie-eval-logs", "cowrie-eval-tty", "cowrie-eval-dl", "cowrie-tty", "cowrie-dl"]


@pytest.fixture
def vm(tmp_path: Path) -> Path:
    stubs = tmp_path / "bin"
    stubs.mkdir()
    (stubs / "docker").write_text('#!/bin/sh\necho "$VOLROOT/$5"\n', newline="\n")
    (stubs / "docker").chmod(0o755)
    for v in VOLUMES:
        (tmp_path / v).mkdir()
        (tmp_path / v / ".gitignore").write_text("")
        (tmp_path / v / "residue").write_text("x")
    (tmp_path / "cowrie-eval-dl" / "sub").mkdir()
    (tmp_path / "cowrie-eval-logs" / "cowrie.json").write_bytes(b'{"n":1}\n{"n":2}\n')
    return tmp_path


def gate(vm: Path, request: str) -> subprocess.CompletedProcess:
    env = {
        **os.environ,
        "PATH": f"{vm / 'bin'}{os.pathsep}{os.environ['PATH']}",
        "VOLROOT": str(vm),
        "SSH_ORIGINAL_COMMAND": request,
    }
    return subprocess.run([SH, str(GATE)], env=env, capture_output=True)


def test_list_and_read_serve_the_evaluation_log(vm: Path) -> None:
    listed = gate(vm, "list")
    assert listed.returncode == 0
    assert listed.stdout.decode().split()[1:] == ["16", "cowrie.json"]
    assert gate(vm, "read cowrie.json 8 8").stdout == b'{"n":2}\n'


@pytest.mark.parametrize(
    "request_",
    [
        "read ../cowrie-tty/residue 0 1",
        "read cowrie.json* 0 10",
        "read cowrie.json 0 1;id",
        "read cowrie.json -1 5",
        "read cowrie.json 010 5",
        "read cowrie.json 0",
        "list extra",
        "sh -c id",
        "",
    ],
)
def test_anything_else_is_refused(vm: Path, request_: str) -> None:
    result = gate(vm, request_)
    assert result.returncode == 2
    assert b"refused" in result.stderr


def test_reset_empties_only_the_evaluation_residue(vm: Path) -> None:
    assert gate(vm, "reset").returncode == 0
    for v in ("cowrie-eval-tty", "cowrie-eval-dl"):
        assert [p.name for p in (vm / v).iterdir()] == [".gitignore"]
    # The live honeypot's volumes and the evaluation log are untouched.
    for v in ("cowrie-tty", "cowrie-dl"):
        assert (vm / v / "residue").exists()
    assert (vm / "cowrie-eval-logs" / "cowrie.json").exists()
