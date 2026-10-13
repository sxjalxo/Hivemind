"""The probe-candidate ranking. Pure functions only: no stack needed."""

import importlib.util
import sys
from pathlib import Path

from app.services.evaluation.probes import Probe

_SPEC = importlib.util.spec_from_file_location(
    "probe_candidates", Path(__file__).resolve().parents[1] / "scripts" / "probe_candidates.py"
)
pc = importlib.util.module_from_spec(_SPEC)
sys.modules["probe_candidates"] = pc
_SPEC.loader.exec_module(pc)

PROBES = (
    Probe(id="uname", characteristic="basic_commands", command="uname -a"),
    Probe(id="proc_cpuinfo", characteristic="file_system", command="cat /proc/cpuinfo"),
)


def test_a_command_counts_once_per_session_however_often_it_was_typed():
    rows = [("s1", "1.1.1.1", "free -m")] * 5 + [("s2", "2.2.2.2", "free -m")]
    [candidate] = pc.rank(rows, PROBES)
    assert (candidate.sessions, candidate.source_ips) == (2, 2)


def test_a_chained_line_is_split_and_each_part_checked_against_the_probes():
    ranked = {
        c.command: c
        for c in pc.rank([("s1", "1.1.1.1", "uname -a; cat /proc/cpuinfo | grep name")], PROBES)
    }
    assert ranked["uname -a"].covered_by == "uname"
    assert ranked["cat /proc/cpuinfo"].covered_by == "proc_cpuinfo"
    assert ranked["grep name"].covered_by is None


def test_the_display_keeps_the_typed_case_which_the_grouping_key_drops():
    [candidate] = pc.rank([("s1", "1.1.1.1", "chmod -R go= ~/.ssh")], PROBES)
    assert candidate.command == "chmod -r go= ~/.ssh"  # normalised key
    assert candidate.example == "chmod -R go= ~/.ssh"  # what is shown


def test_most_sessions_rank_first():
    rows = [("a", "1.1.1.1", "nproc"), ("b", "2.2.2.2", "nproc"), ("c", "3.3.3.3", "id")]
    assert [c.command for c in pc.rank(rows, PROBES)] == ["nproc", "id"]


def test_private_and_unparseable_sources_are_left_out_by_default():
    assert pc._counts("185.220.101.44", include_private=False)
    assert not pc._counts("172.19.0.1", include_private=False)  # the Docker gateway
    assert not pc._counts("127.0.0.1", include_private=False)
    assert not pc._counts("not-an-ip", include_private=False)
    assert pc._counts("172.19.0.1", include_private=True)
