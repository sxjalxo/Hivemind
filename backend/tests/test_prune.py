"""Retention decisions (checklist item 23). Pure; nothing here deletes anything."""

import argparse
import os
from datetime import UTC, datetime, timedelta

import pytest

from scripts.prune import IndexState, index_verdict, old_recordings, parse_age, rotated_logs

NOW = datetime(2026, 10, 15, 12, tzinfo=UTC)
CUTOFF = NOW - timedelta(days=90)  # 2026-07-17 12:00
SHA_A, SHA_B, SHA_C = "a" * 64, "b" * 64, "c" * 64


def test_age_is_days_only_and_positive():
    assert parse_age("90d") == parse_age("90") == timedelta(days=90)
    for bad in ("0d", "-5", "2w", "90h", ""):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_age(bad)


def test_only_rotated_days_that_ended_before_the_cutoff_are_old():
    names = [
        "cowrie.json",  # live: never
        "cowrie.json.2026-07-15",  # ended 07-16 00:00, before the cutoff
        "cowrie.json.2026-07-17",  # ends 07-18 00:00, after the cutoff
        "webpot.json.2026-01-02",
        ".gitignore",
        "cowrie.json.not-a-date",
    ]
    assert rotated_logs(names, CUTOFF) == ["cowrie.json.2026-07-15", "webpot.json.2026-01-02"]


def test_an_old_recording_is_kept_while_a_referenced_session_names_it():
    old = (CUTOFF - timedelta(days=1)).timestamp()
    new = (CUTOFF + timedelta(days=1)).timestamp()
    files = {SHA_A: old, SHA_B: old, SHA_C: new, ".gitignore": old}
    assert old_recordings(files, CUTOFF, keep={SHA_B}) == [SHA_A]


@pytest.mark.parametrize(
    ("state", "kept_because"),
    [
        (IndexState("i-1", True, CUTOFF - timedelta(days=9), 0), "the write index"),
        (IndexState("i-1", False, CUTOFF + timedelta(days=1), 0), "newer than the cutoff"),
        (IndexState("i-1", False, CUTOFF - timedelta(days=9), 3), "3 event(s) referenced"),
    ],
)
def test_an_index_is_kept_for_each_reason(state, kept_because):
    assert kept_because in index_verdict(state, CUTOFF)


def test_an_old_unreferenced_rolled_over_index_may_be_dropped():
    assert index_verdict(IndexState("i-1", False, CUTOFF - timedelta(days=1), 0), CUTOFF) is None
    assert index_verdict(IndexState("i-2", False, None, 0), CUTOFF) is None  # empty


def test_webpot_moves_a_previous_days_log_aside(tmp_path):
    from tests.test_webpot import webpot

    log = tmp_path / "webpot.json"
    log.write_text("{}\n")
    yesterday = (NOW - timedelta(days=1)).timestamp()
    os.utime(log, (yesterday, yesterday))

    webpot.rotate(str(log), NOW)
    assert not log.exists()
    assert (tmp_path / "webpot.json.2026-10-14").read_text() == "{}\n"

    log.write_text("{}\n")  # today's: left alone
    os.utime(log, (NOW.timestamp(), NOW.timestamp()))
    webpot.rotate(str(log), NOW)
    assert log.exists()
    webpot.rotate(str(tmp_path / "missing.json"), NOW)  # nothing to rotate is not an error
