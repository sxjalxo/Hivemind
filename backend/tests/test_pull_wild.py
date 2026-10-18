"""The live-honeypot puller: every line arrives once, in order, across rotations."""

from app.services.wild_pull import (
    LIVE,
    Position,
    Read,
    RemoteFile,
    plan,
    pull_once,
    whole_lines,
)


def test_only_whole_lines_are_taken():
    assert whole_lines(b'{"a":1}\n{"b":2}\n{"c"') == b'{"a":1}\n{"b":2}\n'
    assert whole_lines(b'{"half') == b""


def test_first_pull_reads_the_live_log_and_says_rotated_files_are_skipped():
    files = [RemoteFile(1, 100, "cowrie.json.2026-10-17"), RemoteFile(2, 50, LIVE)]
    reads, warning = plan(None, files)
    assert reads == [Read(LIVE, 0, 50)]
    assert "not backfilled" in warning


def test_a_rotation_finishes_the_old_file_then_starts_the_new_one():
    files = [RemoteFile(7, 120, "cowrie.json.2026-10-18"), RemoteFile(8, 30, LIVE)]
    reads, warning = plan(Position(7, 100), files)
    assert reads == [Read("cowrie.json.2026-10-18", 100, 120), Read(LIVE, 0, 30)]
    assert warning is None


def test_a_vanished_inode_resumes_at_the_live_log_and_warns():
    reads, warning = plan(Position(99, 10), [RemoteFile(8, 30, LIVE)])
    assert reads == [Read(LIVE, 0, 30)]
    assert "gone" in warning


class FakeRemote:
    """A Cowrie log directory: files by name, rotated by renaming (inode kept)."""

    def __init__(self):
        self.files: dict[str, tuple[int, bytearray]] = {LIVE: (1, bytearray())}
        self.next_inode = 2

    def write(self, data: bytes):
        self.files[LIVE][1].extend(data)

    def rotate(self, day: str):
        self.files[f"cowrie.json.{day}"] = self.files.pop(LIVE)
        self.files[LIVE] = (self.next_inode, bytearray())
        self.next_inode += 1

    def listing(self):
        return [RemoteFile(inode, len(data), name) for name, (inode, data) in self.files.items()]

    def read(self, name, start, length):
        return bytes(self.files[name][1][start : start + length])


def test_every_line_arrives_once_across_pulls_partial_lines_and_a_rotation(tmp_path):
    remote, out = FakeRemote(), tmp_path / "gcp"
    remote.write(b'{"n":1}\n{"n":2}\n{"n":3')  # third line half-written
    pull_once(remote, out)
    assert (out / LIVE).read_bytes() == b'{"n":1}\n{"n":2}\n'

    remote.write(b'}\n{"n":4}\n')
    remote.rotate("2026-10-18")
    remote.write(b'{"n":5}\n')
    pull_once(remote, out)
    pull_once(remote, out)  # nothing new: nothing appended

    lines = (out / LIVE).read_bytes().splitlines()
    assert lines == [b'{"n":1}', b'{"n":2}', b'{"n":3}', b'{"n":4}', b'{"n":5}']
