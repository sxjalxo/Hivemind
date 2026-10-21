"""The persona generator (spec 2026-10-20). Pure: renders into memory only."""

import shutil

import pytest
from pydantic import ValidationError

from scripts.build_persona import (
    IMAGE_FILES,
    Persona,
    PersonaError,
    bundle_digest,
    drift,
    load_image_files,
    load_persona,
    main,
    render,
)

IMAGE = load_image_files(IMAGE_FILES)

WEB_MOTD = """Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro
"""
DEBIAN_MOTD = """
The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
"""
WEB = {
    "hostname": "web-test-01",
    "distro": {
        "id": "ubuntu",
        "name": "Ubuntu",
        "pretty_name": "Ubuntu 22.04.4 LTS",
        "version_id": "22.04",
        "version": "22.04.4 LTS (Jammy Jellyfish)",
        "codename": "jammy",
        "id_like": "debian",
        "issue": "Ubuntu 22.04.4 LTS",
        "debian_version": "bookworm/sid",
        "motd": WEB_MOTD,
    },
    "kernel": {
        "release": "5.15.0-113-generic",
        "build": "#123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024",
        "arch": "x86_64",
        "compiler": "(buildd@lcy02-amd64-086) (x86_64-linux-gnu-gcc-12 (Ubuntu 12.3.0-1ubuntu1~22.04) 12.3.0, GNU ld (GNU Binutils for Ubuntu) 2.38)",
    },
    "cpu": {
        "vendor": "intel",
        "model": "Intel(R) Xeon(R) Platinum 8259CL CPU @ 2.50GHz",
        "cores": 2,
        "mhz": 2500,
    },
    "memory_mb": 3920,
    "users": [{"name": "deploy", "uid": 1000, "gecos": "Deploy,,,"}],
    "ssh_banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
}
RPI = {
    **WEB,
    "hostname": "raspberrypi",
    "distro": {
        "id": "debian",
        "name": "Debian GNU/Linux",
        "pretty_name": "Debian GNU/Linux 12 (bookworm)",
        "version_id": "12",
        "version": "12 (bookworm)",
        "codename": "bookworm",
        "issue": "Debian GNU/Linux 12",
        "debian_version": "12.7",
        "motd": DEBIAN_MOTD,
    },
    "kernel": {
        "release": "6.6.51+rpt-rpi-v8",
        "build": "#1 SMP PREEMPT Debian 1:6.6.51-1+rpt3 (2024-10-08)",
        "arch": "aarch64",
        "compiler": "(serge@raspberrypi.com) (aarch64-linux-gnu-gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40)",
    },
    "cpu": {
        "vendor": "arm",
        "model": "Cortex-A72",
        "cores": 4,
        "mhz": 1800,
        "board": "Raspberry Pi 4 Model B Rev 1.4",
    },
    "users": [{"name": "pi", "uid": 1000}],
}
EXPECTED = {
    "cowrie.cfg",
    "etc/userdb.txt",
    "honeyfs/etc/hostname",
    "honeyfs/etc/hosts",
    "honeyfs/etc/passwd",
    "honeyfs/etc/group",
    "honeyfs/usr/lib/os-release",
    "honeyfs/proc/cpuinfo",
    "honeyfs/proc/meminfo",
    "honeyfs/proc/version",
    "honeyfs/etc/issue",
    "honeyfs/etc/issue.net",
    "honeyfs/etc/motd",
    "honeyfs/etc/debian_version",
    "txtcmds/usr/bin/nproc",
    "txtcmds/usr/bin/lscpu",
}


def _persona(base: dict, **changes) -> Persona:
    return Persona.model_validate({**base, **changes})


def test_every_fact_is_rendered_where_cowrie_reads_it() -> None:
    files = render(_persona(WEB), IMAGE, "root")
    assert set(files) == EXPECTED
    cfg = files["cowrie.cfg"]
    for line in (
        "hostname = web-test-01",
        "hardware_platform = x86_64",
        "arch = linux-x64-lsb",
        "kernel_version = 5.15.0-113-generic",
        "contents_path = /persona/honeyfs",
        "txtcmds_path = /persona/txtcmds",
        "etc_path = /persona/etc",
        "version = SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    ):
        assert line in cfg.splitlines(), line
    assert files["honeyfs/etc/hostname"] == "web-test-01\n"
    assert "127.0.1.1\tweb-test-01" in files["honeyfs/etc/hosts"]
    assert "ID=ubuntu" in files["honeyfs/usr/lib/os-release"].splitlines()
    assert files["honeyfs/proc/cpuinfo"].count("processor\t:") == 2
    assert "vendor_id\t: GenuineIntel" in files["honeyfs/proc/cpuinfo"]
    assert "deploy:x:1000:1000:Deploy,,,:/home/deploy:/bin/bash" in files["honeyfs/etc/passwd"]
    assert "deploy:x:1000:" in files["honeyfs/etc/group"].splitlines()
    assert files["txtcmds/usr/bin/nproc"] == "2\n"
    assert files["etc/userdb.txt"].splitlines()[-1] == "root:x:*"
    assert all("\r" not in content for content in files.values())


def test_an_arm_persona_renders_arm_shaped_files() -> None:
    files = render(_persona(RPI), IMAGE, "root")
    assert "arch = linux-arm64-lsb" in files["cowrie.cfg"].splitlines()
    assert files["honeyfs/proc/cpuinfo"].count("CPU architecture: 8") == 4
    assert "Model\t\t: Raspberry Pi 4 Model B Rev 1.4" in files["honeyfs/proc/cpuinfo"]
    assert "Architecture:          aarch64" in files["txtcmds/usr/bin/lscpu"]


def test_rendering_is_deterministic() -> None:
    assert render(_persona(WEB), IMAGE, "root") == render(_persona(WEB), IMAGE, "root")


def test_a_kernel_naming_another_distribution_is_refused() -> None:
    # Ubuntu in os-release, Debian in the kernel string: the evaluator's own
    # reader would report os.identity contradicting itself.
    kernel = {**WEB["kernel"], "build": "#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)"}
    with pytest.raises(PersonaError, match="os.identity"):
        render(_persona(WEB, kernel=kernel), IMAGE, "root")


def test_a_compiler_string_naming_another_distribution_is_refused() -> None:
    # /proc/version is a second reader of the distribution, next to uname.
    compiler = (
        "(debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0, "
        "GNU ld (GNU Binutils for Debian) 2.40)"
    )
    with pytest.raises(PersonaError, match="os.identity"):
        render(_persona(WEB, kernel={**WEB["kernel"], "compiler": compiler}), IMAGE, "root")


def test_an_issue_naming_another_distribution_is_refused() -> None:
    with pytest.raises(PersonaError, match="os.identity"):
        render(
            _persona(WEB, distro={**WEB["distro"], "issue": "Debian GNU/Linux 12"}), IMAGE, "root"
        )


def test_a_cpu_vendor_that_cannot_run_the_architecture_is_refused() -> None:
    with pytest.raises(ValidationError, match="intel"):
        _persona(WEB, kernel={**WEB["kernel"], "arch": "aarch64"})


def test_an_overlay_path_the_image_lacks_is_refused() -> None:
    # Cowrie would ignore it in silence; the generator must not.
    with pytest.raises(PersonaError, match="honeyfs/proc/cpuinfo"):
        render(_persona(WEB), IMAGE - {"honeyfs/proc/cpuinfo"}, "root")


def test_a_text_command_the_image_does_not_ship_is_refused() -> None:
    with pytest.raises(PersonaError, match="txtcmds/usr/bin/lscpu"):
        render(_persona(WEB), IMAGE - {"txtcmds/usr/bin/lscpu"}, "root")


def test_a_login_line_for_the_agent_user_is_refused() -> None:
    # It could deny the evaluation agent its own login; the generator owns that line.
    with pytest.raises(PersonaError, match="root"):
        render(_persona(WEB, logins=["root:x:!root"]), IMAGE, "root")


@pytest.mark.parametrize("user", [{"name": "www-data", "uid": 1001}, {"name": "ops", "uid": 107}])
def test_a_user_colliding_with_a_base_account_is_refused(user) -> None:
    with pytest.raises(ValidationError):
        _persona(WEB, users=[user])


def test_unknown_keys_are_refused() -> None:
    with pytest.raises(ValidationError):
        _persona(WEB, hostnmae="typo")


def test_the_committed_personas_match_a_fresh_render() -> None:
    # A hand edit to generated output -- or a generator change nobody re-ran --
    # would put files in front of attackers that no persona.yaml describes.
    from scripts.build_persona import PERSONAS_DIR

    assert sorted(p.parent.name for p in PERSONAS_DIR.glob("*/persona.yaml")) == [
        "db-server",
        "rpi",
        "web-server",
    ]
    assert main(["--check"]) == 0


@pytest.mark.parametrize(
    "changes",
    [
        {"kernel": {**WEB["kernel"], "build": "#1 SMP Debian\n[ssh]\nenabled = false"}},
        {"kernel": {**WEB["kernel"], "release": "6.1.0\r"}},
        {"ssh_banner": "SSH-2.0-OpenSSH_9.2p1\n[output_jsonlog]"},
        {"kernel": {**WEB["kernel"], "build": "#1 SMP $x Debian"}},
    ],
)
def test_a_newline_in_a_cfg_bound_field_is_refused(changes) -> None:
    # cowrie.cfg is configparser text: a newline injects sections, a $ breaks interpolation.
    with pytest.raises(ValidationError):
        _persona(WEB, **changes)


@pytest.mark.parametrize(
    "users",
    [
        [{"name": "eve", "uid": 1001, "gecos": "x:0:0"}],
        [{"name": "eve", "uid": 1001, "shell": "/bin/sh\nroot2:x:0:0::/:/bin/sh"}],
    ],
)
def test_a_colon_or_newline_in_a_passwd_field_is_refused(users) -> None:
    with pytest.raises(ValidationError):
        _persona(WEB, users=users)


def test_drift_reports_every_kind_of_difference(tmp_path, monkeypatch) -> None:
    from scripts import build_persona

    shutil.copytree(build_persona.PERSONAS_DIR / "web-server", tmp_path / "web-server")
    monkeypatch.setattr(build_persona, "PERSONAS_DIR", tmp_path)
    files = render(load_persona(tmp_path / "web-server" / "persona.yaml"), IMAGE, "root")
    assert drift("web-server", files) == []

    root = tmp_path / "web-server"
    with (root / "honeyfs/etc/hostname").open("ab") as f:
        f.write(b"x")
    (root / "txtcmds/usr/bin/nproc").unlink()
    (root / "honeyfs/etc/extra").write_text("stray")
    problems = drift("web-server", files)
    assert len(problems) == 3
    assert any(p.endswith("honeyfs/etc/hostname: differs from a fresh render") for p in problems)
    assert any(p.endswith("txtcmds/usr/bin/nproc: missing") for p in problems)
    assert any(p.endswith("honeyfs/etc/extra: not generated") for p in problems)


def test_main_reports_a_missing_persona_instead_of_crashing(capsys) -> None:
    assert main(["no-such-persona", "--check"]) == 1
    assert "no-such-persona:" in capsys.readouterr().err


def test_the_vm_role_keeps_the_live_honeypots_operational_settings() -> None:
    cfg = render(_persona(WEB), IMAGE, "root", role="vm")["cowrie.cfg"].splitlines()
    for line in (
        "ttylog = true",
        "ttylog_path = var/lib/cowrie/tty",
        "download_limit_size = 10485760",
        "forwarding = true",
        "forward_redirect = false",
        "forward_tunnel = false",
        "hostname = web-test-01",
        "contents_path = /persona/honeyfs",
        "txtcmds_path = /persona/txtcmds",
    ):
        assert line in cfg, line
    assert "ttylog = false" not in cfg


def test_the_vm_role_keeps_cowries_stock_logins_unless_the_persona_declares_some() -> None:
    # The persona's root-only userdb would lock real attackers out of the live
    # sensor and change what it captures.
    stock = render(_persona(WEB), IMAGE, "root", role="vm")
    assert "etc/userdb.txt" not in stock
    assert not any(line.startswith("etc_path") for line in stock["cowrie.cfg"].splitlines())
    declared = render(_persona(WEB, logins=["admin:x:*"]), IMAGE, "root", role="vm")
    assert declared["etc/userdb.txt"].splitlines() == ["admin:x:*", "root:x:*"]
    assert "etc_path = /persona/etc" in declared["cowrie.cfg"].splitlines()


def test_the_vm_role_carries_the_same_identity_as_the_arm() -> None:
    arm = render(_persona(WEB), IMAGE, "root")
    vm = render(_persona(WEB), IMAGE, "root", role="vm")
    for path in arm:
        if path.startswith(("honeyfs/", "txtcmds/")):
            assert vm[path] == arm[path], path


def test_a_bundle_digest_is_stable_and_content_sensitive() -> None:
    files = render(_persona(WEB), IMAGE, "root", role="vm")
    digest = bundle_digest(files)
    assert digest.startswith("sha256:") and len(digest) == len("sha256:") + 64
    assert bundle_digest(dict(reversed(list(files.items())))) == digest
    changed = {**files, "honeyfs/etc/hostname": "other\n"}
    assert bundle_digest(changed) != digest
