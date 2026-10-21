"""Render each honeypot persona into the files Cowrie reads (spec 2026-10-20).

    python -m scripts.build_persona              # render every persona
    python -m scripts.build_persona rpi          # one persona
    python -m scripts.build_persona --check      # exit 1 if a committed file differs

A persona is facts only: infra/cowrie/personas/<name>/persona.yaml. Each fact is
written ONCE here and rendered into every file that states it, so a persona
cannot contradict itself -- except where Cowrie's own fixed parts (its file
tree) contradict it, which is exactly what the evaluation is meant to find.

Refused rather than written:
  * an overlay or text-command path the pinned image does not have as a real
    file (image-files.txt) -- Cowrie would ignore it with no error;
  * a persona the evaluator's own readers find self-contradictory (the probe
    set's extracts and aliases are applied to the rendered files);
  * a CPU vendor that cannot run the claimed architecture;
  * a userdb line for the evaluation agent's user, which the generator owns.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.db.models import FactStatus
from app.services.evaluation.sanity import (
    Observation,
    comparable_value,
    find_contradictions,
    probe_extracts,
)

PERSONAS_DIR = Path(__file__).resolve().parents[2] / "infra" / "cowrie" / "personas"
IMAGE_FILES = PERSONAS_DIR / "image-files.txt"

Arch = Literal["x86_64", "aarch64", "armv7l"]
_ELF = {"x86_64": "linux-x64-lsb", "aarch64": "linux-arm64-lsb", "armv7l": "linux-arm-lsb"}
_VENDOR_ARCHES = {"intel": {"x86_64"}, "amd": {"x86_64"}, "arm": {"aarch64", "armv7l"}}
_VENDOR_ID = {"intel": "GenuineIntel", "amd": "AuthenticAMD", "arm": "ARM"}

# Debian 12's base accounts, as a fresh install has them. Persona users are
# appended; a persona may not redefine one of these.
_BASE_PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
messagebus:x:100:107::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
"""
_BASE_GROUP = """\
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:
cdrom:x:24:
sudo:x:27:
audio:x:29:
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
messagebus:x:107:
systemd-network:x:998:
nogroup:x:65534:
"""


def _ids(text: str, field: int) -> set[str]:
    return {line.split(":")[field] for line in text.splitlines()}


_BASE_NAMES = _ids(_BASE_PASSWD, 0) | _ids(_BASE_GROUP, 0)
_BASE_IDS = {int(i) for i in _ids(_BASE_PASSWD, 2) | _ids(_BASE_GROUP, 2)}

_X86_FLAGS = (
    "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx "
    "fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm constant_tsc rep_good nopl xtopology "
    "nonstop_tsc cpuid tsc_known_freq pni pclmulqdq ssse3 fma cx16 pcid sse4_1 sse4_2 x2apic "
    "movbe popcnt aes xsave avx f16c rdrand hypervisor lahf_lm abm fsgsbase bmi1 avx2 smep "
    "bmi2 erms invpcid rdseed adx smap clflushopt xsaveopt xsavec xgetbv1 xsaves arat"
)
_X86_FAMILY = {"intel": ("6", "85", "7"), "amd": ("23", "49", "0")}  # family, model, stepping


class PersonaError(ValueError):
    """The persona cannot be rendered into something Cowrie would serve as written."""


# Free-text fields are rendered into configparser text (cowrie.cfg), passwd rows and
# one-line files, so each pattern refuses what would end its line or field early.
# pydantic matches with Rust regex, where $ is end-of-text: a trailing newline fails.
_LINE = r"^[^\r\n]+$"
_CFG = r"^[^\r\n$]+$"  # no $: configparser's ExtendedInterpolation would read it
_PASSWD = r"^[^\r\n:]+$"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Distro(_Strict):
    id: str = Field(pattern=r"^[a-z]+$")
    name: str = Field(pattern=_LINE)
    pretty_name: str = Field(pattern=_LINE)
    version_id: str = Field(pattern=_LINE)
    version: str = Field(pattern=_LINE)
    codename: str = Field(pattern=_LINE)
    id_like: str | None = Field(None, pattern=_LINE)
    home_url: str | None = Field(None, pattern=_LINE)
    issue: str = Field(pattern=_LINE)  # /etc/issue's first line, e.g. "Ubuntu 22.04.4 LTS"
    debian_version: str = Field(pattern=_LINE)  # /etc/debian_version, e.g. "12.7"
    motd: str  # the login message block, rendered verbatim


class Kernel(_Strict):
    release: str = Field(pattern=_CFG)
    build: str = Field(pattern=_CFG)
    # /proc/version's text between the release and the build string
    compiler: str = Field(pattern=_CFG)
    arch: Arch


class Cpu(_Strict):
    vendor: Literal["intel", "amd", "arm"]
    model: str = Field(pattern=_LINE)
    cores: int = Field(ge=1, le=256)
    mhz: int = Field(ge=100, le=10_000)
    # an ARM board's `Model` line, e.g. a Raspberry Pi
    board: str | None = Field(None, pattern=_LINE)


class User(_Strict):
    name: str = Field(pattern=r"^[a-z_][a-z0-9_-]{0,31}$")
    uid: int = Field(ge=100, le=60_000)
    gecos: str = Field("", pattern=r"^[^\r\n:]*$")
    home: str | None = Field(None, pattern=_PASSWD)
    shell: str | None = Field(None, pattern=_PASSWD)

    @property
    def human(self) -> bool:
        return self.uid >= 1000


class Persona(_Strict):
    hostname: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,62}$")
    distro: Distro
    kernel: Kernel
    cpu: Cpu
    memory_mb: int = Field(ge=128)
    users: list[User] = []
    ssh_banner: str = Field(pattern=r"^SSH-2\.0-[^\r\n$]+$")
    logins: list[str] = []  # extra userdb.txt lines (user:x:password pattern)

    @model_validator(mode="after")
    def _consistent(self) -> "Persona":
        if self.kernel.arch not in _VENDOR_ARCHES[self.cpu.vendor]:
            raise ValueError(f"a {self.cpu.vendor} CPU cannot run {self.kernel.arch}")
        names = [u.name for u in self.users]
        uids = [u.uid for u in self.users]
        if len(set(names)) != len(names) or len(set(uids)) != len(uids):
            raise ValueError("persona users must have unique names and uids")
        for user in self.users:
            if user.name in _BASE_NAMES or user.uid in _BASE_IDS:
                raise ValueError(f"user {user.name} ({user.uid}) collides with a base account")
        return self


def load_image_files(path: Path) -> frozenset[str]:
    lines = path.read_text(encoding="utf-8").splitlines()
    return frozenset(line for line in lines if line and not line.startswith("#"))


def load_persona(path: Path) -> Persona:
    return Persona.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _cfg(p: Persona, role: str) -> str:
    if role == "vm":
        # The live honeypot's operational settings (infra/wild-vm/cowrie.cfg): it
        # records terminal sessions and caps downloads, and keeps Cowrie's stock
        # logins unless the persona declares some.
        recording = (
            "ttylog = true\nttylog_path = var/lib/cowrie/tty\ndownload_limit_size = 10485760\n"
        )
        etc = "etc_path = /persona/etc\n" if p.logins else ""
        forwarding = "forwarding = true\nforward_redirect = false\nforward_tunnel = false\n"
        who = "deployed to the GCP VM (both Cowries)"
    else:
        recording, etc, forwarding, who = "ttylog = false\n", "etc_path = /persona/etc\n", "", "arm"
    return f"""\
# GENERATED by backend/scripts/build_persona.py from persona.yaml -- do not edit.
# A persona {who}: every value below comes from one fact in persona.yaml.

[honeypot]
hostname = {p.hostname}
log_path = var/log/cowrie
download_path = var/lib/cowrie/downloads
{recording}contents_path = /persona/honeyfs
txtcmds_path = /persona/txtcmds
{etc}
[shell]
arch = {_ELF[p.kernel.arch]}
kernel_version = {p.kernel.release}
kernel_build_string = {p.kernel.build}
hardware_platform = {p.kernel.arch}
operating_system = GNU/Linux
ssh_version = {p.ssh_banner.removeprefix("SSH-2.0-")}

[ssh]
enabled = true
listen_endpoints = tcp:2222:interface=0.0.0.0
version = {p.ssh_banner}
{forwarding}
[telnet]
enabled = true
listen_endpoints = tcp:2223:interface=0.0.0.0

[output_jsonlog]
enabled = true
logfile = ${{honeypot:log_path}}/cowrie.json

[output_textlog]
enabled = false
"""


def _hosts(p: Persona) -> str:
    return (
        f"127.0.0.1\tlocalhost\n127.0.1.1\t{p.hostname}\n\n"
        "# The following lines are desirable for IPv6 capable hosts\n"
        "::1     localhost ip6-localhost ip6-loopback\n"
        "ff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n"
    )


def _os_release(d: Distro) -> str:
    lines = [
        f'PRETTY_NAME="{d.pretty_name}"',
        f'NAME="{d.name}"',
        f'VERSION_ID="{d.version_id}"',
        f'VERSION="{d.version}"',
        f"VERSION_CODENAME={d.codename}",
        f"ID={d.id}",
    ]
    if d.id_like:
        lines.append(f"ID_LIKE={d.id_like}")
    if d.home_url:
        lines.append(f'HOME_URL="{d.home_url}"')
    return "\n".join(lines) + "\n"


def _passwd(p: Persona) -> str:
    rows = []
    for u in p.users:
        home = u.home or (f"/home/{u.name}" if u.human else f"/var/lib/{u.name}")
        shell = u.shell or ("/bin/bash" if u.human else "/usr/sbin/nologin")
        rows.append(f"{u.name}:x:{u.uid}:{u.uid}:{u.gecos}:{home}:{shell}\n")
    return _BASE_PASSWD + "".join(rows)


def _group(p: Persona) -> str:
    return _BASE_GROUP + "".join(f"{u.name}:x:{u.uid}:\n" for u in p.users)


def _cpuinfo(p: Persona) -> str:
    c = p.cpu
    if c.vendor == "arm":
        number = {"aarch64": 8, "armv7l": 7}[p.kernel.arch]
        block = (
            "processor\t: {i}\nBogoMIPS\t: 108.00\n"
            "Features\t: fp asimd evtstrm crc32 cpuid\nCPU implementer\t: 0x41\n"
            f"CPU architecture: {number}\nCPU variant\t: 0x0\nCPU part\t: 0xd08\n"
            "CPU revision\t: 3\n\n"
        )
        text = "".join(block.format(i=i) for i in range(c.cores))
        return text + (f"Model\t\t: {c.board}\n" if c.board else "")
    family, model, stepping = _X86_FAMILY[c.vendor]
    blocks = []
    for i in range(c.cores):
        blocks.append(
            f"processor\t: {i}\nvendor_id\t: {_VENDOR_ID[c.vendor]}\ncpu family\t: {family}\n"
            f"model\t\t: {model}\nmodel name\t: {c.model}\nstepping\t: {stepping}\n"
            f"cpu MHz\t\t: {c.mhz}.000\ncache size\t: 36608 KB\nphysical id\t: 0\n"
            f"siblings\t: {c.cores}\ncore id\t\t: {i}\ncpu cores\t: {c.cores}\n"
            f"apicid\t\t: {i}\ninitial apicid\t: {i}\nfpu\t\t: yes\nfpu_exception\t: yes\n"
            f"cpuid level\t: 13\nwp\t\t: yes\nflags\t\t: {_X86_FLAGS}\n"
            f"bogomips\t: {c.mhz * 2}.00\nclflush size\t: 64\ncache_alignment\t: 64\n"
            "address sizes\t: 46 bits physical, 48 bits virtual\npower management:\n\n"
        )
    return "".join(blocks)


def _meminfo(p: Persona) -> str:
    total = p.memory_mb * 1024
    rows = [
        ("MemTotal", total),
        ("MemFree", total * 3 // 10),
        ("MemAvailable", total * 7 // 10),
        ("Buffers", total // 50),
        ("Cached", total * 3 // 10),
        ("SwapCached", 0),
        ("SwapTotal", 0),
        ("SwapFree", 0),
    ]
    return "".join(f"{f'{name}:':<16}{value:>8} kB\n" for name, value in rows)


def _lscpu(p: Persona) -> str:
    c = p.cpu
    modes = "32-bit, 64-bit" if p.kernel.arch != "armv7l" else "32-bit"
    rows = [
        ("Architecture", p.kernel.arch),
        ("CPU op-mode(s)", modes),
        ("Byte Order", "Little Endian"),
        ("CPU(s)", str(c.cores)),
        ("On-line CPU(s) list", f"0-{c.cores - 1}" if c.cores > 1 else "0"),
        ("Thread(s) per core", "1"),
        ("Core(s) per socket", str(c.cores)),
        ("Socket(s)", "1"),
        ("Vendor ID", _VENDOR_ID[c.vendor]),
        ("Model name", c.model),
        ("CPU MHz", f"{c.mhz}.000"),
    ]
    return "".join(f"{f'{name}:':<23}{value}\n" for name, value in rows)


def _userdb(p: Persona, agent_user: str) -> str:
    for line in p.logins:
        if line.split(":", 1)[0] == agent_user:
            raise PersonaError(
                f"login line {line!r} names the evaluation agent's user {agent_user!r}; "
                "the generator writes that user's line itself so a run can always sign in"
            )
    return "".join(f"{line}\n" for line in p.logins) + f"{agent_user}:x:*\n"


def _check_against_the_evaluator(p: Persona, files: dict[str, str]) -> None:
    """Read the rendered persona the way the evaluator will, and refuse a
    contradiction. Every fact must also be readable at least twice, or the
    check proves nothing about it."""
    uname = f"Linux {p.hostname} {p.kernel.release} {p.kernel.build} {p.kernel.arch} GNU/Linux"
    claims = [
        ("uname", "os.identity", uname),
        ("os_release", "os.identity", files["honeyfs/usr/lib/os-release"]),
        # extra readers of the distribution, under the probe ids whose extract reads them
        ("uname", "os.identity", files["honeyfs/proc/version"]),
        ("os_release", "os.identity", files["honeyfs/etc/issue"]),
        ("hostname_cmd", "host.name", p.hostname),
        ("hostname_file", "host.name", files["honeyfs/etc/hostname"]),
        ("hosts_file", "host.name", files["honeyfs/etc/hosts"]),
        ("uname_m", "host.arch", p.kernel.arch),
        ("cpu_arch", "host.arch", files["honeyfs/proc/cpuinfo"]),
    ]
    observations = [
        Observation(probe_id=i, establishes=f, value=v, fact_status=FactStatus.OBSERVED)
        for i, f, v in claims
    ]
    found = find_contradictions(observations)
    if found:
        detail = "; ".join(f"{c.fact} ({' vs '.join(c.probe_ids)})" for c in found)
        raise PersonaError(f"the evaluator would find this persona contradicting itself: {detail}")

    extracts = probe_extracts()
    for fact in ("os.identity", "host.name", "host.arch"):
        readable = [
            o
            for o in observations
            if o.establishes == fact and comparable_value(o, extracts) is not None
        ]
        if len(readable) < 2:
            raise PersonaError(f"{fact}: fewer than two rendered sources state it readably")


def render(
    p: Persona, image: frozenset[str], agent_user: str, role: Literal["arm", "vm"] = "arm"
) -> dict[str, str]:
    files = {
        "cowrie.cfg": _cfg(p, role),
        "honeyfs/etc/hostname": f"{p.hostname}\n",
        "honeyfs/etc/hosts": _hosts(p),
        "honeyfs/etc/passwd": _passwd(p),
        "honeyfs/etc/group": _group(p),
        "honeyfs/usr/lib/os-release": _os_release(p.distro),
        "honeyfs/proc/cpuinfo": _cpuinfo(p),
        "honeyfs/proc/meminfo": _meminfo(p),
        "honeyfs/proc/version": f"Linux version {p.kernel.release} {p.kernel.compiler} {p.kernel.build}\n",
        "honeyfs/etc/issue": f"{p.distro.issue} \\n \\l\n\n",
        "honeyfs/etc/issue.net": f"{p.distro.issue}\n",
        "honeyfs/etc/debian_version": f"{p.distro.debian_version}\n",
        "honeyfs/etc/motd": p.distro.motd,
        "txtcmds/usr/bin/nproc": f"{p.cpu.cores}\n",
        "txtcmds/usr/bin/lscpu": _lscpu(p),
    }
    # The generator's own login policy is for the evaluation arms; on the live
    # sensor only logins the persona declares replace Cowrie's stock ones.
    userdb = _userdb(p, agent_user)  # also refuses a login line for the agent's user
    if role == "arm" or p.logins:
        files["etc/userdb.txt"] = userdb
    missing = sorted(
        path for path in files if path.startswith(("honeyfs/", "txtcmds/")) and path not in image
    )
    if missing:
        raise PersonaError(
            f"not a real file in the pinned image, so Cowrie would ignore it: {missing}"
        )
    _check_against_the_evaluator(p, files)
    return files


def bundle_digest(files: dict[str, str]) -> str:
    """Name a rendered bundle by its content: the same files, the same digest,
    in any order. Recorded with each deployment and carried into the remote
    honeypot's fingerprint."""
    canonical = json.dumps(sorted(files.items()), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def _generated(root: Path) -> set[str]:
    return {
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.name != "persona.yaml"
    }


def drift(name: str, files: dict[str, str]) -> list[str]:
    root = PERSONAS_DIR / name
    on_disk = _generated(root)
    problems = [f"{name}/{rel}: missing" for rel in sorted(set(files) - on_disk)]
    problems += [f"{name}/{rel}: not generated" for rel in sorted(on_disk - set(files))]
    problems += [
        f"{name}/{rel}: differs from a fresh render"
        for rel in sorted(set(files) & on_disk)
        if (root / rel).read_bytes() != files[rel].encode()
    ]
    return problems


def _write(name: str, files: dict[str, str]) -> None:
    root = PERSONAS_DIR / name
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content.encode())  # bytes: LF exactly, on every platform
    for stale in _generated(root) - set(files):
        (root / stale).unlink()


def main(argv: list[str] | None = None) -> int:
    from app.config import get_settings

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("names", nargs="*", help="persona names; default every persona")
    parser.add_argument("--check", action="store_true", help="compare, do not write")
    args = parser.parse_args(argv)
    names = args.names or sorted(p.parent.name for p in PERSONAS_DIR.glob("*/persona.yaml"))
    image = load_image_files(IMAGE_FILES)
    agent_user = get_settings().evaluation_ssh_username
    problems: list[str] = []
    for name in names:
        try:
            files = render(load_persona(PERSONAS_DIR / name / "persona.yaml"), image, agent_user)
        except (PersonaError, ValueError, OSError, yaml.YAMLError) as exc:
            problems.append(f"{name}: {exc}")
            continue
        if args.check:
            problems += drift(name, files)
        else:
            _write(name, files)
            print(f"{name}: {len(files)} files")
    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
