"""Generate live SSH traffic against the Cowrie honeypot.

Non-interactive replacement for manually driving `ssh` at a password prompt.
Connects with Paramiko, drives an interactive shell channel, and prints each
command's output. Cowrie's default userdb accepts any password for `root`,
so this needs no real credentials.

An interactive shell (`invoke_shell`) is used rather than Paramiko's
`exec_command` because Cowrie does not reliably acknowledge exec-channel
requests before closing them — the same way a human operator would drive it
over `ssh -p 2222 root@127.0.0.1` and type at the prompt.

Usage:
    python scripts/generate_traffic.py
    python scripts/generate_traffic.py --host 127.0.0.1 --port 2222 \
        --username root --password anything --command "whoami" --command "id"
"""

from __future__ import annotations

import argparse
import sys
import time

import paramiko

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 2222
DEFAULT_USERNAME = "root"
DEFAULT_PASSWORD = "hivemind"
DEFAULT_COMMANDS = ["uname -a"]


def _drain(channel: paramiko.Channel, settle: float = 1.0) -> str:
    """Read whatever output is available, waiting for the channel to settle."""
    time.sleep(settle)
    chunks: list[bytes] = []
    while channel.recv_ready():
        chunks.append(channel.recv(4096))
        time.sleep(0.1)
    return b"".join(chunks).decode(errors="replace")


def run_commands(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    commands: list[str] | None = None,
    timeout: float = 10.0,
) -> None:
    """Connect to an SSH honeypot, drive an interactive shell, run each command.

    Raises whatever Paramiko raises on connection failure (e.g.
    `paramiko.SSHException`, `OSError`) so the caller can exit non-zero.
    """
    commands = commands if commands is not None else DEFAULT_COMMANDS

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        channel = client.invoke_shell()
        _drain(channel)  # banner / initial prompt

        for command in commands:
            print(f"$ {command}")
            channel.send(command + "\n")
            output = _drain(channel)
            print(output)

        channel.send("exit\n")
        _drain(channel, settle=0.5)
        channel.close()
    finally:
        client.close()


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--username", default=DEFAULT_USERNAME)
    parser.add_argument("--password", default=DEFAULT_PASSWORD)
    parser.add_argument(
        "--command",
        dest="commands",
        action="append",
        help="Shell command to run (repeatable). Defaults to 'uname -a'.",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = _parse_args()
    try:
        run_commands(
            host=args.host,
            port=args.port,
            username=args.username,
            password=args.password,
            commands=args.commands,
        )
    except Exception as exc:  # noqa: BLE001 - report and exit non-zero
        print(f"error: failed to generate traffic against Cowrie: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
