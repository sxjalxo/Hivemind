"""Which honeypot an evaluation run connects to.

Containment is unchanged: `evaluation_targets` is server-side settings, so a
caller still names a honeypot id and never an address. This only decides which
configured target that id resolves to.
"""

from app.config import HoneypotTarget, Settings


class UnknownTargetError(LookupError):
    """A honeypot id with no entry in a configured target map.

    Refused rather than defaulted. Falling back would evaluate one honeypot
    while labelling the run another -- every score, finding and fingerprint
    filed against the wrong decoy, and nothing downstream able to notice.
    """


def resolve(honeypot_id: str, settings: Settings) -> HoneypotTarget:
    """The target for one honeypot id.

    With no map configured every id resolves to the single legacy target, so
    a one-honeypot deployment needs no configuration at all.
    """
    if not settings.evaluation_targets:
        return HoneypotTarget(
            # The legacy path names the Cowrie service from this project's
            # own docker-compose.yml, so it is the one target whose kind we
            # know rather than have to be told. Every entry in
            # EVALUATION_TARGETS names an address somebody typed, and
            # defaults to `cowrie` only because that is what the field's
            # default says -- see `HoneypotTarget.kind` for why a real host
            # must be declared `generic`.
            kind="cowrie",
            host=settings.evaluation_target_host,
            ssh_port=settings.evaluation_ssh_port,
            ssh_username=settings.evaluation_ssh_username,
            ssh_password=settings.evaluation_ssh_password,
            container_name=settings.evaluation_container_name,
            capture_interface=settings.evaluation_capture_interface,
            capture_container=settings.evaluation_capture_container or None,
        )

    try:
        return settings.evaluation_targets[honeypot_id]
    except KeyError:
        raise UnknownTargetError(
            f"honeypot {honeypot_id!r} has no entry in EVALUATION_TARGETS "
            f"(configured: {sorted(settings.evaluation_targets)}). Add one, or "
            f"clear the map to send every honeypot to the single default target."
        ) from None
