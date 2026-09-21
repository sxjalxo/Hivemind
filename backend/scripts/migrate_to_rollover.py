"""Convert a concrete `honeypot-events` index into a rollover alias.

Run once, by hand, from `backend/`:

    .venv/Scripts/python -m scripts.migrate_to_rollover            # dry run
    .venv/Scripts/python -m scripts.migrate_to_rollover --apply

Why this is not done automatically at startup: converting means copying every
document into a new index and deleting the original. That is irreversible, it
operates on captured attacker telemetry rather than on anything reproducible,
and doing it unattended on every boot is exactly the class of action that
rollover-without-a-delete-phase was chosen to avoid. `bootstrap_es` logs a
warning and leaves the index alone; this script is the deliberate act.

What it does, in order:

  1. Refuse if `honeypot-events` is already an alias (nothing to do) or is
     missing entirely (nothing to migrate).
  2. Create `honeypot-events-000001`.
  3. Reindex everything into it, preserving document ids.
  4. **Verify the counts match.** Nothing is deleted until they do.
  5. Delete the old concrete index.
  6. Point the alias at the new index as its write index.

Steps 5 and 6 cannot be reordered: an alias cannot take a name that a
concrete index already holds. So there is a brief window -- between the
delete and the alias creation -- in which nothing answers to
`honeypot-events`. Stop the backend before running this.
"""

import argparse
import asyncio
import sys

from app.config import get_settings
from app.es.bootstrap import bootstrap_es
from app.es.client import get_es


async def _run(apply: bool) -> int:
    settings = get_settings()
    es = get_es()
    alias = settings.es_index
    target = f"{alias}-000001"

    if await es.indices.exists_alias(name=alias):
        print(f"{alias} is already a rollover alias. Nothing to do.")
        return 0

    if not await es.indices.exists(index=alias):
        print(f"{alias} does not exist. Nothing to migrate; start the backend instead.")
        return 0

    source_count = (await es.count(index=alias))["count"]
    print(f"source index {alias}: {source_count} documents")

    if await es.indices.exists(index=target):
        print(f"REFUSING: {target} already exists. Inspect it and remove it first.")
        return 1

    if not apply:
        print()
        print("Dry run. This would:")
        print(f"  1. create {target}")
        print(f"  2. reindex {source_count} documents into it, ids preserved")
        print("  3. verify the counts match")
        print(f"  4. DELETE the index {alias}")
        print(f"  5. create the write alias {alias} -> {target}")
        print()
        print("Stop the backend, then re-run with --apply.")
        return 0

    # The template carries the ILM settings, so this index picks them up.
    await bootstrap_es()
    await es.indices.create(index=target)
    print(f"created {target}")

    # `op_type: index` preserves ids and overwrites; the target is empty, so
    # this is a straight copy. No pipeline: the source documents were already
    # processed by it on the way in, and running it twice would re-apply the
    # rename and remove steps to fields that no longer look the same.
    result = await es.reindex(
        source={"index": alias},
        dest={"index": target, "op_type": "index"},
        refresh=True,
        wait_for_completion=True,
    )
    print(f"reindexed: created={result.get('created')} failures={len(result.get('failures', []))}")

    if result.get("failures"):
        print("REFUSING to delete anything: the reindex reported failures.")
        for failure in result["failures"][:5]:
            print(f"  {failure}")
        return 1

    await es.indices.refresh(index=target)
    target_count = (await es.count(index=target))["count"]
    if target_count != source_count:
        print(
            f"REFUSING to delete anything: {target} holds {target_count} documents "
            f"but {alias} held {source_count}. The copy is incomplete; both "
            f"indices are intact, so nothing is lost -- investigate before retrying."
        )
        return 1
    print(f"verified: {target_count} documents in {target}")

    await es.indices.delete(index=alias)
    print(f"deleted the old concrete index {alias}")

    await es.indices.put_alias(index=target, name=alias, is_write_index=True)
    print(f"created the write alias {alias} -> {target}")
    print()
    print("Done. Index lifecycle is now active; rollover happens on the policy's")
    print("thresholds and NOTHING is ever deleted by it.")
    return 0


async def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply",
        action="store_true",
        help="actually perform the migration (default is a dry run)",
    )
    args = parser.parse_args()
    try:
        return await _run(args.apply)
    finally:
        await get_es().close()


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
