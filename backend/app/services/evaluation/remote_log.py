"""Index a remote evaluation Cowrie's log, so a run can read its session back.

A local Cowrie's log reaches Elasticsearch through Filebeat within seconds.
The evaluation Cowrie on the VM has nothing carrying its log home, and the
chain read-back cannot wait for a timer, so a run fetches the log through the
gate (`wild_pull.read_live_log`) and indexes it here -- through the same
`cowrie-ecs` pipeline, as the same document Filebeat would have sent.

Every line is indexed under an id made of the honeypot, the remote file's
inode and the line's byte offset, so fetching the same bytes again creates
nothing. Ids already in the index are skipped before the bulk request: a
`create` only conflicts within one concrete index, and after an ILM rollover
the same id would otherwise be created a second time in the new one.
"""

import asyncio
import json

from app.config import EvalGate, get_settings
from app.es.client import get_es
from app.services import wild_pull


async def ingest(gate: EvalGate, honeypot_id: str) -> int:
    """Index whatever of the evaluation log is not yet indexed. Returns how many."""
    inode, data = await asyncio.to_thread(wild_pull.read_live_log, gate)
    docs: dict[str, dict] = {}
    offset = 0
    for line in data.splitlines(keepends=True):
        docs[f"{honeypot_id}:{inode}:{offset}"] = {
            "cowrie": json.loads(line),
            "honeypot": {"id": honeypot_id, "name": gate.name},
            "labels": {"seeded": False},
        }
        offset += len(line)
    if not docs:
        return 0

    index = get_settings().es_index
    es = get_es()
    seen = await es.search(
        index=index,
        query={"ids": {"values": list(docs)}},
        size=len(docs),
        source=False,
    )
    for hit in seen["hits"]["hits"]:
        docs.pop(hit["_id"], None)
    if not docs:
        return 0

    operations: list[dict] = []
    for doc_id, doc in docs.items():
        operations += [{"create": {"_index": index, "_id": doc_id}}, doc]
    result = await es.bulk(operations=operations, refresh="wait_for")
    refused = [
        item["create"]["error"]
        for item in result["items"]
        if item["create"].get("status") not in (201, 409)
    ]
    if refused:
        # Never a silent gap: a chain step whose event was refused would read
        # as a honeypot that did not record it.
        raise RuntimeError(
            f"{len(refused)} of {len(docs)} evaluation events were refused by the index, "
            f"first: {refused[0].get('reason', refused[0])}"
        )
    return len(docs)
