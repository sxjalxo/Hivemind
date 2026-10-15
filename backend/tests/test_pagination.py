"""Paging past the first screen (checklist item 18).

A caller pages by asking for the next `offset` while pages come back full. That
only works if every page is full until the last one -- a short page in the
middle reads as the end -- and if walking the pages yields exactly the list,
with nothing skipped or repeated.
"""

import httpx
import pytest

from app.main import app
from app.routers.limits import MAX_OFFSET
from app.services import analyzer


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")


async def _walk(client: httpx.AsyncClient, route: str, page: int, total: int) -> list[str]:
    # A walk that never meets a short page is a paging bug: it must fail, not
    # hang, so it gets one page more than the list can fill.
    pages = total // page + 2
    seen: list[str] = []
    offset = 0
    for _ in range(pages):
        response = await client.get(route, params={"limit": page, "offset": offset})
        assert response.status_code == 200, response.text
        items = response.json()
        seen.extend(item["id"] for item in items)
        if len(items) < page:
            return seen
        offset += page
    pytest.fail(f"{route}: still full pages after {pages}")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "route", ["/api/sessions", "/api/analysis", "/api/threat-intelligence", "/api/reports"]
)
async def test_walking_the_pages_yields_exactly_the_list(route):
    async with _client() as client:
        whole = (await client.get(route, params={"limit": 500})).json()
        walked = await _walk(client, route, page=2, total=len(whole))
    assert walked == [item["id"] for item in whole]


@pytest.mark.asyncio
async def test_a_scoped_analysis_page_is_full_until_the_last(monkeypatch):
    unscoped = await analyzer.load_history()
    if len(unscoped) < 3:
        pytest.skip("needs at least three stored analyses")
    hidden = unscoped[0].session_id

    async def owners(session_ids):
        return {s: ("hidden-sensor" if s == hidden else "cowrie-01") for s in session_ids}

    monkeypatch.setattr(analyzer, "honeypots_for_sessions", owners)
    monkeypatch.setattr(analyzer, "_SCOPE_BATCH", 3)  # several batches per page
    expected = [a.id for a in unscoped if a.session_id != hidden]

    walked: list[str] = []
    offset = 0
    for _ in range(len(expected) // 2 + 2):
        page = await analyzer.load_history(limit=2, offset=offset, deny_honeypots={"hidden-sensor"})
        walked.extend(a.id for a in page)
        if len(page) < 2:
            break
        offset += 2
    else:
        pytest.fail("still full pages past the end of the list")
    assert walked == expected


@pytest.mark.asyncio
async def test_an_offset_past_the_bound_is_refused_not_clamped():
    async with _client() as client:
        response = await client.get("/api/sessions", params={"offset": MAX_OFFSET + 1})
    assert response.status_code == 422


@pytest.mark.asyncio
async def test_a_log_page_past_the_search_window_is_a_422_not_a_500():
    async with _client() as client:
        too_deep = await client.get("/api/logs", params={"page": 21, "pageSize": 500})
        deepest = await client.get("/api/logs", params={"page": 20, "pageSize": 500})
    assert too_deep.status_code == 422
    assert str(MAX_OFFSET) in too_deep.text
    assert deepest.status_code == 200
