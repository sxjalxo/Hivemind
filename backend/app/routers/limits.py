"""One page-size contract, so the list endpoints cannot drift apart.

Every list route used to return its whole table. `/api/sessions` assembled one
`AttackSession` per session in the index -- two Elasticsearch round trips each,
sequentially. `/api/analysis` read every row and hydrated each one. `/api/logs`
accepted a `pageSize` with no ceiling at all. None of that needs a hostile
caller to hurt: a honeypot that has been collecting for a month simply has more
rows than one response should carry, and the cost grows with the corpus rather
than with the request.

`/api/evaluations` already bounded itself (`DEFAULT_RUN_LIMIT` /
`MAX_RUN_LIMIT`, with its own values because a run history is a different
shape). These are the same idea for the rest, kept together so the ceiling is
one reviewable decision instead of four independent guesses.

The ceiling is enforced by FastAPI (`Query(..., ge=1, le=MAX_PAGE_LIMIT)`), so
an over-large request is a 422 naming the bound -- not silently clamped, which
would hand back a short page that looks complete.

**The services keep an unbounded default on purpose.** Only the HTTP boundary
caps; internal callers do not. `create_report` reads every indicator and keeps
one session's worth, so a cap inside `list_indicators` would quietly drop
evidence from a report rather than paginate a screen.
"""

# What a first screen shows.
DEFAULT_PAGE_LIMIT = 100

# What one response may ever carry.
MAX_PAGE_LIMIT = 500
