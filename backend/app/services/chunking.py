"""Session-level token budget and chunk-and-merge for oversized prompts.

`num_ctx` is 8192 (see `app.services.llm.ollama`), measured on this hardware:
32768 spills a chunk of the model's weights off the GPU (a 34%/66% CPU/GPU
split, ~3.5x slower per call). Compaction bounds each event's *output*
(`seed_output_head_lines` / `seed_output_tail_lines`) but never bounded the
*command* text itself, and nothing bounded the session as a whole. A session
with enough commands, or a single pathologically long command (e.g. a
base64 blob pasted at a shell prompt), can render a block that alone
exceeds the context window.

Ollama does not error when a prompt is too long for `num_ctx` -- it
silently drops earlier context and the model answers from whatever
survived. That produces a confident-looking conclusion built from partial
evidence, which is exactly the failure this module exists to prevent: a
prompt is never sent to the model unless it is known, in advance, to fit.

The fix is chunk-and-merge: never render a single block whose estimated
token count exceeds the budget. Split the oversized input into multiple
chunks that each fit, analyze every chunk in its own LLM call (still "one
context per stage" -- each call is a complete, independent context, not a
shared one), and merge the results afterward.
"""

import re
from collections.abc import Callable
from typing import TypeVar

# No tokenizer dependency: a conservative chars-per-token heuristic errs on
# the side of UNDER-estimating how much fits, which is the safe direction
# here (an over-cautious split is harmless; an under-cautious one silently
# reproduces the exact overflow this module exists to prevent).
CHARS_PER_TOKEN = 4

# Must track app.services.llm.ollama._NUM_CTX. Not imported directly to
# avoid a hard dependency between a general-purpose budgeting module and one
# LLM backend's client -- BYOK evaluators may have a different window
# entirely -- but the two are deliberately kept in sync by this comment.
NUM_CTX = 8192

# Headroom for the model's JSON response (classification, technique list,
# recommendations, ...). Generous on purpose: a truncated *response* is as
# bad as a truncated prompt.
RESPONSE_RESERVE_TOKENS = 1024

# Headroom for the prompt template itself: the fixed instructional text in
# behaviors.md / classify.md / recommend.md / mitre_gapfill.md, the untrusted
# fence markers, and the JSON schema the client sends via `format=`.
TEMPLATE_OVERHEAD_TOKENS = 600

SESSION_TOKEN_BUDGET = NUM_CTX - RESPONSE_RESERVE_TOKENS - TEMPLATE_OVERHEAD_TOKENS

# A single item (one command) is atomic -- it cannot be split across two LLM
# calls the way a *list* of commands can be regrouped into chunks. If one
# item's own rendering already exceeds the budget, the only honest options
# are to explicitly, visibly truncate its text or to refuse to analyze it;
# this bound sets how much of that one item survives before truncation
# kicks in, well under the full budget so it always leaves room for the
# session metadata (attacker_ip, login state, ...) that is rendered
# alongside it.
MAX_ITEM_CHARS = (SESSION_TOKEN_BUDGET * CHARS_PER_TOKEN) // 2

T = TypeVar("T")

# A run of three or more of the same rule-drawing character is how this
# project (and almost every other) draws a delimiter line. Neutralising the
# run rather than the literal fence strings means the defence does not have
# to be revisited if a prompt's markers are ever reworded or redrawn.
_FENCE_RUN = re.compile(r"([-=_*~#])\1{2,}")
_FENCE_MARKER = "[fence-like delimiter run neutralised]"

# Visible, counted-in-spirit marker in the style of `truncate_text`: the
# reader of the rendered prompt can see that a line break was there.
# Silently deleting the break would hide from a human auditor that the
# attacker's text was multi-line at all.
_LINE_BREAK_MARKER = " [line break] "


def flatten(text: str) -> str:
    """Reduce attacker-controlled text to a single structurally inert line.

    Every prompt in this system fences untrusted text and tells the model the
    fence contains data. A fence only contains what cannot get out of it, and
    all of these prompts are LINE-ORIENTED -- the delimiters are whole lines,
    and so is each rendered command, evidence item or citation. So text that
    may contain a line break can close the fence from the inside
    (`----- END UNTRUSTED DATA -----` on a line of its own puts everything
    after it in the prompt's TRUSTED region) or forge an extra structured
    entry under an id that really was offered, which an id-validity check
    cannot catch.

    After this, the text cannot start a line: every character it contributes
    sits on a line the caller already opened. That argument does not depend
    on what the delimiter string is, which is why it stays correct if the
    markers are reworded later.

    `str.splitlines()` is used deliberately over `text.split("\\n")`: it is
    the stdlib's own definition of a line break and covers `\\r`, `\\v`,
    `\\f`, `\\x1c`-`\\x1e`, `\\x85`, `\\u2028` and `\\u2029` as well, any one
    of which a renderer or a model may treat as ending a line.

    Runs of rule-drawing characters are neutralised first as a second layer,
    for a model that pattern-matches a delimiter mid-line rather than strictly
    per line. Nothing is silently dropped -- both substitutions leave a
    visible marker, the same honesty rule `truncate_text` follows.

    Pair it with `truncate_text`, in that order: truncation inserts its own
    omission marker on its own lines, so flattening has to come second or
    those newlines survive into the prompt.
    """
    return _LINE_BREAK_MARKER.join(_FENCE_RUN.sub(_FENCE_MARKER, text).splitlines())


def estimate_tokens(text: str) -> int:
    """A conservative, tokenizer-free estimate. Always rounds up."""
    if not text:
        return 0
    return max(1, (len(text) + CHARS_PER_TOKEN - 1) // CHARS_PER_TOKEN)


def truncate_text(text: str, max_chars: int) -> str:
    """Bound a single oversized item's text with a visible, honest marker.

    Keeps a head and a tail (like `compaction._truncate_output`) rather
    than just the head, so a payload's final action (e.g. `> payload &&
    chmod +x payload && ./payload` at the end of a long base64 blob) is
    not silently dropped. The omission is explicit and counted -- never a
    silent cut a reader could mistake for the whole command.
    """
    if len(text) <= max_chars:
        return text
    head = max_chars * 2 // 3
    tail = max_chars - head
    omitted = len(text) - head - tail
    return (
        f"{text[:head]}"
        f"\n... [{omitted} characters omitted -- oversized single command, "
        f"explicitly bounded, never silently truncated by the model's own "
        f"context window] ...\n"
        f"{text[-tail:]}"
    )


def chunk_items(
    items: list[T],
    render: Callable[[list[T]], str],
    budget_tokens: int = SESSION_TOKEN_BUDGET,
) -> list[list[T]]:
    """Greedily pack items into chunks whose rendered text fits the budget.

    `render` renders a candidate group of items exactly as it will be sent
    to the model (including whatever fixed scaffolding surrounds it), so
    the estimate reflects the real prompt, not just the items' raw text.

    Assumes no single item alone renders over budget -- callers must bound
    an individual item's size first (see `truncate_text`), since an atomic
    item cannot be split any further than that.
    """
    if not items:
        return [[]]

    chunks: list[list[T]] = []
    current: list[T] = []
    for item in items:
        trial = current + [item]
        if current and estimate_tokens(render(trial)) > budget_tokens:
            chunks.append(current)
            current = [item]
        else:
            current = trial
    if current:
        chunks.append(current)
    return chunks
