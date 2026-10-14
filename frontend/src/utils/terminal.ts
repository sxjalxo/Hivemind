// Escape sequences: CSI (colours, cursor moves), OSC (window titles), and any
// other two-byte escape. "Erase to end of line" is kept as a marker because
// shells send it after a backspace; dropping it would leave deleted characters
// on screen.
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const ANSI = /\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-_]/g;
const ERASE_LINE = "\u0001";

/**
 * Terminal output as plain text: carriage returns, backspaces and line erases
 * applied, every other escape sequence dropped. Colour and full-screen
 * programs (vi, top) are not reproduced -- this is a transcript, not an
 * emulator.
 */
export function renderTerminal(raw: string): string {
  let line: string[] = [];
  const lines = [line];
  let col = 0;
  const text = raw.replace(ANSI, (seq) =>
    seq === "\x1b[K" || seq === "\x1b[0K" ? ERASE_LINE : "",
  );
  for (const ch of text) {
    if (ch === "\n") {
      line = [];
      lines.push(line);
      col = 0;
    } else if (ch === "\r") col = 0;
    else if (ch === "\b") col = Math.max(0, col - 1);
    else if (ch === ERASE_LINE) line.length = col;
    else if (ch >= " " || ch === "\t") {
      line[col] = ch;
      col += 1;
    }
  }
  return lines.map((l) => l.join("")).join("\n");
}

/** Pauses longer than this are shortened to it, as `playlog -m` does. */
export const MAX_PAUSE_S = 2;

/** Each frame's time on a timeline whose idle gaps are capped at MAX_PAUSE_S. */
export function compressTimeline(times: number[]): number[] {
  const out: number[] = [];
  let prev = 0;
  let at = 0;
  for (const t of times) {
    at += Math.min(t - prev, MAX_PAUSE_S);
    prev = t;
    out.push(at);
  }
  return out;
}
