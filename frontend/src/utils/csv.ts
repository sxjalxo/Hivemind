/**
 * Spreadsheet applications evaluate a cell that starts with one of these as a
 * formula. Honeypot data is attacker-controlled -- a command line, a username --
 * so `=HYPERLINK(...)` typed into a decoy shell would run on whoever opens the
 * export. A leading apostrophe makes the cell literal text (OWASP's CSV
 * injection guidance).
 */
const FORMULA_TRIGGERS = /^[=+\-@\t\r]/;

function cell(value: string | number | null | undefined): string {
  if (value === null || value === undefined) return "";
  const text = typeof value === "number" ? String(value) : value;
  const safe = FORMULA_TRIGGERS.test(text) ? `'${text}` : text;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** RFC 4180 CSV, CRLF-terminated, with formula-injection neutralised. */
export function toCsv(
  header: readonly string[],
  rows: readonly (readonly (string | number | null | undefined)[])[],
): string {
  return [header, ...rows].map((row) => row.map(cell).join(",")).join("\r\n") + "\r\n";
}

/** Hands `text` to the browser as a file download. */
export function downloadText(filename: string, text: string, mime = "text/csv"): void {
  const url = URL.createObjectURL(new Blob([text], { type: `${mime};charset=utf-8` }));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}
