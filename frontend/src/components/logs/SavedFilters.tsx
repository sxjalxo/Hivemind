import { Bookmark, X } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

// Per-browser, like the notables "seen" mark: a saved view is the viewer's own
// convenience, not shared state. Storage can be unavailable (private windows,
// blocked site data); saving then lasts for this page only.
const KEY = "hivemind.logs.savedFilters";

export type FilterSearch = Record<string, string | number | undefined>;

interface SavedView {
  name: string;
  search: FilterSearch;
}

function load(): SavedView[] {
  try {
    const parsed: unknown = JSON.parse(window.localStorage.getItem(KEY) ?? "[]");
    return Array.isArray(parsed) ? (parsed as SavedView[]) : [];
  } catch {
    return [];
  }
}

function store(views: SavedView[]) {
  try {
    window.localStorage.setItem(KEY, JSON.stringify(views));
  } catch {
    // Kept in memory for this page; nothing else to do.
  }
}

/**
 * Named Log Explorer filter sets. A view is the URL's search params minus the
 * page number, so applying one is the same navigation a shared link performs.
 */
export function SavedFilters({
  current,
  onApply,
}: {
  current: FilterSearch;
  onApply: (search: FilterSearch) => void;
}) {
  const [views, setViews] = useState<SavedView[]>(load);
  const [naming, setNaming] = useState(false);
  const [name, setName] = useState("");

  const { page: _page, ...filters } = current;
  const active = Object.values(filters).some((v) => v !== undefined && v !== "");

  const update = (next: SavedView[]) => {
    setViews(next);
    store(next);
  };

  const save = () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    update([...views.filter((v) => v.name !== trimmed), { name: trimmed, search: filters }]);
    setName("");
    setNaming(false);
  };

  if (views.length === 0 && !active) return null;

  return (
    <div className="mt-2.5 flex flex-wrap items-center gap-1.5">
      <Bookmark className="size-3.5 text-muted-foreground" aria-hidden />
      {views.map((view) => (
        <span
          key={view.name}
          className="inline-flex items-center rounded border border-border bg-background/40 text-[11px]"
        >
          <button
            type="button"
            onClick={() => onApply(view.search)}
            className="px-2 py-0.5 font-mono hover:text-primary"
          >
            {view.name}
          </button>
          <button
            type="button"
            onClick={() => update(views.filter((v) => v.name !== view.name))}
            className="border-l border-border px-1 py-0.5 text-muted-foreground hover:text-foreground"
            aria-label={`Delete saved view ${view.name}`}
          >
            <X className="size-3" />
          </button>
        </span>
      ))}
      {active && !naming ? (
        <button
          type="button"
          onClick={() => setNaming(true)}
          className="font-mono text-[11px] uppercase tracking-[0.08em] text-primary hover:underline"
        >
          Save view
        </button>
      ) : null}
      {naming ? (
        <span className="inline-flex items-center gap-1.5">
          <Input
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                e.preventDefault(); // inside the search form: do not submit it
                save();
              }
              if (e.key === "Escape") setNaming(false);
            }}
            placeholder="View name"
            className="h-7 w-40 text-xs"
            aria-label="Saved view name"
          />
          <Button type="button" size="sm" className="h-7" onClick={save} disabled={!name.trim()}>
            Save
          </Button>
        </span>
      ) : null}
    </div>
  );
}
