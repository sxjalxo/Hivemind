import { TIME_RANGES, useTimeRange } from "@/hooks/useTimeRange";
import { cn } from "@/lib/utils";

/** The dashboard's window: the only page that reads the shared time range. */
export function TimeRangeTabs({ className }: { className?: string }) {
  const { range, setRange } = useTimeRange();
  return (
    <div
      className={cn(
        "flex items-center gap-0.5 rounded-md border border-border bg-surface p-0.5",
        className,
      )}
    >
      {TIME_RANGES.map((item) => (
        <button
          key={item.id}
          type="button"
          onClick={() => setRange(item.id)}
          aria-pressed={range === item.id}
          title={item.label}
          className={cn(
            "rounded px-2 py-1 font-mono text-[11px] transition-colors",
            range === item.id
              ? "bg-accent text-foreground"
              : "text-muted-foreground hover:text-foreground",
          )}
        >
          {item.short}
        </button>
      ))}
    </div>
  );
}
