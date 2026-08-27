import { CalendarClock } from "lucide-react";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { TIME_RANGES, useTimeRange, type TimeRangeId } from "@/hooks/useTimeRange";
import { cn } from "@/lib/utils";

export function TimeRangeSelector({ className }: { className?: string }) {
  const { range, setRange } = useTimeRange();

  return (
    <Select value={range} onValueChange={(value) => setRange(value as TimeRangeId)}>
      <SelectTrigger
        className={cn("h-8 w-[168px] border-border bg-surface text-xs", className)}
        aria-label="Time range"
      >
        <CalendarClock className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {TIME_RANGES.map((item) => (
          <SelectItem key={item.id} value={item.id} className="text-xs">
            {item.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

/** Inline segmented variant used inside chart headers. */
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
