import { formatNumber } from "@/utils/format";

export interface TooltipRow {
  label: string;
  value: number;
  color?: string;
  suffix?: string;
}

/**
 * Shared tooltip surface. Values wear text tokens; the swatch beside them is
 * the only thing carrying series colour.
 */
export function ChartTooltipCard({
  title,
  rows,
  footer,
}: {
  title: string;
  rows: TooltipRow[];
  footer?: string;
}) {
  return (
    <div className="pointer-events-none min-w-[172px] rounded-md border border-border-strong bg-popover px-3 py-2 shadow-lg">
      <p className="font-mono text-[11px] uppercase tracking-[0.08em] text-muted-foreground">
        {title}
      </p>
      <div className="mt-1.5 space-y-1">
        {rows.map((row) => (
          <div key={row.label} className="flex items-center gap-2">
            {row.color ? (
              <span
                className="size-2 shrink-0 rounded-[2px]"
                style={{ backgroundColor: row.color }}
                aria-hidden
              />
            ) : null}
            <span className="min-w-0 flex-1 truncate text-xs text-foreground/80">{row.label}</span>
            <span className="font-mono text-xs font-semibold tabular-nums text-foreground">
              {formatNumber(row.value)}
              {row.suffix ?? ""}
            </span>
          </div>
        ))}
      </div>
      {footer ? (
        <p className="mt-1.5 border-t border-border pt-1.5 text-[11px] text-muted-foreground">
          {footer}
        </p>
      ) : null}
    </div>
  );
}

/** Legend swatch + label + value, used where a chart needs identity off-colour. */
export function LegendRow({
  color,
  label,
  value,
  share,
  muted = false,
  onClick,
}: {
  color: string;
  label: string;
  value: number;
  share?: number;
  muted?: boolean;
  onClick?: () => void;
}) {
  const Wrapper = onClick ? "button" : "div";
  return (
    <Wrapper
      {...(onClick ? { type: "button" as const, onClick } : {})}
      className="flex w-full items-center gap-2 rounded px-1 py-[3px] text-left transition-colors hover:bg-accent/40"
    >
      <span
        className="size-2 shrink-0 rounded-[2px]"
        style={{ backgroundColor: color }}
        aria-hidden
      />
      <span
        className={`min-w-0 flex-1 truncate text-xs ${muted ? "text-muted-foreground" : "text-foreground/85"}`}
      >
        {label}
      </span>
      {/* Numbers stay unwrapped but claim no fixed width, so the label keeps
          whatever room is left rather than truncating behind a reserved column. */}
      <span className="shrink-0 whitespace-nowrap font-mono text-xs tabular-nums text-foreground">
        {formatNumber(value)}
      </span>
      {share !== undefined ? (
        <span className="shrink-0 whitespace-nowrap font-mono text-[11px] tabular-nums text-muted-foreground">
          {share.toFixed(1)}%
        </span>
      ) : null}
    </Wrapper>
  );
}
