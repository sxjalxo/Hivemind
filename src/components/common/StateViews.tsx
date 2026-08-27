import { AlertTriangle, Inbox, Loader2, RefreshCw, ServerCrash } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export function LoadingState({
  message = "Loading honeypot telemetry...",
  className,
}: {
  message?: string;
  className?: string;
}) {
  return (
    <div
      role="status"
      className={cn(
        "flex flex-col items-center justify-center gap-3 px-6 py-14 text-center",
        className,
      )}
    >
      <Loader2 className="size-5 animate-spin text-primary" aria-hidden />
      <p className="font-mono text-xs uppercase tracking-[0.08em] text-muted-foreground">
        {message}
      </p>
    </div>
  );
}

export function EmptyState({
  title,
  description,
  icon: Icon = Inbox,
  action,
  className,
}: {
  title: string;
  description?: string;
  icon?: typeof Inbox;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-3 px-6 py-14 text-center",
        className,
      )}
    >
      <span className="flex size-10 items-center justify-center rounded-lg border border-border bg-muted/40">
        <Icon className="size-4 text-muted-foreground" aria-hidden />
      </span>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        {description ? (
          <p className="mx-auto max-w-md text-xs text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {action}
    </div>
  );
}

export function ErrorState({
  title = "Something went wrong",
  description,
  error,
  onRetry,
  className,
}: {
  title?: string;
  description?: string;
  error?: unknown;
  onRetry?: () => void;
  className?: string;
}) {
  const detail =
    description ?? (error instanceof Error ? error.message : "An unexpected error occurred.");

  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-3 px-6 py-14 text-center",
        className,
      )}
    >
      <span className="flex size-10 items-center justify-center rounded-lg border border-critical/40 bg-critical/10">
        <ServerCrash className="size-4 text-critical" aria-hidden />
      </span>
      <div className="space-y-1">
        <p className="text-sm font-medium text-foreground">{title}</p>
        <p className="mx-auto max-w-md font-mono text-xs text-muted-foreground">{detail}</p>
      </div>
      {onRetry ? (
        <Button variant="outline" size="sm" onClick={onRetry}>
          <RefreshCw className="size-3.5" />
          Retry
        </Button>
      ) : null}
    </div>
  );
}

/** Dependency-specific errors the spec calls out by name. */
export const SERVICE_ERRORS = {
  ai: {
    title: "AI analysis unavailable",
    description: "Verify that the Ollama/LLM service is running and reachable from the backend.",
  },
  elasticsearch: {
    title: "Elasticsearch connection unavailable",
    description: "The backend could not reach the Elasticsearch cluster holding honeypot events.",
  },
  api: {
    title: "Backend unavailable",
    description: "The FastAPI service did not respond. Check VITE_API_BASE_URL and the API host.",
  },
} as const;

export function InlineNotice({
  tone = "info",
  icon: Icon = AlertTriangle,
  children,
  className,
}: {
  tone?: "info" | "warn" | "critical" | "ai";
  icon?: typeof AlertTriangle;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-start gap-2.5 rounded-md border px-3 py-2.5 text-xs leading-relaxed",
        tone === "info" && "border-info/30 bg-info/8 text-info",
        tone === "warn" && "border-medium/30 bg-medium/8 text-medium",
        tone === "critical" && "border-critical/30 bg-critical/8 text-critical",
        tone === "ai" && "border-ai/30 bg-ai/8 text-ai",
        className,
      )}
    >
      <Icon className="mt-px size-3.5 shrink-0" aria-hidden />
      <div className="min-w-0 flex-1 text-foreground/85">{children}</div>
    </div>
  );
}

export function TableSkeleton({ rows = 6, cols = 5 }: { rows?: number; cols?: number }) {
  return (
    <div className="space-y-2 p-4">
      {Array.from({ length: rows }, (_, rowIndex) => (
        <div key={rowIndex} className="flex gap-3">
          {Array.from({ length: cols }, (_, colIndex) => (
            <Skeleton
              key={colIndex}
              className={cn("h-6 flex-1", colIndex === 0 && "max-w-[160px]")}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
