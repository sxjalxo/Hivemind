import { Check, Copy } from "lucide-react";
import { useState } from "react";
import { cn } from "@/lib/utils";
import { copyToClipboard } from "@/utils/format";

/** Monospace treatment for telemetry values: IPs, hashes, commands, session IDs. */
export function Mono({
  children,
  className,
  tone = "default",
}: {
  children: React.ReactNode;
  className?: string | undefined;
  tone?: "default" | "muted" | "accent" | undefined;
}) {
  return (
    <span
      className={cn(
        "font-mono text-[13px] tabular-nums",
        tone === "muted" && "text-muted-foreground",
        tone === "accent" && "text-primary",
        className,
      )}
    >
      {children}
    </span>
  );
}

export function CopyButton({
  value,
  label = "Copy",
  className,
}: {
  value: string;
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);

  return (
    <button
      type="button"
      aria-label={`${label} ${value}`}
      title={`${label} to clipboard`}
      onClick={async (event) => {
        event.stopPropagation();
        if (await copyToClipboard(value)) {
          setCopied(true);
          window.setTimeout(() => setCopied(false), 1200);
        }
      }}
      className={cn(
        "inline-flex size-6 shrink-0 items-center justify-center rounded text-muted-foreground transition-colors hover:bg-accent hover:text-foreground",
        className,
      )}
    >
      {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
    </button>
  );
}

/** Monospace value with an inline copy affordance — used across tables and detail panels. */
export function CopyableMono({
  value,
  className,
  tone,
}: {
  value: string;
  className?: string | undefined;
  tone?: "default" | "muted" | "accent" | undefined;
}) {
  return (
    <span className="group/copy inline-flex items-center gap-1">
      <Mono className={className} {...(tone ? { tone } : {})}>
        {value}
      </Mono>
      <CopyButton
        value={value}
        className="opacity-0 group-hover/copy:opacity-100 focus:opacity-100"
      />
    </span>
  );
}
