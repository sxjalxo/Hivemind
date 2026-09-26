import { FileCode2, Settings2, Wrench, XCircle } from "lucide-react";
import { CopyButton, Mono } from "@/components/common";
import type { EvaluationRemediation } from "@/types";

/**
 * The fix for one finding, or the reason there is not one.
 *
 * Rendered beneath the finding it belongs to rather than in a panel of its
 * own, because a patch read away from the defect it repairs is a patch
 * applied without reading the defect.
 *
 * Two things here are deliberate and load-bearing:
 *
 * A REFUSAL IS RENDERED, not hidden. The backend returns an entry for every
 * finding including those nothing can mechanically fix, and dropping those
 * from the UI would let a reader who applied everything on screen believe
 * they had addressed the whole run. So a refusal gets the same visual weight
 * as a patch and states its own reason.
 *
 * A TEMPLATE SAYS SO. `fromTemplate` marks content that is a reviewed
 * starting point rather than a value derived from this run's own evidence --
 * nobody can recover the accounts an emptied /etc/passwd should hold from the
 * fact that it is empty. Applying a template is a claim about the honeypot;
 * applying a derived value is not, and the badge is what tells them apart
 * before it is pasted into a decoy.
 */
export function RemediationPatch({ remediation }: { remediation: EvaluationRemediation }) {
  if (!remediation.isActionable) {
    return (
      <div className="mt-2.5 rounded border border-border/70 border-l-2 border-l-muted-foreground/40 bg-background/50 px-2.5 py-2">
        <p className="label-caps mb-1 flex items-center gap-1.5">
          <XCircle className="size-3 text-muted-foreground" aria-hidden />
          No automated fix
        </p>
        <p className="text-xs leading-relaxed text-foreground/80">{remediation.summary}</p>
        {remediation.unsupportedReason ? (
          <p className="mt-1 text-[11px] leading-relaxed text-muted-foreground">
            {remediation.unsupportedReason}
          </p>
        ) : null}
      </div>
    );
  }

  return (
    <div className="mt-2.5 rounded border border-border/70 border-l-2 border-l-success/60 bg-background/50 px-2.5 py-2">
      <p className="label-caps mb-1 flex flex-wrap items-center gap-1.5">
        <Wrench className="size-3 text-success" aria-hidden />
        Suggested fix
        {remediation.fromTemplate ? (
          <span
            className="rounded-sm border border-border px-1 py-px font-mono text-[9px] font-normal uppercase tracking-[0.06em] text-muted-foreground"
            title="A reviewed starting point, not a value measured from this run. Read it before applying it."
          >
            template
          </span>
        ) : (
          <span
            className="rounded-sm border border-border px-1 py-px font-mono text-[9px] font-normal uppercase tracking-[0.06em] text-muted-foreground"
            title="Derived from this run's own evidence — the value the honeypot itself reported."
          >
            derived
          </span>
        )}
      </p>
      <p className="text-xs leading-relaxed text-foreground/80">{remediation.summary}</p>

      {remediation.honeyfsFiles.map((file) => (
        <div key={file.path} className="mt-2">
          <div className="flex items-center gap-1.5">
            <FileCode2 className="size-3 shrink-0 text-muted-foreground" aria-hidden />
            <Mono className="min-w-0 flex-1 truncate text-[11px]">honeyfs/{file.path}</Mono>
            <CopyButton value={file.content} label={`Copy contents of ${file.path}`} />
          </div>
          <pre className="mt-1 max-h-56 overflow-auto rounded bg-background/70 p-2 font-mono text-[11px] leading-relaxed text-foreground/90">
            {file.content}
          </pre>
        </div>
      ))}

      {remediation.configSettings.length > 0 ? (
        <div className="mt-2">
          <p className="label-caps mb-1 flex items-center gap-1.5">
            <Settings2 className="size-3 text-muted-foreground" aria-hidden />
            cowrie.cfg
          </p>
          <ul className="space-y-1">
            {remediation.configSettings.map((setting) => (
              <li
                key={`${setting.section}.${setting.option}`}
                className="flex items-center gap-1.5"
              >
                <Mono className="min-w-0 flex-1 truncate text-[11px]">
                  [{setting.section}] {setting.option} = {setting.value}
                </Mono>
                <CopyButton
                  value={`[${setting.section}]\n${setting.option} = ${setting.value}`}
                  label={`Copy ${setting.option}`}
                />
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {remediation.honeyfsFiles.length > 0 ? (
        <p className="mt-2 text-[11px] leading-relaxed text-muted-foreground">
          Place these under the directory this honeypot&rsquo;s{" "}
          <Mono tone="muted" className="text-[10px]">
            contents_path
          </Mono>{" "}
          points at, then restart the decoy — and its capture sidecar with it, which shares its
          network namespace and is left attached to the old one otherwise.
        </p>
      ) : null}
    </div>
  );
}
