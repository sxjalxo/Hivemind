import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { PenLine, X } from "lucide-react";
import { useState } from "react";
import { InlineNotice, Mono, Panel } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useAdminForHoneypot } from "@/hooks/useAdminFor";
import { ApiError, provider } from "@/services";
import { sessionQueries } from "@/services/queries";
import { formatDateTime } from "@/utils/format";
import type { Annotation } from "@/types";

/** The backend's own reason when it gave one: "a tag is 1-40 characters of ..." beats "422". */
function failureText(error: unknown): string {
  if (error instanceof ApiError) {
    const detail = (error.body as { detail?: unknown } | undefined)?.detail;
    if (typeof detail === "string") return detail;
  }
  return error instanceof Error ? error.message : "The change was not saved.";
}

/** Who wrote it, without pretending an open deployment knows. */
function authorText(a: Annotation): string {
  if (a.authorLabel) return a.authorLabel;
  if (a.author === "unauthenticated") return "unattributed (authentication off)";
  return a.author;
}

/**
 * Analyst tags and notes: what a PERSON concluded about this session.
 *
 * Labelled ANALYST and kept visually apart from the AI analysis and the
 * evidence, because it is a third kind of statement -- neither recorded
 * telemetry nor model output -- and must never be read as either.
 */
export function AnnotationsPanel({
  sessionId,
  honeypotId,
}: {
  sessionId: string;
  honeypotId: string;
}) {
  const queryClient = useQueryClient();
  const { data, isError } = useQuery(sessionQueries.annotations(sessionId));
  const canEdit = useAdminForHoneypot(honeypotId);
  const [tag, setTag] = useState("");
  const [note, setNote] = useState("");

  const refresh = () =>
    void queryClient.invalidateQueries({ queryKey: ["session-annotations", sessionId] });
  const add = useMutation({
    mutationFn: ({ kind, body }: { kind: "tag" | "note"; body: string }) =>
      provider.addAnnotation(sessionId, kind, body),
    onSuccess: (_, { kind }) => {
      if (kind === "tag") setTag("");
      else setNote("");
      refresh();
    },
  });
  const remove = useMutation({
    mutationFn: (id: string) => provider.deleteAnnotation(sessionId, id),
    onSuccess: refresh,
  });

  const tags = (data ?? []).filter((a) => a.kind === "tag");
  const notes = (data ?? []).filter((a) => a.kind === "note");
  const failure = add.error ?? remove.error;

  return (
    <Panel
      title="Analyst notes"
      description="What a person concluded about this session. Not telemetry, not model output."
      actions={
        <span className="inline-flex items-center gap-1.5 rounded border border-border-strong bg-muted/60 px-1.5 py-[3px] font-mono text-[10px] font-semibold uppercase tracking-[0.08em] text-muted-foreground">
          <PenLine className="size-3" aria-hidden />
          Analyst
        </span>
      }
    >
      {isError ? (
        <InlineNotice tone="critical">Notes could not be read.</InlineNotice>
      ) : (
        <div className="space-y-4">
          <div className="flex flex-wrap items-center gap-1.5">
            {tags.length === 0 ? (
              <span className="text-xs text-muted-foreground">No tags.</span>
            ) : null}
            {tags.map((t) => (
              <span
                key={t.id}
                title={`Tagged by ${authorText(t)}, ${formatDateTime(t.createdAt)}`}
                className="inline-flex items-center rounded border border-border bg-background/40 font-mono text-[11px]"
              >
                <span className="px-2 py-0.5">{t.body}</span>
                {canEdit.allowed ? (
                  <button
                    type="button"
                    onClick={() => remove.mutate(t.id)}
                    className="border-l border-border px-1 py-0.5 text-muted-foreground hover:text-foreground"
                    aria-label={`Remove tag ${t.body}`}
                  >
                    <X className="size-3" />
                  </button>
                ) : null}
              </span>
            ))}
            {canEdit.allowed ? (
              <form
                className="inline-flex items-center gap-1.5"
                onSubmit={(e) => {
                  e.preventDefault();
                  if (tag.trim()) add.mutate({ kind: "tag", body: tag });
                }}
              >
                <Input
                  value={tag}
                  onChange={(e) => setTag(e.target.value)}
                  placeholder="add tag"
                  className="h-7 w-32 font-mono text-xs"
                  aria-label="New tag"
                />
              </form>
            ) : null}
          </div>

          {notes.length > 0 ? (
            <ul className="space-y-2">
              {notes.map((n) => (
                <li key={n.id} className="rounded-md border border-border bg-background/40 p-2.5">
                  <p className="whitespace-pre-wrap text-sm text-foreground">{n.body}</p>
                  <div className="mt-1.5 flex items-center gap-2">
                    <Mono tone="muted" className="text-[11px]">
                      {authorText(n)} · {formatDateTime(n.createdAt)}
                    </Mono>
                    {canEdit.allowed ? (
                      <button
                        type="button"
                        onClick={() => remove.mutate(n.id)}
                        className="ml-auto font-mono text-[10px] uppercase tracking-[0.08em] text-muted-foreground hover:text-foreground"
                      >
                        Delete
                      </button>
                    ) : null}
                  </div>
                </li>
              ))}
            </ul>
          ) : null}

          {canEdit.allowed ? (
            <form
              className="space-y-2"
              onSubmit={(e) => {
                e.preventDefault();
                if (note.trim()) add.mutate({ kind: "note", body: note });
              }}
            >
              <textarea
                value={note}
                onChange={(e) => setNote(e.target.value)}
                maxLength={2000}
                rows={2}
                placeholder="Add a note for whoever looks at this session next"
                className="w-full resize-y rounded-md border border-input bg-transparent px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
                aria-label="New note"
              />
              <Button
                type="submit"
                size="sm"
                className="h-7"
                disabled={!note.trim() || add.isPending}
              >
                Add note
              </Button>
            </form>
          ) : (
            <p className="text-xs text-muted-foreground">{canEdit.title}</p>
          )}

          {failure ? <InlineNotice tone="critical">{failureText(failure)}</InlineNotice> : null}
        </div>
      )}
    </Panel>
  );
}
