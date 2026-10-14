import { useQuery } from "@tanstack/react-query";
import { Pause, Play, RotateCcw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { EmptyState, InlineNotice, Panel, ProvenanceBadge } from "@/components/common";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { sessionQueries } from "@/services/queries";
import { MAX_PAUSE_S, compressTimeline, renderTerminal } from "@/utils/terminal";

const TICK_MS = 100;
const SPEEDS = [1, 2, 4, 8];

const UNAVAILABLE: Record<string, string> = {
  not_configured:
    "This backend cannot see the honeypot's TTY recordings (COWRIE_TTY_PATH is unset).",
  no_recording:
    "No recording for this session. Recording was off when it happened, or it has not closed yet.",
  missing: "The recording for this session is no longer on disk.",
};

/** Cowrie's TTY recording of the session, played back as plain text. */
export function SessionReplay({ sessionId }: { sessionId: string }) {
  const replay = useQuery(sessionQueries.replay(sessionId));
  const frames = useMemo(() => replay.data?.frames ?? [], [replay.data]);
  const times = useMemo(() => compressTimeline(frames.map((f) => f.t)), [frames]);
  const duration = times.at(-1) ?? 0;

  const [position, setPosition] = useState(0);
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState(1);

  useEffect(() => {
    if (!playing) return;
    const timer = setInterval(() => {
      setPosition((p) => {
        const next = p + (TICK_MS / 1000) * speed;
        if (next >= duration) setPlaying(false);
        return Math.min(next, duration);
      });
    }, TICK_MS);
    return () => clearInterval(timer);
  }, [playing, speed, duration]);

  const shown = times.filter((t) => t <= position).length;
  const screen = useMemo(
    () =>
      renderTerminal(
        frames
          .slice(0, shown)
          .map((f) => f.data)
          .join(""),
      ),
    [frames, shown],
  );

  // Keep the newest output in view, as a terminal does.
  const screenRef = useRef<HTMLPreElement>(null);
  useEffect(() => {
    const el = screenRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [screen]);

  let body: React.ReactNode;
  if (replay.isPending) body = <Skeleton className="h-[240px] w-full" />;
  else if (replay.isError) body = <EmptyState title="The replay could not be loaded." />;
  else if (replay.data.status !== "ok" || frames.length === 0)
    body = (
      <EmptyState
        title={UNAVAILABLE[replay.data.status] ?? "The recording holds no terminal output."}
      />
    );
  else
    body = (
      <div className="space-y-3">
        {replay.data.shared && (
          <InlineNotice tone="warn">
            Cowrie keeps one recording per distinct keystroke sequence, and this one was opened
            outside this session: another session typed exactly the same input. The output shown is
            that session&apos;s and may differ from what this one saw.
          </InlineNotice>
        )}
        {replay.data.truncated && (
          <InlineNotice tone="info">
            The recording is long; only its beginning is shown.
          </InlineNotice>
        )}
        <pre
          ref={screenRef}
          className="h-[320px] overflow-auto rounded-md bg-black p-3 font-mono text-[12px] leading-relaxed whitespace-pre-wrap text-green-300"
        >
          {screen}
        </pre>
        <div className="flex flex-wrap items-center gap-3">
          <Button
            size="sm"
            variant="outline"
            aria-label={playing ? "Pause replay" : "Play replay"}
            onClick={() => {
              if (!playing && position >= duration) setPosition(0);
              setPlaying(!playing);
            }}
          >
            {playing ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            aria-label="Restart replay"
            onClick={() => {
              setPlaying(false);
              setPosition(0);
            }}
          >
            <RotateCcw className="h-4 w-4" />
          </Button>
          <input
            type="range"
            aria-label="Replay position"
            className="min-w-[160px] flex-1"
            min={0}
            max={duration}
            step={0.1}
            value={position}
            onChange={(e) => setPosition(Number(e.target.value))}
          />
          <span className="font-mono text-xs text-muted-foreground tabular-nums">
            {position.toFixed(1)} / {duration.toFixed(1)} s
          </span>
          <select
            aria-label="Replay speed"
            className="rounded border bg-background px-1 py-0.5 text-xs"
            value={speed}
            onChange={(e) => setSpeed(Number(e.target.value))}
          >
            {SPEEDS.map((s) => (
              <option key={s} value={s}>
                {s}×
              </option>
            ))}
          </select>
        </div>
      </div>
    );

  return (
    <Panel
      title="Terminal Replay"
      description={`What the attacker's terminal showed, as Cowrie recorded it. Plain text: colours are dropped, and pauses over ${MAX_PAUSE_S} s are shortened.`}
      actions={<ProvenanceBadge kind="OBSERVED" />}
    >
      {body}
    </Panel>
  );
}
