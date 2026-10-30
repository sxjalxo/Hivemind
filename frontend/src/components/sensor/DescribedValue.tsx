import type { Described } from "@/types";

const SOURCE_LABEL: Record<Described["source"], string> = {
  observed: "observed",
  persona: "from persona",
  evaluation: "from evaluation",
  unknown: "unknown",
};

/** A derived value with its source as a small muted label. "unknown" is said once. */
export function DescribedValue({ item }: { item: Described }) {
  if (item.source === "unknown") {
    return <span className="text-muted-foreground">{item.value}</span>;
  }
  return (
    <span>
      {item.value}{" "}
      <span className="font-mono text-[10px] text-muted-foreground">
        {SOURCE_LABEL[item.source]}
      </span>
    </span>
  );
}
