import { useQuery } from "@tanstack/react-query";
import { StatusRow } from "@/components/common";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";
import { systemStatusQuery } from "@/services/queries";

/**
 * System health block. States come from GET /api/status via the active
 * provider — nothing here is hardcoded to "connected".
 */
export function SystemStatusPanel({ className }: { className?: string }) {
  const { data, isPending, isError } = useQuery(systemStatusQuery());

  return (
    <div className={cn("space-y-1", className)}>
      <p className="label-caps px-1 pb-1">System status</p>
      {isPending ? (
        <div className="space-y-2 px-1 py-1">
          {Array.from({ length: 4 }, (_, i) => (
            <Skeleton key={i} className="h-3 w-full" />
          ))}
        </div>
      ) : isError ? (
        <StatusRow
          status={{ id: "api", name: "API", state: "disconnected", detail: "Unreachable" }}
          dense
          className="px-1"
        />
      ) : (
        data.map((status) => <StatusRow key={status.id} status={status} dense className="px-1" />)
      )}
    </div>
  );
}
