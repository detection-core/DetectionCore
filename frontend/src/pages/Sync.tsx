import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { RefreshCw, CheckCircle2, XCircle, Clock } from "lucide-react";
import { getSyncJobs, getSyncStatus, triggerSync } from "@/api/endpoints";
import { formatDate } from "@/lib/utils";

export default function Sync() {
  const qc = useQueryClient();

  const { data: status } = useQuery({
    queryKey: ["sync-status"],
    queryFn: () => getSyncStatus().then((r) => r.data.data),
    refetchInterval: 10_000,
  });

  const { data: jobs, isLoading } = useQuery({
    queryKey: ["sync-jobs"],
    queryFn: () => getSyncJobs().then((r) => r.data.data),
    refetchInterval: 5_000,
  });

  const triggerMut = useMutation({
    mutationFn: triggerSync,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sync-jobs"] });
      qc.invalidateQueries({ queryKey: ["sync-status"] });
    },
  });

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Sync Status</h1>
          <p className="text-sm text-muted-foreground">DetectionHub synchronization history</p>
        </div>
        <button
          onClick={() => triggerMut.mutate()}
          disabled={triggerMut.isPending}
          className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${triggerMut.isPending ? "animate-spin" : ""}`} />
          Sync Now
        </button>
      </div>

      {/* Config */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Schedule", value: status?.sync_cron ?? "—" },
          { label: "Auto-sync", value: status?.sync_enabled ? "Enabled" : "Disabled" },
          { label: "Last Sync", value: status?.last_sync ? formatDate(status.last_sync) : "Never" },
          { label: "Last Status", value: status?.last_status ?? "—" },
        ].map(({ label, value }) => (
          <div key={label} className="bg-card rounded-xl border border-border p-4">
            <p className="text-xs text-muted-foreground">{label}</p>
            <p className="text-sm font-medium text-foreground mt-1">{value}</p>
          </div>
        ))}
      </div>

      {/* Jobs Table */}
      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <div className="px-5 py-3 border-b border-border">
          <h2 className="font-medium text-foreground">Job History</h2>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Trigger</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Pulled</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">New</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Updated</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Skipped</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Started</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {isLoading ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">Loading...</td></tr>
            ) : (jobs ?? []).length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">No sync jobs yet. Click "Sync Now" to start.</td></tr>
            ) : (
              (jobs ?? []).map((job: {
                id: string; status: string; triggered_by: string;
                rules_pulled: number; rules_new: number; rules_updated: number; rules_skipped: number;
                errors: string[]; started_at: string;
              }) => (
                <tr key={job.id} className="hover:bg-secondary/30 transition-colors">
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      {job.status === "completed" && <CheckCircle2 className="w-4 h-4 text-green-400" />}
                      {job.status === "failed" && <XCircle className="w-4 h-4 text-red-400" />}
                      {job.status === "running" && <RefreshCw className="w-4 h-4 text-yellow-400 animate-spin" />}
                      <span className={
                        job.status === "completed" ? "text-green-400"
                        : job.status === "failed" ? "text-red-400"
                        : "text-yellow-400"
                      }>{job.status}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{job.triggered_by}</td>
                  <td className="px-4 py-3 text-foreground">{job.rules_pulled}</td>
                  <td className="px-4 py-3 text-green-400">{job.rules_new}</td>
                  <td className="px-4 py-3 text-cyan-400">{job.rules_updated}</td>
                  <td className="px-4 py-3 text-muted-foreground">{job.rules_skipped}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(job.started_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
