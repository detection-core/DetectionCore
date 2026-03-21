import { useQuery } from "@tanstack/react-query";
import { Zap, CheckCircle2, XCircle, Database } from "lucide-react";
import { getElkStatus, getElkIndices } from "@/api/endpoints";

export default function ElkPage() {
  const { data: status, isLoading: statusLoading } = useQuery({
    queryKey: ["elk-status"],
    queryFn: () => getElkStatus().then((r) => r.data.data),
    refetchInterval: 30_000,
  });

  const { data: indices, isLoading: indicesLoading } = useQuery({
    queryKey: ["elk-indices"],
    queryFn: () => getElkIndices().then((r) => r.data.data),
    enabled: status?.connected,
  });

  return (
    <div className="p-6 space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-foreground">ELK Integration</h1>
        <p className="text-sm text-muted-foreground">Elasticsearch connection and index overview</p>
      </div>

      {/* Connection Status */}
      <div className="bg-card rounded-xl border border-border p-5">
        <div className="flex items-center gap-3">
          <div className={`p-3 rounded-xl ${status?.connected ? "bg-green-500/10" : "bg-red-500/10"}`}>
            <Zap className={`w-6 h-6 ${status?.connected ? "text-green-400" : "text-red-400"}`} />
          </div>
          <div>
            <div className="flex items-center gap-2">
              {status?.connected
                ? <CheckCircle2 className="w-4 h-4 text-green-400" />
                : <XCircle className="w-4 h-4 text-red-400" />}
              <span className={`font-medium ${status?.connected ? "text-green-400" : "text-red-400"}`}>
                {statusLoading ? "Checking..." : status?.connected ? "Connected" : "Disconnected"}
              </span>
            </div>
            {status?.connected && (
              <div className="flex gap-4 mt-1 text-sm text-muted-foreground">
                <span>Cluster: <span className="text-foreground">{status.cluster_name}</span></span>
                <span>Version: <span className="text-foreground">{status.version}</span></span>
                <span>Health: <span className={
                  status.status === "green" ? "text-green-400"
                  : status.status === "yellow" ? "text-yellow-400"
                  : "text-red-400"
                }>{status.status}</span></span>
              </div>
            )}
            {status?.error && (
              <p className="text-sm text-red-400 mt-1">{status.error}</p>
            )}
          </div>
        </div>
      </div>

      {/* Indices */}
      {status?.connected && (
        <div className="bg-card rounded-xl border border-border overflow-hidden">
          <div className="px-5 py-3 border-b border-border flex items-center gap-2">
            <Database className="w-4 h-4 text-primary" />
            <h2 className="font-medium text-foreground">Available Indices</h2>
            <span className="text-xs text-muted-foreground ml-auto">{(indices ?? []).length} indices</span>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Index / Data Stream</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Type</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Documents</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Size</th>
                <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Health</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {indicesLoading ? (
                <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">Loading indices...</td></tr>
              ) : (indices ?? []).map((idx: { index: string; type: string; docs_count: number; size?: string; health: string; backing_indices?: number }) => (
                <tr key={idx.index} className="hover:bg-secondary/30 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-foreground">{idx.index}</td>
                  <td className="px-4 py-3">
                    {idx.type === "data_stream" ? (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-primary/10 text-primary border border-primary/20">
                        data stream {idx.backing_indices != null ? `(${idx.backing_indices})` : ""}
                      </span>
                    ) : (
                      <span className="text-xs px-2 py-0.5 rounded-full bg-secondary text-muted-foreground border border-border">
                        index
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">{idx.docs_count.toLocaleString()}</td>
                  <td className="px-4 py-3 text-muted-foreground">{idx.size ?? "—"}</td>
                  <td className="px-4 py-3">
                    <span className={
                      idx.health === "green" ? "text-green-400"
                      : idx.health === "yellow" ? "text-yellow-400"
                      : "text-red-400"
                    }>{idx.health}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
