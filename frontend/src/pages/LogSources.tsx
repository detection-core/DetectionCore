import { useRef, useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Upload, CheckCircle2, XCircle, Trash2 } from "lucide-react";
import { getLogSources, uploadLogSources, updateLogSource, deleteLogSource } from "@/api/endpoints";

export default function LogSources() {
  const qc = useQueryClient();
  const fileRef = useRef<HTMLInputElement>(null);
  const [uploadMsg, setUploadMsg] = useState<string | null>(null);

  const { data: sources, isLoading } = useQuery({
    queryKey: ["log-sources"],
    queryFn: () => getLogSources().then((r) => r.data.data),
  });

  const uploadMut = useMutation({
    mutationFn: (file: File) => uploadLogSources(file),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ["log-sources"] });
      setUploadMsg(`Uploaded: ${res.data.data.inserted} new, ${res.data.data.updated} updated`);
      setTimeout(() => setUploadMsg(null), 5000);
    },
  });

  const toggleMut = useMutation({
    mutationFn: ({ id, val }: { id: string; val: boolean }) =>
      updateLogSource(id, { is_available: val }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["log-sources"] }),
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => deleteLogSource(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["log-sources"] }),
  });

  const available = (sources ?? []).filter((s: { is_available: boolean }) => s.is_available).length;

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Log Sources</h1>
          <p className="text-sm text-muted-foreground">
            {available} of {(sources ?? []).length} log sources available in ELK
          </p>
        </div>
        <div className="flex items-center gap-3">
          <input
            ref={fileRef}
            type="file"
            accept=".csv,.json"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) uploadMut.mutate(f);
            }}
          />
          <button
            onClick={() => fileRef.current?.click()}
            className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <Upload className="w-4 h-4" />
            Upload CSV/JSON
          </button>
        </div>
      </div>

      {uploadMsg && (
        <div className="px-4 py-3 rounded-lg bg-green-500/10 border border-green-500/20 text-sm text-green-400">
          {uploadMsg}
        </div>
      )}

      {/* Format hint */}
      <div className="px-4 py-3 rounded-lg bg-secondary border border-border text-xs text-muted-foreground">
        <p className="font-medium text-foreground mb-1">CSV Format:</p>
        <code>category,product,service,elk_index_pattern,is_available,notes</code>
        <br />
        <code>process_creation,windows,sysmon,winlogbeat-*,true,Primary Windows telemetry</code>
      </div>

      {/* Table */}
      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Log Source</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">ELK Index</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Available</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Notes</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {isLoading ? (
              <tr><td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">Loading...</td></tr>
            ) : (sources ?? []).length === 0 ? (
              <tr>
                <td colSpan={5} className="px-4 py-8 text-center text-muted-foreground">
                  No log sources uploaded yet. Upload a CSV or JSON file to get started.
                </td>
              </tr>
            ) : (
              (sources ?? []).map((s: {
                id: string; category: string; product: string; service?: string;
                elk_index_pattern?: string; is_available: boolean; notes?: string;
              }) => (
                <tr key={s.id} className="hover:bg-secondary/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className="font-mono text-foreground text-xs">
                      {s.category}/{s.product}{s.service ? `/${s.service}` : ""}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground font-mono">
                    {s.elk_index_pattern ?? "—"}
                  </td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => toggleMut.mutate({ id: s.id, val: !s.is_available })}
                      className="flex items-center gap-1.5 text-sm"
                    >
                      {s.is_available ? (
                        <CheckCircle2 className="w-4 h-4 text-green-400" />
                      ) : (
                        <XCircle className="w-4 h-4 text-red-400" />
                      )}
                      <span className={s.is_available ? "text-green-400" : "text-red-400"}>
                        {s.is_available ? "Available" : "Unavailable"}
                      </span>
                    </button>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{s.notes ?? "—"}</td>
                  <td className="px-4 py-3">
                    <button
                      onClick={() => deleteMut.mutate(s.id)}
                      className="text-muted-foreground hover:text-destructive transition-colors"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
