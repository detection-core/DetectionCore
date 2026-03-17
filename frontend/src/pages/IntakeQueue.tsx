import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Zap, CheckCircle2, Clock, ChevronDown, ChevronUp } from "lucide-react";
import { getIntakeQueue, updateIntakeItem, deployToElk } from "@/api/endpoints";
import { Badge } from "@/components/ui/badge";
import { severityVariant, scoreColor, formatDate } from "@/lib/utils";

const STATUS_OPTIONS = ["pending", "in_progress", "implemented", "deferred"];

export default function IntakeQueue() {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [page, setPage] = useState(1);
  const [filterStatus, setFilterStatus] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [notes, setNotes] = useState<Record<string, { impl?: string; tuning?: string }>>({});

  const { data, isLoading } = useQuery({
    queryKey: ["intake", page, filterStatus],
    queryFn: () =>
      getIntakeQueue({ page, page_size: 20, ...(filterStatus && { status: filterStatus }) })
        .then((r) => r.data.data),
  });

  const patchMut = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      updateIntakeItem(id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intake"] }),
  });

  const deployMut = useMutation({
    mutationFn: (id: string) => deployToElk(id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["intake"] }),
  });

  const items = data?.items ?? [];

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">In-Take Queue</h1>
          <p className="text-sm text-muted-foreground">
            {data?.total ?? 0} rules sorted by priority score
          </p>
        </div>
        <select
          value={filterStatus}
          onChange={(e) => { setFilterStatus(e.target.value); setPage(1); }}
          className="px-3 py-2 text-sm rounded-lg bg-card border border-border text-foreground focus:outline-none"
        >
          <option value="">All Statuses</option>
          {STATUS_OPTIONS.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
      </div>

      <div className="space-y-2">
        {isLoading ? (
          <div className="text-center py-8 text-muted-foreground">Loading queue...</div>
        ) : items.length === 0 ? (
          <div className="text-center py-8 text-muted-foreground">No items in queue</div>
        ) : (
          items.map((item: {
            id: string; rule_id: string; rule_title: string; rule_severity: string;
            score: number; status: string; test_passed: boolean; elk_deployed: boolean;
            implementation_notes?: string; tuning_notes?: string; assigned_to?: string;
            mitre_technique_ids: string[]; log_source_product?: string; updated_at: string;
          }, idx: number) => {
            const isExpanded = expandedId === item.id;
            return (
              <div key={item.id} className="bg-card rounded-xl border border-border overflow-hidden">
                {/* Row */}
                <div
                  className="flex items-center gap-4 px-5 py-4 cursor-pointer hover:bg-secondary/30 transition-colors"
                  onClick={() => setExpandedId(isExpanded ? null : item.id)}
                >
                  <span className="text-xl font-bold text-muted-foreground/40 w-8 text-right">
                    {(page - 1) * 20 + idx + 1}
                  </span>

                  <div className={`text-2xl font-bold w-14 text-right ${scoreColor(item.score)}`}>
                    {item.score.toFixed(0)}
                  </div>

                  <div className="flex-1 min-w-0">
                    <p
                      className="font-medium text-foreground hover:text-primary cursor-pointer truncate"
                      onClick={(e) => { e.stopPropagation(); navigate(`/rules/${item.rule_id}`); }}
                    >
                      {item.rule_title}
                    </p>
                    <div className="flex items-center gap-2 mt-1 flex-wrap">
                      <Badge variant={severityVariant(item.rule_severity)} className="text-xs">
                        {item.rule_severity}
                      </Badge>
                      <Badge
                        variant={
                          item.status === "implemented" ? "success"
                          : item.status === "in_progress" ? "info"
                          : item.status === "deferred" ? "secondary"
                          : "outline"
                        }
                        className="text-xs"
                      >
                        {item.status}
                      </Badge>
                      {item.test_passed && (
                        <Badge variant="success" className="text-xs">Tests OK</Badge>
                      )}
                      {item.elk_deployed && (
                        <Badge variant="info" className="text-xs">ELK Deployed</Badge>
                      )}
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                  </div>
                </div>

                {/* Expanded panel */}
                {isExpanded && (
                  <div className="border-t border-border px-5 py-4 space-y-4 bg-secondary/20">
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                      {/* Notes */}
                      <div className="space-y-3">
                        <div>
                          <label className="text-xs font-medium text-muted-foreground uppercase">Implementation Notes</label>
                          <textarea
                            rows={3}
                            defaultValue={item.implementation_notes ?? ""}
                            onChange={(e) => setNotes((prev) => ({ ...prev, [item.id]: { ...prev[item.id], impl: e.target.value } }))}
                            placeholder="Steps taken to implement this rule in the SIEM..."
                            className="mt-1 w-full px-3 py-2 text-sm rounded-lg bg-card border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
                          />
                        </div>
                        <div>
                          <label className="text-xs font-medium text-muted-foreground uppercase">Tuning Notes</label>
                          <textarea
                            rows={3}
                            defaultValue={item.tuning_notes ?? ""}
                            onChange={(e) => setNotes((prev) => ({ ...prev, [item.id]: { ...prev[item.id], tuning: e.target.value } }))}
                            placeholder="Exclusions, thresholds, whitelist entries..."
                            className="mt-1 w-full px-3 py-2 text-sm rounded-lg bg-card border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
                          />
                        </div>
                      </div>

                      {/* Actions */}
                      <div className="space-y-3">
                        <div>
                          <label className="text-xs font-medium text-muted-foreground uppercase">Status</label>
                          <select
                            defaultValue={item.status}
                            onChange={(e) => patchMut.mutate({ id: item.id, payload: { status: e.target.value } })}
                            className="mt-1 w-full px-3 py-2 text-sm rounded-lg bg-card border border-border text-foreground focus:outline-none"
                          >
                            {STATUS_OPTIONS.map((s) => (
                              <option key={s} value={s}>{s}</option>
                            ))}
                          </select>
                        </div>

                        <div className="flex items-center gap-3">
                          <label className="flex items-center gap-2 text-sm text-foreground cursor-pointer">
                            <input
                              type="checkbox"
                              defaultChecked={item.test_passed}
                              onChange={(e) => patchMut.mutate({ id: item.id, payload: { test_passed: e.target.checked } })}
                              className="rounded"
                            />
                            Test Passed
                          </label>
                        </div>

                        <div className="flex gap-2 pt-1">
                          <button
                            onClick={() => patchMut.mutate({
                              id: item.id,
                              payload: {
                                implementation_notes: notes[item.id]?.impl ?? item.implementation_notes,
                                tuning_notes: notes[item.id]?.tuning ?? item.tuning_notes,
                              },
                            })}
                            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm rounded-lg bg-secondary border border-border text-foreground hover:bg-secondary/80 transition-colors"
                          >
                            <CheckCircle2 className="w-4 h-4" />
                            Save Notes
                          </button>
                          <button
                            onClick={() => deployMut.mutate(item.id)}
                            disabled={deployMut.isPending || item.elk_deployed}
                            className="flex-1 flex items-center justify-center gap-2 px-3 py-2 text-sm rounded-lg bg-primary/10 border border-primary/20 text-primary hover:bg-primary/20 disabled:opacity-50 transition-colors"
                          >
                            <Zap className="w-4 h-4" />
                            {item.elk_deployed ? "Deployed" : "Deploy to ELK"}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>

      {/* Pagination */}
      <div className="flex justify-between items-center pt-2">
        <p className="text-sm text-muted-foreground">Page {page} of {data?.total_pages ?? 1}</p>
        <div className="flex gap-2">
          <button onClick={() => setPage((p) => Math.max(1, p - 1))} disabled={page === 1}
            className="px-3 py-1.5 text-sm rounded-lg border border-border hover:bg-secondary disabled:opacity-40">Prev</button>
          <button onClick={() => setPage((p) => p + 1)} disabled={page >= (data?.total_pages ?? 1)}
            className="px-3 py-1.5 text-sm rounded-lg border border-border hover:bg-secondary disabled:opacity-40">Next</button>
        </div>
      </div>
    </div>
  );
}
