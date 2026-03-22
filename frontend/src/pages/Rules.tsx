import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { Search, Filter, RefreshCw, ChevronLeft, ChevronRight } from "lucide-react";
import { getRules } from "@/api/endpoints";
import { Badge } from "@/components/ui/badge";
import { severityVariant, statusColor, scoreColor, formatDate } from "@/lib/utils";

const STATUSES = ["", "synced", "converted", "enhanced", "tested", "scored", "queued", "implemented", "failed"];
const SEVERITIES = ["", "critical", "high", "medium", "low", "informational"];

export default function Rules() {
  const navigate = useNavigate();
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["rules", page, debouncedSearch, status, severity],
    queryFn: () =>
      getRules({
        page,
        page_size: 25,
        ...(debouncedSearch && { search: debouncedSearch }),
        ...(status && { status }),
        ...(severity && { severity }),
      }).then((r) => r.data.data),
  });

  const handleSearchChange = (v: string) => {
    setSearch(v);
    clearTimeout((window as unknown as Record<string, ReturnType<typeof setTimeout>>)._searchTimer);
    (window as unknown as Record<string, ReturnType<typeof setTimeout>>)._searchTimer = setTimeout(() => {
      setDebouncedSearch(v);
      setPage(1);
    }, 400);
  };

  const rules = data?.items ?? [];
  const totalPages = data?.total_pages ?? 1;

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Rules Library</h1>
          <p className="text-sm text-muted-foreground">{data?.total ?? 0} total rules</p>
        </div>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-2 px-3 py-2 text-sm rounded-lg bg-secondary text-foreground hover:bg-secondary/80 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
          Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-48">
          <Search className="absolute left-3 top-2.5 w-4 h-4 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => handleSearchChange(e.target.value)}
            placeholder="Search rules, MITRE techniques..."
            className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-card border border-border text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
          />
        </div>
        <select
          value={status}
          onChange={(e) => { setStatus(e.target.value); setPage(1); }}
          className="px-3 py-2 text-sm rounded-lg bg-card border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          {STATUSES.map((s) => (
            <option key={s} value={s}>{s || "All Statuses"}</option>
          ))}
        </select>
        <select
          value={severity}
          onChange={(e) => { setSeverity(e.target.value); setPage(1); }}
          className="px-3 py-2 text-sm rounded-lg bg-card border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
        >
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s || "All Severities"}</option>
          ))}
        </select>
      </div>

      {/* Table */}
      <div className="bg-card rounded-xl border border-border overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border">
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Rule</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Severity</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Status</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Score</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Log Source</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">MITRE</th>
              <th className="text-left px-4 py-3 text-xs font-medium text-muted-foreground uppercase">Synced</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border">
            {isLoading ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">Loading...</td>
              </tr>
            ) : rules.length === 0 ? (
              <tr>
                <td colSpan={7} className="px-4 py-8 text-center text-muted-foreground">No rules found</td>
              </tr>
            ) : (
              rules.map((rule: {
                id: string; title: string; severity: string; pipeline_status: string;
                total_score: number; log_source_product?: string; log_source_category?: string;
                log_source_available: boolean; log_source_match_type?: string;
                mitre_technique_ids: string[]; synced_at: string;
              }) => (
                <tr
                  key={rule.id}
                  onClick={() => navigate(`/rules/${rule.id}`)}
                  className="hover:bg-secondary/50 cursor-pointer transition-colors"
                >
                  <td className="px-4 py-3 max-w-xs">
                    <p className="font-medium text-foreground truncate">{rule.title}</p>
                  </td>
                  <td className="px-4 py-3">
                    <Badge variant={severityVariant(rule.severity)}>{rule.severity}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`text-xs font-medium ${statusColor(rule.pipeline_status)}`}>
                      {rule.pipeline_status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`font-bold ${scoreColor(rule.total_score)}`}>
                      {rule.total_score.toFixed(0)}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono ${
                      rule.log_source_match_type === "exact" ? "bg-green-500/15 text-green-400" :
                      rule.log_source_match_type === "partial" || rule.log_source_match_type === "product" ? "bg-amber-500/15 text-amber-400" :
                      "bg-red-500/15 text-red-400"
                    }`}>
                      {rule.log_source_category}/{rule.log_source_product ?? "?"}
                      {rule.log_source_match_type && (
                        <span className="text-[10px] opacity-70">({rule.log_source_match_type})</span>
                      )}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {rule.mitre_technique_ids.slice(0, 2).map((id: string) => (
                        <Badge key={id} variant="outline" className="text-xs">{id}</Badge>
                      ))}
                      {rule.mitre_technique_ids.length > 2 && (
                        <span className="text-xs text-muted-foreground">+{rule.mitre_technique_ids.length - 2}</span>
                      )}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(rule.synced_at)}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Page {page} of {totalPages}
        </p>
        <div className="flex gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="p-2 rounded-lg border border-border text-foreground hover:bg-secondary disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page >= totalPages}
            className="p-2 rounded-lg border border-border text-foreground hover:bg-secondary disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
