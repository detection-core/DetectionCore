import { useQuery } from "@tanstack/react-query";
import { Printer, Download } from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { getDetectionReport } from "@/api/endpoints";

interface ReportData {
  generated_at: string;
  rules_summary: {
    total: number;
    by_status: Record<string, number>;
    by_severity: Record<string, number>;
    deployed_to_elk: number;
    failed: number;
  };
  mitre_summary: {
    techniques_covered: number;
    techniques_total: number;
    coverage_percent: number;
    tactics_coverage: { tactic: string; covered: number; total: number }[];
    top_uncovered: { technique_id: string; name: string; tactic: string }[];
  };
  log_source_summary: {
    total_sources: number;
    available: number;
    unavailable: number;
    rules_covered: number;
    rules_uncovered: number;
    top_gaps: { source: string; blocked_rules: number }[];
  };
  score_summary: {
    average_score: number;
    median_score: number;
    rules_above_70: number;
    distribution: { range: string; count: number }[];
  };
}

function KpiCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="px-4 py-3 rounded-lg bg-card border border-border">
      <p className="text-2xl font-bold text-foreground">{value}</p>
      <p className="text-xs text-muted-foreground">{label}</p>
      {sub && <p className="text-[10px] text-muted-foreground mt-0.5">{sub}</p>}
    </div>
  );
}

export default function DetectionReport() {
  const { data, isLoading } = useQuery({
    queryKey: ["detection-report"],
    queryFn: () => getDetectionReport().then((r) => r.data.data as ReportData),
  });

  const handlePrint = () => window.print();

  const handleExport = () => {
    if (!data) return;
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `detection-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (isLoading) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-foreground mb-4">Detection Report</h1>
        <p className="text-muted-foreground">Generating report...</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-foreground mb-4">Detection Report</h1>
        <p className="text-muted-foreground">No data available.</p>
      </div>
    );
  }

  const { rules_summary, mitre_summary, log_source_summary, score_summary } = data;

  return (
    <div className="p-6 space-y-6 max-w-5xl print:max-w-none">
      {/* Header */}
      <div className="flex items-center justify-between print:hidden">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Detection Report</h1>
          <p className="text-sm text-muted-foreground">
            Generated {new Date(data.generated_at).toLocaleString()}
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={handlePrint}
            className="flex items-center gap-2 px-3 py-2 text-sm rounded-lg bg-secondary text-foreground hover:bg-secondary/80 transition-colors"
          >
            <Printer className="w-4 h-4" /> Print Report
          </button>
          <button
            onClick={handleExport}
            className="flex items-center gap-2 px-3 py-2 text-sm rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
          >
            <Download className="w-4 h-4" /> Export JSON
          </button>
        </div>
      </div>
      <div className="hidden print:block mb-4">
        <h1 className="text-2xl font-bold">Detection Posture Report</h1>
        <p className="text-sm text-gray-500">Generated {new Date(data.generated_at).toLocaleString()}</p>
      </div>

      {/* Executive Summary */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-3">Executive Summary</h2>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <KpiCard label="Total Rules" value={rules_summary.total} />
          <KpiCard label="Deployed to ELK" value={rules_summary.deployed_to_elk} />
          <KpiCard label="Failed Pipeline" value={rules_summary.failed} />
          <KpiCard
            label="MITRE Coverage"
            value={`${mitre_summary.coverage_percent}%`}
            sub={`${mitre_summary.techniques_covered}/${mitre_summary.techniques_total} techniques`}
          />
          <KpiCard label="Log Sources Available" value={log_source_summary.available} sub={`of ${log_source_summary.total_sources}`} />
          <KpiCard label="Rules Covered" value={log_source_summary.rules_covered} />
          <KpiCard label="Avg Score" value={score_summary.average_score} />
          <KpiCard label="Rules Above 70" value={score_summary.rules_above_70} />
        </div>
      </section>

      {/* Pipeline Status */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-3">Pipeline Status</h2>
        <div className="space-y-2">
          {Object.entries(rules_summary.by_status).map(([status, count]) => (
            <div key={status} className="flex items-center gap-3">
              <span className="w-24 text-xs text-muted-foreground text-right">{status}</span>
              <div className="flex-1 h-5 bg-muted rounded overflow-hidden">
                <div
                  className="h-full bg-primary/70 rounded"
                  style={{ width: rules_summary.total ? `${(count / rules_summary.total) * 100}%` : "0%" }}
                />
              </div>
              <span className="w-10 text-xs text-foreground text-right">{count}</span>
            </div>
          ))}
        </div>
      </section>

      {/* MITRE Coverage */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-3">MITRE ATT&CK Coverage</h2>
        <div className="space-y-2">
          {mitre_summary.tactics_coverage.map((t) => (
            <div key={t.tactic} className="flex items-center gap-3">
              <span className="w-40 text-xs text-muted-foreground text-right truncate" title={t.tactic}>{t.tactic}</span>
              <div className="flex-1 h-5 bg-muted rounded overflow-hidden">
                <div
                  className="h-full bg-blue-500/70 rounded"
                  style={{ width: t.total ? `${(t.covered / t.total) * 100}%` : "0%" }}
                />
              </div>
              <span className="w-16 text-xs text-foreground text-right">{t.covered}/{t.total}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Log Source Coverage */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-3">Log Source Coverage</h2>
        {log_source_summary.top_gaps.length === 0 ? (
          <p className="text-sm text-muted-foreground">No log source gaps detected.</p>
        ) : (
          <div className="bg-card rounded-xl border border-border overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground uppercase">Missing Log Source</th>
                  <th className="text-right px-4 py-2 text-xs font-medium text-muted-foreground uppercase">Blocked Rules</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {log_source_summary.top_gaps.map((g) => (
                  <tr key={g.source}>
                    <td className="px-4 py-2 font-mono text-xs text-foreground">{g.source}</td>
                    <td className="px-4 py-2 text-right text-xs text-red-400 font-bold">{g.blocked_rules}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {/* Score Distribution */}
      <section>
        <h2 className="text-lg font-semibold text-foreground mb-3">Score Distribution</h2>
        <div className="flex gap-4 mb-3 text-sm text-muted-foreground">
          <span>Average: <strong className="text-foreground">{score_summary.average_score}</strong></span>
          <span>Median: <strong className="text-foreground">{score_summary.median_score}</strong></span>
        </div>
        {score_summary.distribution.length > 0 ? (
          <div className="h-48 print:h-40">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={score_summary.distribution}>
                <XAxis dataKey="range" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip />
                <Bar dataKey="count" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">No score data available.</p>
        )}
      </section>

      {/* Print styles */}
      <style>{`
        @media print {
          nav, aside, [class*="print\\:hidden"] { display: none !important; }
          body { background: white !important; color: black !important; }
          .print\\:block { display: block !important; }
          section { break-inside: avoid; }
        }
      `}</style>
    </div>
  );
}
