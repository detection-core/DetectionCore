import { useQuery } from "@tanstack/react-query";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  ShieldCheck, AlertTriangle, CheckCircle2, Layers,
  Zap, TrendingUp, RefreshCw, Database,
} from "lucide-react";
import {
  getDashboardSummary,
  getPipelineFunnel,
  getSeverityDistribution,
  getMitreCoverage,
  getLogSourceGaps,
} from "@/api/endpoints";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#dc2626",
  high: "#ea580c",
  medium: "#d97706",
  low: "#2563eb",
  informational: "#6b7280",
};

const STAGE_COLORS: Record<string, string> = {
  synced: "#3b82f6",
  converted: "#06b6d4",
  enhanced: "#14b8a6",
  tested: "#6366f1",
  scored: "#a855f7",
  queued: "#eab308",
  implemented: "#22c55e",
  failed: "#ef4444",
};

function KpiCard({
  icon: Icon,
  label,
  value,
  sub,
  color = "text-primary",
}: {
  icon: React.ElementType;
  label: string;
  value: number | string;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="bg-card rounded-xl border border-border p-5 flex items-start gap-4">
      <div className={`p-2.5 rounded-lg bg-secondary`}>
        <Icon className={`w-5 h-5 ${color}`} />
      </div>
      <div>
        <p className="text-2xl font-bold text-foreground">{value}</p>
        <p className="text-sm text-muted-foreground">{label}</p>
        {sub && <p className="text-xs text-primary mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { data: summary } = useQuery({
    queryKey: ["dashboard-summary"],
    queryFn: () => getDashboardSummary().then((r) => r.data.data),
    refetchInterval: 30_000,
  });

  const { data: funnel } = useQuery({
    queryKey: ["pipeline-funnel"],
    queryFn: () => getPipelineFunnel().then((r) => r.data.data),
  });

  const { data: severityDist } = useQuery({
    queryKey: ["severity-dist"],
    queryFn: () => getSeverityDistribution().then((r) => r.data.data),
  });

  const { data: mitreCoverage } = useQuery({
    queryKey: ["mitre-coverage"],
    queryFn: () => getMitreCoverage().then((r) => r.data.data),
  });

  const { data: logGaps } = useQuery({
    queryKey: ["log-gaps"],
    queryFn: () => getLogSourceGaps().then((r) => r.data.data),
  });

  const s = summary ?? {};

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Dashboard</h1>
        <p className="text-sm text-muted-foreground">Detection engineering pipeline overview</p>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard icon={ShieldCheck} label="Total Rules" value={s.total_rules ?? 0} color="text-primary" />
        <KpiCard
          icon={TrendingUp}
          label="Converted"
          value={s.converted_rules ?? 0}
          sub={`${s.conversion_rate ?? 0}% conversion rate`}
          color="text-cyan-400"
        />
        <KpiCard
          icon={CheckCircle2}
          label="Implemented"
          value={s.implemented_rules ?? 0}
          sub={`${s.implementation_rate ?? 0}% of total`}
          color="text-green-400"
        />
        <KpiCard icon={Layers} label="In Queue" value={s.in_queue ?? 0} color="text-yellow-400" />
        <KpiCard
          icon={CheckCircle2}
          label="Tests Passed"
          value={s.test_passed ?? 0}
          sub={`${s.test_pass_rate ?? 0}% pass rate`}
          color="text-indigo-400"
        />
        <KpiCard icon={Zap} label="ELK Deployed" value={s.elk_deployed ?? 0} color="text-purple-400" />
        <KpiCard icon={AlertTriangle} label="Pipeline Failures" value={s.failed_pipeline ?? 0} color="text-red-400" />
        <KpiCard icon={Database} label="Total Rules Queued" value={s.in_queue ?? 0} color="text-orange-400" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Pipeline Funnel */}
        <div className="bg-card rounded-xl border border-border p-5">
          <h2 className="font-semibold text-foreground mb-4">Pipeline Funnel</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={funnel ?? []} layout="vertical">
              <XAxis type="number" tick={{ fill: "#6b7280", fontSize: 11 }} />
              <YAxis
                dataKey="stage"
                type="category"
                tick={{ fill: "#9ca3af", fontSize: 11 }}
                width={80}
              />
              <Tooltip
                contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
                labelStyle={{ color: "#e2e8f0" }}
              />
              <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                {(funnel ?? []).map((entry: { stage: string }) => (
                  <Cell key={entry.stage} fill={STAGE_COLORS[entry.stage] ?? "#64748b"} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Severity Distribution */}
        <div className="bg-card rounded-xl border border-border p-5">
          <h2 className="font-semibold text-foreground mb-4">Severity Distribution</h2>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={severityDist ?? []}
                dataKey="count"
                nameKey="severity"
                cx="50%"
                cy="50%"
                outerRadius={80}
                label={({ severity, percent }) =>
                  `${severity} ${(percent * 100).toFixed(0)}%`
                }
                labelLine={false}
              >
                {(severityDist ?? []).map((entry: { severity: string }) => (
                  <Cell key={entry.severity} fill={SEVERITY_COLORS[entry.severity] ?? "#64748b"} />
                ))}
              </Pie>
              <Legend formatter={(v) => <span className="text-xs text-muted-foreground capitalize">{v}</span>} />
              <Tooltip
                contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* MITRE Coverage */}
        <div className="bg-card rounded-xl border border-border p-5">
          <h2 className="font-semibold text-foreground mb-4">Top MITRE Techniques</h2>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={(mitreCoverage ?? []).slice(0, 10)}>
              <XAxis dataKey="technique_id" tick={{ fill: "#9ca3af", fontSize: 10 }} />
              <YAxis tick={{ fill: "#6b7280", fontSize: 11 }} />
              <Tooltip
                contentStyle={{ background: "#1e293b", border: "1px solid #334155", borderRadius: 8 }}
              />
              <Bar dataKey="count" fill="#06b6d4" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Log Source Gaps */}
        <div className="bg-card rounded-xl border border-border p-5">
          <h2 className="font-semibold text-foreground mb-4">Log Source Gaps (Blocked Rules)</h2>
          <div className="space-y-2 max-h-52 overflow-auto">
            {(logGaps ?? []).length === 0 ? (
              <p className="text-sm text-muted-foreground">No log source gaps detected.</p>
            ) : (
              (logGaps ?? []).map((g: { log_source: string; blocked_rules: number }) => (
                <div
                  key={g.log_source}
                  className="flex items-center justify-between text-sm py-2 px-3 rounded-lg bg-secondary"
                >
                  <span className="text-foreground font-mono text-xs">{g.log_source}</span>
                  <span className="text-red-400 font-medium">{g.blocked_rules} blocked</span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
