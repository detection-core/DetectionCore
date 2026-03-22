import { useQuery } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { getMitreMatrix } from "@/api/endpoints";

interface SubTechnique {
  technique_id: string;
  name: string;
  rule_count: number;
  implemented_count: number;
}

interface Technique {
  technique_id: string;
  name: string;
  rule_count: number;
  implemented_count: number;
  subtechniques: SubTechnique[];
}

interface Tactic {
  tactic_id: string;
  tactic_name: string;
  techniques: Technique[];
}

interface MitreData {
  tactics: Tactic[];
  summary: {
    total_techniques: number;
    covered_techniques: number;
    coverage_percent: number;
  };
}

function cellColor(ruleCount: number): string {
  if (ruleCount === 0) return "bg-muted/40 text-muted-foreground";
  if (ruleCount === 1) return "bg-blue-500/20 text-blue-300";
  if (ruleCount <= 3) return "bg-blue-500/40 text-blue-200";
  if (ruleCount <= 5) return "bg-blue-600/50 text-blue-100";
  return "bg-purple-600/60 text-purple-100";
}

export default function MitreHeatmap() {
  const navigate = useNavigate();
  const { data, isLoading } = useQuery({
    queryKey: ["mitre-matrix"],
    queryFn: () => getMitreMatrix().then((r) => r.data.data as MitreData),
  });

  if (isLoading) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-foreground mb-4">MITRE ATT&CK Coverage</h1>
        <p className="text-muted-foreground">Loading matrix...</p>
      </div>
    );
  }

  if (!data || data.tactics.length === 0) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-foreground mb-4">MITRE ATT&CK Coverage</h1>
        <p className="text-muted-foreground">No MITRE data available. Sync and process rules first.</p>
      </div>
    );
  }

  const { tactics, summary } = data;

  return (
    <div className="p-6 space-y-4">
      <div>
        <h1 className="text-2xl font-bold text-foreground">MITRE ATT&CK Coverage</h1>
        <p className="text-sm text-muted-foreground">
          {summary.covered_techniques} of {summary.total_techniques} techniques covered ({summary.coverage_percent}%)
        </p>
      </div>

      {/* Summary bar */}
      <div className="flex items-center gap-4">
        <div className="flex-1 h-3 bg-muted rounded-full overflow-hidden">
          <div
            className="h-full bg-primary rounded-full transition-all"
            style={{ width: `${summary.coverage_percent}%` }}
          />
        </div>
        <span className="text-sm font-bold text-foreground">{summary.coverage_percent}%</span>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-muted-foreground">
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-muted/40" /> No coverage</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-500/20" /> 1 rule</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-500/40" /> 2-3 rules</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-blue-600/50" /> 4-5 rules</span>
        <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-purple-600/60" /> 6+ rules</span>
      </div>

      {/* Matrix grid */}
      <div className="overflow-x-auto pb-4">
        <div
          className="grid gap-1"
          style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(140px, 1fr))` }}
        >
          {/* Tactic headers */}
          {tactics.map((tactic) => (
            <div
              key={tactic.tactic_id}
              className="px-2 py-2 text-xs font-bold text-center text-foreground bg-secondary rounded-t-lg truncate"
              title={tactic.tactic_name}
            >
              {tactic.tactic_name}
            </div>
          ))}

          {/* Technique cells — render row by row up to the max column height */}
          {Array.from({ length: Math.max(...tactics.map((t) => t.techniques.length), 0) }).map((_, rowIdx) => (
            tactics.map((tactic) => {
              const tech = tactic.techniques[rowIdx];
              if (!tech) return <div key={`${tactic.tactic_id}-${rowIdx}-empty`} />;
              return (
                <div
                  key={tech.technique_id}
                  onClick={() => navigate(`/rules?search=${tech.technique_id}`)}
                  className={`px-2 py-1.5 rounded text-[11px] leading-tight cursor-pointer hover:ring-1 hover:ring-primary/50 transition-all ${cellColor(tech.rule_count)}`}
                  title={`${tech.technique_id}: ${tech.name}\nRules: ${tech.rule_count} (${tech.implemented_count} implemented)${
                    tech.subtechniques.length > 0
                      ? "\nSub-techniques: " + tech.subtechniques.map((s) => `${s.technique_id} (${s.rule_count})`).join(", ")
                      : ""
                  }`}
                >
                  <span className="font-mono font-medium">{tech.technique_id}</span>
                  <br />
                  <span className="opacity-80">{tech.name}</span>
                  {tech.rule_count > 0 && (
                    <span className="block text-[10px] opacity-60 mt-0.5">
                      {tech.rule_count} rule{tech.rule_count > 1 ? "s" : ""}
                    </span>
                  )}
                </div>
              );
            })
          ))}
        </div>
      </div>
    </div>
  );
}
