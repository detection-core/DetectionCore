import { useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, RefreshCw, Terminal, Code2, BarChart3, Play } from "lucide-react";
import { getRule, reprocessRule, runUnitTest } from "@/api/endpoints";
import { Badge } from "@/components/ui/badge";
import { severityVariant, statusColor, scoreColor } from "@/lib/utils";

export default function RuleDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState<"sigma" | "elk" | "tests" | "score">("sigma");
  const [testResults, setTestResults] = useState<Record<string, { passed: boolean; hits: number; error?: string }>>({});

  const { data: rule, isLoading } = useQuery({
    queryKey: ["rule", id],
    queryFn: () => getRule(id!).then((r) => r.data.data),
    enabled: !!id,
  });

  const reprocessMut = useMutation({
    mutationFn: () => reprocessRule(id!),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["rule", id] }),
  });

  const runTestMut = useMutation({
    mutationFn: ({ testId }: { testId: string }) => runUnitTest(id!, testId),
    onSuccess: (res, { testId }) => {
      setTestResults((prev) => ({ ...prev, [testId]: res.data.data }));
      qc.invalidateQueries({ queryKey: ["rule", id] });
    },
  });

  if (isLoading) return <div className="p-6 text-muted-foreground">Loading...</div>;
  if (!rule) return <div className="p-6 text-muted-foreground">Rule not found</div>;

  const tabs = [
    { id: "sigma", label: "SIGMA", icon: Code2 },
    { id: "elk", label: "ELK Query", icon: Terminal },
    { id: "tests", label: `Unit Tests (${rule.unit_tests?.length ?? 0})`, icon: Play },
    { id: "score", label: "Score Breakdown", icon: BarChart3 },
  ];

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-start gap-4">
        <button
          onClick={() => navigate(-1)}
          className="mt-1 p-1.5 rounded-lg border border-border hover:bg-secondary transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-3 flex-wrap">
            <h1 className="text-xl font-bold text-foreground">{rule.title}</h1>
            <Badge variant={severityVariant(rule.severity)}>{rule.severity}</Badge>
            <span className={`text-sm font-medium ${statusColor(rule.pipeline_status)}`}>
              {rule.pipeline_status}
            </span>
          </div>
          {rule.description && (
            <p className="text-sm text-muted-foreground mt-1">{rule.description}</p>
          )}
          <div className="flex flex-wrap gap-2 mt-2">
            {rule.mitre_technique_ids?.map((id: string) => (
              <Badge key={id} variant="outline" className="text-xs">{id}</Badge>
            ))}
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className="text-right">
            <p className={`text-3xl font-bold ${scoreColor(rule.total_score)}`}>
              {rule.total_score?.toFixed(0)}
            </p>
            <p className="text-xs text-muted-foreground">Priority Score</p>
          </div>
          <button
            onClick={() => reprocessMut.mutate()}
            disabled={reprocessMut.isPending}
            className="flex items-center gap-2 px-3 py-2 text-sm rounded-lg bg-secondary hover:bg-secondary/80 text-foreground transition-colors"
          >
            <RefreshCw className={`w-4 h-4 ${reprocessMut.isPending ? "animate-spin" : ""}`} />
            Reprocess
          </button>
        </div>
      </div>

      {/* Pipeline error */}
      {rule.pipeline_error && (
        <div className="px-4 py-3 rounded-lg bg-destructive/10 border border-destructive/20 text-sm text-destructive">
          Pipeline Error: {rule.pipeline_error}
        </div>
      )}

      {/* Tabs */}
      <div className="border-b border-border">
        <div className="flex gap-1">
          {tabs.map(({ id: tabId, label, icon: Icon }) => (
            <button
              key={tabId}
              onClick={() => setActiveTab(tabId as typeof activeTab)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tabId
                  ? "border-primary text-primary"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      {activeTab === "sigma" && (
        <pre className="code-block">{rule.sigma_content || "No SIGMA content available"}</pre>
      )}

      {activeTab === "elk" && (
        <div className="space-y-4">
          <div>
            <p className="text-sm font-medium text-foreground mb-2">Lucene Query</p>
            <pre className="code-block">{rule.elk_query || "Not converted yet"}</pre>
          </div>
          {rule.elk_rule_json && (
            <div>
              <p className="text-sm font-medium text-foreground mb-2">ELK Alert Rule JSON</p>
              <pre className="code-block">{JSON.stringify(rule.elk_rule_json, null, 2)}</pre>
            </div>
          )}
          {rule.ai_enhancement_notes && (
            <div className="px-4 py-3 rounded-lg bg-secondary text-sm text-foreground">
              <p className="font-medium mb-1 text-primary">AI Enhancement Notes</p>
              {rule.ai_enhancement_notes}
            </div>
          )}
        </div>
      )}

      {activeTab === "tests" && (
        <div className="space-y-4">
          {rule.unit_tests?.length === 0 ? (
            <p className="text-sm text-muted-foreground">No unit tests generated yet. Run the pipeline to generate tests.</p>
          ) : (
            rule.unit_tests?.map((test: {
              test_id: string; test_type: string; description: string;
              command: string; last_run_result: string; last_run_at?: string;
            }) => {
              const result = testResults[test.test_id];
              return (
                <div key={test.test_id} className="bg-card rounded-xl border border-border p-5 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs uppercase">{test.test_type}</Badge>
                        {(result ?? test.last_run_result !== "not_run") && (
                          <Badge variant={
                            (result?.passed ?? test.last_run_result === "passed") ? "success" : "destructive"
                          }>
                            {(result?.passed ?? test.last_run_result === "passed") ? "PASSED" : "FAILED"}
                            {result?.hits !== undefined && ` (${result.hits} hits)`}
                          </Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{test.description}</p>
                    </div>
                    <button
                      onClick={() => runTestMut.mutate({ testId: test.test_id })}
                      disabled={runTestMut.isPending}
                      className="flex items-center gap-1.5 px-3 py-1.5 text-xs rounded-lg bg-primary/10 text-primary hover:bg-primary/20 transition-colors border border-primary/20"
                    >
                      <Play className="w-3 h-3" />
                      Run Test
                    </button>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground mb-1">Attack Command:</p>
                    <pre className="code-block text-xs">{test.command}</pre>
                  </div>
                  {result?.error && (
                    <p className="text-xs text-destructive">{result.error}</p>
                  )}
                </div>
              );
            })
          )}
        </div>
      )}

      {activeTab === "score" && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <p className={`text-5xl font-bold ${scoreColor(rule.total_score)}`}>
              {rule.scoring?.total_score?.toFixed(1)}
            </p>
            <div>
              <p className="text-foreground font-medium">Priority Score</p>
              <p className="text-sm text-muted-foreground">
                {rule.scoring?.manually_overridden ? "Manually overridden" : "AI-calculated"}
              </p>
            </div>
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              { label: "Log Availability", value: rule.scoring?.log_availability },
              { label: "Industry Match", value: rule.scoring?.industry_match },
              { label: "Region Match", value: rule.scoring?.region_match },
              { label: "Severity", value: rule.scoring?.severity_score },
              { label: "Threat Actor", value: rule.scoring?.threat_actor_score },
              { label: "Asset Type", value: rule.scoring?.asset_type_score },
            ].map(({ label, value }) => (
              <div key={label} className="bg-secondary rounded-lg p-4">
                <p className="text-xs text-muted-foreground">{label}</p>
                <div className="flex items-center gap-2 mt-1">
                  <div className="flex-1 h-1.5 bg-border rounded-full overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{ width: `${value ?? 0}%` }}
                    />
                  </div>
                  <span className={`text-sm font-bold ${scoreColor(value ?? 0)}`}>
                    {(value ?? 0).toFixed(0)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
