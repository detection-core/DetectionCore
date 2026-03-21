import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Save, RefreshCw, Plus, Trash2, Search, Loader2 } from "lucide-react";
import {
  getScoringConfig,
  updateScoringConfig,
  recalculateScores,
  getSettings,
  getSiemIntegrations,
  updateSiemIntegration,
  reconvertAllRules,
  getReconvertStatus,
  getElkFields,
} from "@/api/endpoints";

// ── Types ─────────────────────────────────────────────────────────────────────

interface MappingRow {
  sigmaField: string;
  targetField: string;
}

interface LoosourceRow {
  key: string; // "windows/process_creation"
  mappings: MappingRow[];
}

interface SiemIntegration {
  id: string;
  name: string;
  siem_type: string;
  is_default: boolean;
  base_pipeline: string;
  custom_field_mappings: Record<string, string>;
  logsource_field_overrides: Record<string, Record<string, string>>;
  updated_at: string | null;
}

interface ReconvertJob {
  status: string;
  total: number;
  done: number;
  errors: number;
  started_at: string | null;
  finished_at: string | null;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function mappingsToRows(obj: Record<string, string>): MappingRow[] {
  return Object.entries(obj).map(([sigmaField, targetField]) => ({ sigmaField, targetField }));
}

function rowsToMappings(rows: MappingRow[]): Record<string, string> {
  const out: Record<string, string> = {};
  for (const r of rows) {
    if (r.sigmaField.trim()) out[r.sigmaField.trim()] = r.targetField.trim();
  }
  return out;
}

function logsourceObjToRows(obj: Record<string, Record<string, string>>): LoosourceRow[] {
  return Object.entries(obj).map(([key, mappings]) => ({
    key,
    mappings: mappingsToRows(mappings),
  }));
}

function logsourceRowsToObj(rows: LoosourceRow[]): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {};
  for (const r of rows) {
    if (r.key.trim()) out[r.key.trim()] = rowsToMappings(r.mappings);
  }
  return out;
}

// ── Main Component ────────────────────────────────────────────────────────────

export default function Settings() {
  const qc = useQueryClient();
  const [saved, setSaved] = useState(false);

  // Scoring config queries
  const { data: platform } = useQuery({
    queryKey: ["settings"],
    queryFn: () => getSettings().then((r) => r.data.data),
  });

  const { data: config, isLoading } = useQuery({
    queryKey: ["scoring-config"],
    queryFn: () => getScoringConfig().then((r) => r.data.data),
  });

  const updateMut = useMutation({
    mutationFn: (data: Record<string, unknown>) => updateScoringConfig(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scoring-config"] });
      qc.invalidateQueries({ queryKey: ["settings"] });
      setSaved(true);
      setTimeout(() => setSaved(false), 3000);
    },
  });

  const recalcMut = useMutation({ mutationFn: recalculateScores });
  const [form, setForm] = useState<Record<string, string | number | boolean | string[]>>({});
  const val = (key: string) => form[key] ?? config?.[key] ?? "";
  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateMut.mutate(form as Record<string, unknown>);
  };

  // ── SIEM Integration state ─────────────────────────────────────────────────

  const { data: siemList } = useQuery({
    queryKey: ["siem-integrations"],
    queryFn: () => getSiemIntegrations().then((r) => r.data.data as SiemIntegration[]),
  });

  const defaultSiem = siemList?.find((s) => s.is_default) ?? siemList?.[0] ?? null;

  const [siemBasePipeline, setSiemBasePipeline] = useState<string>("");
  const [customMappingRows, setCustomMappingRows] = useState<MappingRow[]>([]);
  const [logsourceRows, setLogsourceRows] = useState<LoosourceRow[]>([]);
  const [siemSaved, setSiemSaved] = useState(false);

  // Populate SIEM form when data loads
  useEffect(() => {
    if (defaultSiem) {
      setSiemBasePipeline(defaultSiem.base_pipeline);
      setCustomMappingRows(mappingsToRows(defaultSiem.custom_field_mappings ?? {}));
      setLogsourceRows(logsourceObjToRows(defaultSiem.logsource_field_overrides ?? {}));
    }
  }, [defaultSiem?.id]);

  const siemMut = useMutation({
    mutationFn: (data: Record<string, unknown>) =>
      updateSiemIntegration(defaultSiem!.id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["siem-integrations"] });
      setSiemSaved(true);
      setTimeout(() => setSiemSaved(false), 3000);
    },
  });

  const handleSiemSave = () => {
    if (!defaultSiem) return;
    siemMut.mutate({
      base_pipeline: siemBasePipeline,
      custom_field_mappings: rowsToMappings(customMappingRows),
      logsource_field_overrides: logsourceRowsToObj(logsourceRows),
    });
  };

  // ── Reconvert All state ────────────────────────────────────────────────────

  const [reconvertJob, setReconvertJob] = useState<ReconvertJob | null>(null);
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };

  const startPolling = () => {
    stopPolling();
    pollingRef.current = setInterval(async () => {
      try {
        const res = await getReconvertStatus();
        const job = res.data.data as ReconvertJob;
        setReconvertJob(job);
        if (job.status !== "running") stopPolling();
      } catch {
        stopPolling();
      }
    }, 2000);
  };

  useEffect(() => () => stopPolling(), []);

  const handleReconvertAll = async () => {
    try {
      const res = await reconvertAllRules();
      setReconvertJob(res.data.data as ReconvertJob);
      if (res.data.data?.status === "running") startPolling();
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } };
      alert(err?.response?.data?.message ?? "Failed to start reconvert job");
    }
  };

  // ── Field Discovery state ──────────────────────────────────────────────────

  const [fieldIndex, setFieldIndex] = useState("winlogbeat-*");
  const [fields, setFields] = useState<Array<{ name: string; type: string }> | null>(null);
  const [fieldsLoading, setFieldsLoading] = useState(false);
  const [fieldsError, setFieldsError] = useState<string | null>(null);

  const handleBrowseFields = async () => {
    setFieldsLoading(true);
    setFieldsError(null);
    setFields(null);
    try {
      const res = await getElkFields(fieldIndex);
      setFields(res.data.data?.fields ?? []);
    } catch (e: unknown) {
      const err = e as { response?: { data?: { message?: string } } };
      setFieldsError(err?.response?.data?.message ?? "Elasticsearch unreachable");
    } finally {
      setFieldsLoading(false);
    }
  };

  // ── Shared UI components ───────────────────────────────────────────────────

  if (isLoading) return <div className="p-6 text-muted-foreground">Loading...</div>;

  const Section = ({ title, children }: { title: string; children: React.ReactNode }) => (
    <div className="bg-card rounded-xl border border-border p-5 space-y-4">
      <h2 className="font-semibold text-foreground border-b border-border pb-2">{title}</h2>
      {children}
    </div>
  );

  const Field = ({ label, name, type = "text", placeholder = "" }: {
    label: string; name: string; type?: string; placeholder?: string;
  }) => (
    <div className="space-y-1">
      <label className="text-xs font-medium text-muted-foreground uppercase">{label}</label>
      <input
        type={type}
        value={val(name) as string | number}
        onChange={(e) => setForm((f) => ({ ...f, [name]: type === "number" ? Number(e.target.value) : e.target.value }))}
        placeholder={placeholder}
        className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
      />
    </div>
  );

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-5">
      {/* Scoring config form */}
      <form onSubmit={handleSubmit} className="space-y-5">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-foreground">Settings</h1>
            <p className="text-sm text-muted-foreground">
              {platform?.app_name} v{platform?.app_version}
            </p>
          </div>
          <div className="flex gap-3">
            <button
              type="button"
              onClick={() => recalcMut.mutate()}
              disabled={recalcMut.isPending}
              className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-secondary border border-border text-foreground hover:bg-secondary/80 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${recalcMut.isPending ? "animate-spin" : ""}`} />
              Recalculate Scores
            </button>
            <button
              type="submit"
              disabled={updateMut.isPending}
              className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              <Save className="w-4 h-4" />
              {saved ? "Saved!" : "Save Settings"}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {/* Client Context */}
          <Section title="Client Context">
            <Field label="Client Name" name="client_name" placeholder="Acme Corp" />
            <Field label="Industry" name="client_industry" placeholder="Financial Services" />
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase">Regions (comma-separated)</label>
              <input
                type="text"
                value={(val("client_regions") as string[] | string[]).toString()}
                onChange={(e) => setForm((f) => ({
                  ...f, client_regions: e.target.value.split(",").map((s) => s.trim()).filter(Boolean)
                }))}
                placeholder="US, EU, Middle East"
                className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase">Threat Actor Watchlist (comma-separated)</label>
              <input
                type="text"
                value={(val("threat_actor_watchlist") as string[] | string[]).toString()}
                onChange={(e) => setForm((f) => ({
                  ...f, threat_actor_watchlist: e.target.value.split(",").map((s) => s.trim()).filter(Boolean)
                }))}
                placeholder="APT28, Lazarus Group, MuddyWater"
                className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
          </Section>

          {/* DetectionHub */}
          <Section title="DetectionHub Connection">
            <Field label="Base URL" name="detectionhub_base_url" placeholder="https://detectionhub.ai" />
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase">API Key</label>
              <input
                type="password"
                onChange={(e) => setForm((f) => ({ ...f, detectionhub_api_key: e.target.value }))}
                placeholder="Enter API key to update"
                className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
              <p className="text-xs text-muted-foreground">
                Connected: {platform?.detectionhub_connected ? "Yes" : "No"}
              </p>
            </div>
          </Section>

          {/* ELK */}
          <Section title="ELK Connection">
            <div className="grid grid-cols-2 gap-3">
              <Field label="Host" name="elk_host" placeholder="elasticsearch" />
              <Field label="Port" name="elk_port" type="number" placeholder="9200" />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase">API Key</label>
              <input
                type="password"
                onChange={(e) => setForm((f) => ({ ...f, elk_api_key: e.target.value }))}
                placeholder="Enter API key to update"
                className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <Field label="Username" name="elk_username" placeholder="elastic" />
              <div className="space-y-1">
                <label className="text-xs font-medium text-muted-foreground uppercase">Password</label>
                <input type="password" onChange={(e) => setForm((f) => ({ ...f, elk_password: e.target.value }))}
                  placeholder="••••••••"
                  className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none" />
              </div>
            </div>
          </Section>

          {/* AI */}
          <Section title="AI Provider">
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase">Provider</label>
              <select
                value={val("ai_provider") as string}
                onChange={(e) => setForm((f) => ({ ...f, ai_provider: e.target.value }))}
                className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none"
              >
                <option value="gemini">Gemini</option>
                <option value="openrouter">OpenRouter</option>
              </select>
            </div>
            <Field label="Model" name="ai_model" placeholder="gemini-2.0-flash" />
          </Section>

          {/* Scoring Weights */}
          <Section title="Scoring Weights (must sum to 100)">
            {[
              { key: "weight_log_availability", label: "Log Availability" },
              { key: "weight_industry_match", label: "Industry Match" },
              { key: "weight_region_match", label: "Region Match" },
              { key: "weight_severity", label: "Severity" },
              { key: "weight_threat_actor", label: "Threat Actor" },
              { key: "weight_asset_type", label: "Asset Type" },
            ].map(({ key, label }) => (
              <div key={key} className="flex items-center gap-3">
                <span className="text-sm text-muted-foreground w-36">{label}</span>
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={val(key) as number}
                  onChange={(e) => setForm((f) => ({ ...f, [key]: Number(e.target.value) }))}
                  className="w-20 px-2 py-1.5 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none text-center"
                />
                <span className="text-xs text-muted-foreground">%</span>
              </div>
            ))}
          </Section>

          {/* Sync */}
          <Section title="Sync Schedule">
            <Field label="Cron Expression" name="sync_cron" placeholder="0 6 * * *" />
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="sync_enabled"
                checked={val("sync_enabled") as boolean ?? config?.sync_enabled ?? true}
                onChange={(e) => setForm((f) => ({ ...f, sync_enabled: e.target.checked }))}
              />
              <label htmlFor="sync_enabled" className="text-sm text-foreground">Enable automatic sync</label>
            </div>
          </Section>
        </div>
      </form>

      {/* ── SIEM Integration Section ───────────────────────────────────────── */}
      <Section title="SIEM Integration">
        {!defaultSiem ? (
          <p className="text-sm text-muted-foreground">No SIEM integration configured.</p>
        ) : (
          <div className="space-y-6">
            {/* Header row: pipeline + save + reconvert */}
            <div className="flex flex-wrap items-end gap-4">
              <div className="space-y-1 flex-1 min-w-[180px]">
                <label className="text-xs font-medium text-muted-foreground uppercase">
                  Base Pipeline — {defaultSiem.name}
                </label>
                <select
                  value={siemBasePipeline}
                  onChange={(e) => setSiemBasePipeline(e.target.value)}
                  className="w-full px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none"
                >
                  <option value="ecs_windows">ecs_windows (Winlogbeat / ECS)</option>
                  <option value="ecs_linux">ecs_linux (placeholder)</option>
                  <option value="custom_only">custom_only (mappings only)</option>
                  <option value="none">none (pass-through)</option>
                </select>
              </div>
              <button
                onClick={handleSiemSave}
                disabled={siemMut.isPending}
                className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-primary text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
              >
                <Save className="w-4 h-4" />
                {siemSaved ? "Saved!" : "Save SIEM Config"}
              </button>
              <button
                onClick={handleReconvertAll}
                disabled={reconvertJob?.status === "running"}
                className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-secondary border border-border text-foreground hover:bg-secondary/80 disabled:opacity-50 transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${reconvertJob?.status === "running" ? "animate-spin" : ""}`} />
                Reconvert All Rules
              </button>
            </div>

            {/* Reconvert progress */}
            {reconvertJob && (
              <div className="rounded-lg border border-border bg-background p-3 space-y-1">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">
                    {reconvertJob.status === "running" ? "Reconverting…" :
                      reconvertJob.status === "done" ? "Reconvert complete" :
                      reconvertJob.status === "error" ? "Reconvert failed" : "Idle"}
                  </span>
                  <span className="font-medium text-foreground">
                    {reconvertJob.done}/{reconvertJob.total} rules
                    {reconvertJob.errors > 0 && `, ${reconvertJob.errors} errors`}
                  </span>
                </div>
                {reconvertJob.total > 0 && (
                  <div className="w-full bg-secondary rounded-full h-1.5">
                    <div
                      className="bg-primary h-1.5 rounded-full transition-all"
                      style={{ width: `${Math.round((reconvertJob.done / reconvertJob.total) * 100)}%` }}
                    />
                  </div>
                )}
              </div>
            )}

            {/* Custom global field mappings */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-muted-foreground uppercase">
                  Custom Field Mappings (Sigma field → target field)
                </label>
                <button
                  type="button"
                  onClick={() => setCustomMappingRows((r) => [...r, { sigmaField: "", targetField: "" }])}
                  className="flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  <Plus className="w-3 h-3" /> Add Row
                </button>
              </div>
              {customMappingRows.length === 0 && (
                <p className="text-xs text-muted-foreground italic">No custom mappings. Click "Add Row" to define one.</p>
              )}
              <div className="space-y-1.5">
                {customMappingRows.map((row, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <input
                      value={row.sigmaField}
                      onChange={(e) => setCustomMappingRows((rows) => rows.map((r, j) => j === i ? { ...r, sigmaField: e.target.value } : r))}
                      placeholder="Sigma field (e.g. Hashes)"
                      className="flex-1 px-2 py-1.5 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none"
                    />
                    <span className="text-muted-foreground text-xs">→</span>
                    <input
                      value={row.targetField}
                      onChange={(e) => setCustomMappingRows((rows) => rows.map((r, j) => j === i ? { ...r, targetField: e.target.value } : r))}
                      placeholder="Target field (e.g. file.hash.sha256)"
                      className="flex-1 px-2 py-1.5 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none"
                    />
                    <button
                      type="button"
                      onClick={() => setCustomMappingRows((rows) => rows.filter((_, j) => j !== i))}
                      className="text-destructive hover:opacity-70"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            {/* Per-logsource overrides */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-medium text-muted-foreground uppercase">
                  Per-Logsource Overrides (product/category)
                </label>
                <button
                  type="button"
                  onClick={() => setLogsourceRows((r) => [...r, { key: "", mappings: [{ sigmaField: "", targetField: "" }] }])}
                  className="flex items-center gap-1 text-xs text-primary hover:underline"
                >
                  <Plus className="w-3 h-3" /> Add Logsource
                </button>
              </div>
              {logsourceRows.length === 0 && (
                <p className="text-xs text-muted-foreground italic">No logsource overrides defined.</p>
              )}
              <div className="space-y-3">
                {logsourceRows.map((lsRow, li) => (
                  <div key={li} className="rounded-lg border border-border p-3 space-y-2">
                    <div className="flex items-center gap-2">
                      <input
                        value={lsRow.key}
                        onChange={(e) => setLogsourceRows((rows) => rows.map((r, j) => j === li ? { ...r, key: e.target.value } : r))}
                        placeholder="windows/process_creation"
                        className="flex-1 px-2 py-1.5 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none font-mono"
                      />
                      <button
                        type="button"
                        onClick={() => setLogsourceRows((rows) => rows.filter((_, j) => j !== li))}
                        className="text-destructive hover:opacity-70"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                    <div className="space-y-1.5 pl-2">
                      {lsRow.mappings.map((mRow, mi) => (
                        <div key={mi} className="flex items-center gap-2">
                          <input
                            value={mRow.sigmaField}
                            onChange={(e) => setLogsourceRows((rows) => rows.map((r, j) => j === li
                              ? { ...r, mappings: r.mappings.map((m, k) => k === mi ? { ...m, sigmaField: e.target.value } : m) }
                              : r))}
                            placeholder="Sigma field"
                            className="flex-1 px-2 py-1 text-xs rounded-lg bg-background border border-border text-foreground focus:outline-none"
                          />
                          <span className="text-muted-foreground text-xs">→</span>
                          <input
                            value={mRow.targetField}
                            onChange={(e) => setLogsourceRows((rows) => rows.map((r, j) => j === li
                              ? { ...r, mappings: r.mappings.map((m, k) => k === mi ? { ...m, targetField: e.target.value } : m) }
                              : r))}
                            placeholder="Target field"
                            className="flex-1 px-2 py-1 text-xs rounded-lg bg-background border border-border text-foreground focus:outline-none"
                          />
                          <button
                            type="button"
                            onClick={() => setLogsourceRows((rows) => rows.map((r, j) => j === li
                              ? { ...r, mappings: r.mappings.filter((_, k) => k !== mi) }
                              : r))}
                            className="text-destructive hover:opacity-70"
                          >
                            <Trash2 className="w-3 h-3" />
                          </button>
                        </div>
                      ))}
                      <button
                        type="button"
                        onClick={() => setLogsourceRows((rows) => rows.map((r, j) => j === li
                          ? { ...r, mappings: [...r.mappings, { sigmaField: "", targetField: "" }] }
                          : r))}
                        className="flex items-center gap-1 text-xs text-primary hover:underline"
                      >
                        <Plus className="w-3 h-3" /> Add Field
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Field Discovery */}
            <div className="space-y-2">
              <label className="text-xs font-medium text-muted-foreground uppercase">
                Field Discovery — Browse Elasticsearch Fields
              </label>
              <div className="flex items-center gap-2">
                <input
                  value={fieldIndex}
                  onChange={(e) => setFieldIndex(e.target.value)}
                  placeholder="winlogbeat-*"
                  className="flex-1 px-3 py-2 text-sm rounded-lg bg-background border border-border text-foreground focus:outline-none font-mono"
                />
                <button
                  type="button"
                  onClick={handleBrowseFields}
                  disabled={fieldsLoading}
                  className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg bg-secondary border border-border text-foreground hover:bg-secondary/80 disabled:opacity-50 transition-colors"
                >
                  {fieldsLoading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
                  Browse Fields
                </button>
              </div>
              {fieldsError && (
                <p className="text-xs text-destructive">{fieldsError}</p>
              )}
              {fields !== null && !fieldsError && (
                fields.length === 0 ? (
                  <p className="text-xs text-muted-foreground italic">No fields found for this pattern.</p>
                ) : (
                  <div className="max-h-48 overflow-y-auto rounded-lg border border-border bg-background p-2 space-y-0.5">
                    {fields.map((f) => (
                      <div key={f.name} className="flex items-center justify-between text-xs px-1 py-0.5 hover:bg-secondary rounded">
                        <span className="font-mono text-foreground">{f.name}</span>
                        <span className="text-muted-foreground ml-2 shrink-0">({f.type})</span>
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>
          </div>
        )}
      </Section>
    </div>
  );
}
