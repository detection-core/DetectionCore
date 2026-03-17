import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Save, RefreshCw } from "lucide-react";
import { getScoringConfig, updateScoringConfig, recalculateScores, getSettings } from "@/api/endpoints";

export default function Settings() {
  const qc = useQueryClient();
  const [saved, setSaved] = useState(false);

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

  const recalcMut = useMutation({
    mutationFn: recalculateScores,
  });

  const [form, setForm] = useState<Record<string, string | number | boolean | string[]>>({});

  const val = (key: string) => form[key] ?? config?.[key] ?? "";

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    updateMut.mutate(form as Record<string, unknown>);
  };

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

  return (
    <form onSubmit={handleSubmit} className="p-6 space-y-5">
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
  );
}
