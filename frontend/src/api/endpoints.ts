import api from "./client";

// Auth
export const login = (username: string, password: string) => {
  const form = new URLSearchParams();
  form.append("username", username);
  form.append("password", password);
  return api.post("/auth/login", form, { headers: { "Content-Type": "application/x-www-form-urlencoded" } });
};
export const getMe = () => api.get("/auth/me");

// Dashboard
export const getDashboardSummary = () => api.get("/dashboard/summary");
export const getPipelineFunnel = () => api.get("/dashboard/pipeline-funnel");
export const getSeverityDistribution = () => api.get("/dashboard/severity-distribution");
export const getMitreCoverage = () => api.get("/dashboard/mitre-coverage");
export const getLogSourceGaps = () => api.get("/dashboard/log-source-gaps");
export const getScoreDistribution = () => api.get("/dashboard/score-distribution");
export const getMitreMatrix = () => api.get("/dashboard/mitre-matrix");
export const getDetectionReport = () => api.get("/dashboard/detection-report");

// Rules
export const getRules = (params?: Record<string, unknown>) => api.get("/rules", { params });
export const getRule = (id: string) => api.get(`/rules/${id}`);
export const getRuleSigma = (id: string) => api.get(`/rules/${id}/sigma`);
export const getRuleElk = (id: string) => api.get(`/rules/${id}/elk`);
export const getRuleTests = (id: string) => api.get(`/rules/${id}/unit-tests`);
export const reprocessRule = (id: string) => api.post(`/rules/${id}/reprocess`);

// Sync
export const triggerSync = () => api.post("/sync/trigger");
export const getSyncJobs = () => api.get("/sync/jobs");
export const getSyncStatus = () => api.get("/sync/status");

// Intake Queue
export const getIntakeQueue = (params?: Record<string, unknown>) => api.get("/intake", { params });
export const getIntakeItem = (id: string) => api.get(`/intake/${id}`);
export const updateIntakeItem = (id: string, data: Record<string, unknown>) => api.patch(`/intake/${id}`, data);
export const deployToElk = (id: string) => api.post(`/intake/${id}/deploy-to-elk`);

// Log Sources
export const getLogSources = () => api.get("/log-sources");
export const uploadLogSources = (file: File) => {
  const form = new FormData();
  form.append("file", file);
  return api.post("/log-sources/upload", form);
};
export const updateLogSource = (id: string, data: Record<string, unknown>) => api.put(`/log-sources/${id}`, data);
export const deleteLogSource = (id: string) => api.delete(`/log-sources/${id}`);
export const autoDiscoverLogSources = () => api.post("/log-sources/auto-discover");
export const getLogSourceCoverageSummary = () => api.get("/log-sources/coverage-summary");

// ELK
export const getElkStatus = () => api.get("/elk/status");
export const getElkIndices = () => api.get("/elk/indices");
export const runUnitTest = (ruleId: string, testId: string) =>
  api.post("/elk/run-test", { rule_id: ruleId, test_id: testId });

// Scoring
export const getScoringConfig = () => api.get("/scoring/config");
export const updateScoringConfig = (data: Record<string, unknown>) => api.put("/scoring/config", data);
export const recalculateScores = () => api.post("/scoring/recalculate-all");

// Settings
export const getSettings = () => api.get("/settings");

// SIEM Integrations
export const getSiemIntegrations = () => api.get("/settings/siem-integrations");
export const getSiemIntegration = (id: string) => api.get(`/settings/siem-integrations/${id}`);
export const updateSiemIntegration = (id: string, data: Record<string, unknown>) =>
  api.put(`/settings/siem-integrations/${id}`, data);
export const createSiemIntegration = (data: Record<string, unknown>) =>
  api.post("/settings/siem-integrations", data);

// Reconvert
export const reconvertAllRules = () => api.post("/rules/reconvert-all");
export const getReconvertStatus = () => api.get("/rules/reconvert-status");

// ELK Field Discovery
export const getElkFields = (index: string) => api.get("/elk/fields", { params: { index } });
