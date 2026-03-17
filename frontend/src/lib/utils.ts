import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function severityVariant(severity: string) {
  const map: Record<string, string> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
    informational: "info",
  };
  return (map[severity?.toLowerCase()] ?? "secondary") as
    | "critical"
    | "high"
    | "medium"
    | "low"
    | "info"
    | "secondary";
}

export function statusColor(status: string): string {
  const map: Record<string, string> = {
    synced: "text-blue-400",
    converted: "text-cyan-400",
    enhanced: "text-teal-400",
    tested: "text-indigo-400",
    scored: "text-purple-400",
    queued: "text-yellow-400",
    implemented: "text-green-400",
    failed: "text-red-400",
  };
  return map[status] ?? "text-muted-foreground";
}

export function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 60) return "text-yellow-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}

export function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString("en-US", {
    year: "numeric",
    month: "short",
    day: "numeric",
  });
}
