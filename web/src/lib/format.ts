import type { RiskTier } from "../types";

export const numberFormat = new Intl.NumberFormat("en-US");

export function formatNumber(value: number | null | undefined): string {
  return value == null ? "—" : numberFormat.format(value);
}

export function formatScore(value: number | null | undefined): string {
  return value == null || !Number.isFinite(value) ? "—" : value.toFixed(1);
}

export function titleCase(value: string | null | undefined): string {
  if (!value) return "Unknown";
  return value.replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function tierClass(tier: RiskTier | string | null | undefined): string {
  return tier ? `tier-${tier.toLowerCase()}` : "tier-unrated";
}

export function statusClass(status: string): string {
  if (status === "confirmed_match" || status === "scored") return "status-confirmed";
  if (status === "unsupported_matching") return "status-unsupported";
  if (status === "pending_manual_review") return "status-review";
  return "status-unresolved";
}

export function matchesQuery(values: unknown[], query: string): boolean {
  if (!query.trim()) return true;
  const needle = query.trim().toLowerCase();
  return values.some((value) => String(value ?? "").toLowerCase().includes(needle));
}
