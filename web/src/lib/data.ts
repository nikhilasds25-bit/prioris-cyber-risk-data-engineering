import type { DashboardSummary, ReviewRecord, RiskExposure } from "../types";

const DATA_ROOT = "/data/";
const API_ROOT = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
const PAGE_SIZE = 200;

async function getJson<T>(name: string): Promise<T> {
  const response = await fetch(`${DATA_ROOT}${name}`);
  if (!response.ok) {
    throw new Error(
      `Could not load ${name} (${response.status}). Regenerate the dashboard export and redeploy.`,
    );
  }
  return (await response.json()) as T;
}

async function getApiJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_ROOT}${path}`);
  if (!response.ok) {
    throw new Error(`PRIORIS API request failed (${response.status}) for ${path}.`);
  }
  return (await response.json()) as T;
}

async function getAllApiRecords<T>(path: string): Promise<T[]> {
  const first = await getApiJson<{
    total: number;
    offset: number;
    limit: number;
    items: T[];
  }>(`${path}?offset=0&limit=${PAGE_SIZE}`);

  const records = [...first.items];
  for (let offset = first.limit; offset < first.total; offset += PAGE_SIZE) {
    const page = await getApiJson<{
      total: number;
      offset: number;
      limit: number;
      items: T[];
    }>(`${path}?offset=${offset}&limit=${PAGE_SIZE}`);
    records.push(...page.items);
  }
  return records;
}

// Without VITE_API_BASE_URL, the dashboard keeps using its current static exports.
// When configured, API failures are surfaced instead of silently showing stale data.
export const loadSummary = () =>
  API_ROOT
    ? getApiJson<DashboardSummary>("/api/v1/dashboard/summary")
    : getJson<DashboardSummary>("dashboard-summary.json");

export const loadConfirmedExposures = () =>
  API_ROOT
    ? getAllApiRecords<RiskExposure>("/api/v1/exposures/confirmed")
    : getJson<RiskExposure[]>("confirmed-exposures.json.gz");

export const loadReviewQueue = () =>
  API_ROOT
    ? getAllApiRecords<ReviewRecord>("/api/v1/exposures/review")
    : getJson<ReviewRecord[]>("review-queue.json.gz");
