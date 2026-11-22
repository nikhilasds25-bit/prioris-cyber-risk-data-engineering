import type { DashboardSummary, ReviewRecord, RiskExposure } from "../types";

const DATA_ROOT = "/data/";

async function getJson<T>(name: string): Promise<T> {
  const response = await fetch(`${DATA_ROOT}${name}`);
  if (!response.ok) {
    throw new Error(
      `Could not load ${name} (${response.status}). Regenerate the dashboard export and redeploy.`,
    );
  }
  return (await response.json()) as T;
}

export const loadSummary = () => getJson<DashboardSummary>("dashboard-summary.json");
export const loadConfirmedExposures = () =>
  getJson<RiskExposure[]>("confirmed-exposures.json.gz");
export const loadReviewQueue = () => getJson<ReviewRecord[]>("review-queue.json.gz");
