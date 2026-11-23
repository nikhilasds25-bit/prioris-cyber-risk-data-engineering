export interface OrganizationInfo {
  id: string;
  name: string;
  slug: string;
  role: "admin" | "analyst" | "viewer";
}

export interface EnterpriseSession {
  access_token: string;
  token_type: "bearer";
  expires_in: number;
  user: { id: string; email: string };
  organizations: OrganizationInfo[];
}

export interface EnterpriseAsset {
  asset_id: string;
  asset_name: string | null;
  asset_type: string | null;
  hostname: string | null;
  ip_address: string | null;
  operating_system: string | null;
  business_criticality: string | null;
  internet_exposed: boolean | null;
  affected_installations: number;
  distinct_cves: number;
  critical_high_findings: number;
  known_exploited_findings: number;
  max_risk_score: number | null;
  risk_tier: string | null;
  top_cve: string | null;
  risk_reasons: string[];
}

export interface EnterpriseExposure {
  asset_id: string;
  software_name: string | null;
  installed_version: string | null;
  cve_id: string | null;
  vulnerability_name: string | null;
  severity: string | null;
  cvss_score: number | null;
  known_exploited: boolean | null;
  remediation_status: string | null;
  first_detected: string | null;
  applicability_status: string;
  risk_score: number | null;
  risk_tier: string | null;
  risk_factors: Record<string, number>;
  missing_evidence: string[];
  source_evidence: Record<string, unknown>;
}

export interface EnterpriseImport {
  id: string;
  filename: string;
  status: string;
  rows_total: number;
  rows_valid: number;
  rows_invalid: number;
  rows_duplicate: number;
  records_imported: number;
  created_at: string;
  completed_at: string | null;
  detected_columns: string[];
  column_mapping: Record<string, string | null>;
  validation_errors: Array<{ row: number; field: string; message: string }>;
  validation_errors_truncated: boolean;
}

export interface EnterpriseSummary {
  latest_import_id: string | null;
  total_assets: number;
  total_records: number;
  total_installed_software_records: number;
  affected_installations: number;
  reported_vulnerability_records: number;
  distinct_cves: number;
  unresolved_records: number;
  multi_critical_high_assets: number;
  internet_facing_assets: number;
  risk_tiers: Record<"critical" | "high" | "medium" | "low", number>;
  status_counts: Record<string, number>;
  top_assets: EnterpriseAsset[];
  top_cves: Array<{
    cve_id: string;
    severity: string | null;
    cvss_score: number | null;
    risk_score: number | null;
    risk_tier: string | null;
    known_exploited: boolean | null;
    affected_assets: number;
    reported_installations: number;
  }>;
  known_exploited_cves: Array<{
    cve_id: string;
    vulnerability_name: string | null;
    severity: string | null;
    cvss_score: number | null;
    risk_score: number | null;
    risk_tier: string | null;
    known_exploited: boolean | null;
    affected_assets: number;
    reported_installations: number;
    internet_exposed_assets: number;
    criticality_assets: number;
    risk_factors: Record<string, number>;
    missing_evidence: string[];
    applicability_status: string;
    applicability_statuses: string[];
  }>;
  prioritized_remediation: Array<{
    cve_id: string;
    vulnerability_name: string | null;
    severity: string | null;
    cvss_score: number | null;
    risk_score: number | null;
    risk_tier: string | null;
    known_exploited: boolean | null;
    affected_assets: number;
    reported_installations: number;
    internet_exposed_assets: number;
    criticality_assets: number;
    risk_factors: Record<string, number>;
    missing_evidence: string[];
    applicability_status: string;
    applicability_statuses: string[];
    suggested_priority: string;
    risk_evidence: string[];
    recommended_action: string;
  }>;
  top_software: Array<{
    software_name: string;
    installed_version: string | null;
    affected_assets: number;
    distinct_cves: number;
    risk_score: number | null;
    risk_tier: string | null;
  }>;
  executive_summary: {
    biggest_security_problem: string;
    immediate_attention: Array<{
      asset_id: string;
      asset_name: string | null;
      risk_score: number | null;
      reasons: string[];
    }>;
    greatest_software_exposure: string;
    fix_first: string;
  };
  limitations: string[];
}

export interface DatasetPreview {
  filename: string;
  file_size_bytes: number;
  detected_columns: string[];
  canonical_fields: string[];
  suggested_mapping: Record<string, string | null>;
  mapping_errors: string[];
  validation: {
    rows_total: number;
    rows_valid: number;
    rows_invalid: number;
    rows_duplicate: number;
  };
  validation_errors: Array<{ row: number; field: string; message: string }>;
  validation_errors_truncated: boolean;
}

export interface Page<T> {
  total: number;
  offset: number;
  limit: number;
  items: T[];
}

const API_ROOT = (import.meta.env.VITE_API_BASE_URL ?? "").replace(/\/$/, "");
const SESSION_KEY = "prioris.enterprise.session";

export function getStoredSession(): EnterpriseSession | null {
  try {
    const raw = sessionStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as EnterpriseSession) : null;
  } catch {
    sessionStorage.removeItem(SESSION_KEY);
    return null;
  }
}

export function storeSession(session: EnterpriseSession | null): void {
  if (session) sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
  else sessionStorage.removeItem(SESSION_KEY);
}

export function apiRoot(): string {
  return API_ROOT;
}

async function decodeError(response: Response): Promise<Error> {
  const body: unknown = await response.json().catch(() => null);
  if (body && typeof body === "object" && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return new Error(detail);
    return new Error(JSON.stringify(detail));
  }
  return new Error(`PRIORIS request failed (${response.status}).`);
}

async function request<T>(
  path: string,
  session?: EnterpriseSession,
  organizationId?: string,
  init?: RequestInit,
): Promise<T> {
  const headers = new Headers(init?.headers);
  if (session) headers.set("Authorization", `Bearer ${session.access_token}`);
  if (organizationId) headers.set("X-Organization-ID", organizationId);
  const response = await fetch(`${API_ROOT}${path}`, { ...init, headers });
  if (!response.ok) throw await decodeError(response);
  return (await response.json()) as T;
}

export function authenticate(
  mode: "login" | "register",
  payload: { email: string; password: string; organization_name?: string },
): Promise<EnterpriseSession> {
  return request(`/api/v1/auth/${mode}`, undefined, undefined, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export function acceptInvitation(token: string, password: string): Promise<{ status: string }> {
  return request("/api/v1/organizations/invitations/accept", undefined, undefined, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ token, password }),
  });
}

export function logoutRequest(session: EnterpriseSession, organizationId: string): Promise<{ status: string }> {
  return request("/api/v1/auth/logout", session, organizationId, { method: "POST" });
}

export function loadEnterpriseSummary(session: EnterpriseSession, orgId: string) {
  return request<EnterpriseSummary>("/api/v1/enterprise/summary", session, orgId);
}

export function loadEnterpriseAssets(session: EnterpriseSession, orgId: string, offset: number, q: string) {
  const params = new URLSearchParams({ offset: String(offset), limit: "20" });
  if (q) params.set("q", q);
  return request<Page<EnterpriseAsset>>(`/api/v1/enterprise/assets?${params}`, session, orgId);
}

export function loadEnterpriseExposures(
  session: EnterpriseSession,
  orgId: string,
  offset: number,
  q: string,
  statusFilter: string,
) {
  const params = new URLSearchParams({ offset: String(offset), limit: "20" });
  if (q) params.set("q", q);
  if (statusFilter !== "all") params.set("applicability_status", statusFilter);
  return request<Page<EnterpriseExposure>>(`/api/v1/enterprise/exposures?${params}`, session, orgId);
}

export function loadImports(session: EnterpriseSession, orgId: string) {
  return request<Page<EnterpriseImport>>("/api/v1/enterprise/imports?limit=50", session, orgId);
}

export function previewFile(
  file: File,
  mapping: Record<string, string | null>,
  session: EnterpriseSession,
  orgId: string,
  onProgress: (progress: number) => void,
): Promise<DatasetPreview> {
  return uploadRequest("/api/v1/enterprise/imports/preview", file, mapping, session, orgId, onProgress);
}

export function importFile(
  file: File,
  mapping: Record<string, string | null>,
  session: EnterpriseSession,
  orgId: string,
  onProgress: (progress: number) => void,
) {
  return uploadRequest<{ id: string; status: string; records_imported: number; validation: DatasetPreview["validation"] }>(
    "/api/v1/enterprise/imports",
    file,
    mapping,
    session,
    orgId,
    onProgress,
  );
}

function uploadRequest<T>(
  path: string,
  file: File,
  mapping: Record<string, string | null>,
  session: EnterpriseSession,
  orgId: string,
  onProgress: (progress: number) => void,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open("POST", `${API_ROOT}${path}`);
    request.setRequestHeader("Authorization", `Bearer ${session.access_token}`);
    request.setRequestHeader("X-Organization-ID", orgId);
    request.upload.onprogress = (event) => {
      if (event.lengthComputable) onProgress(Math.round((event.loaded / event.total) * 100));
    };
    request.onerror = () => reject(new Error("Upload failed because the API could not be reached."));
    request.onload = () => {
      let body: unknown;
      try {
        body = JSON.parse(request.responseText);
      } catch {
        body = null;
      }
      if (request.status < 200 || request.status >= 300) {
        const detail = body && typeof body === "object" && "detail" in body
          ? (body as { detail: unknown }).detail
          : `PRIORIS upload failed (${request.status}).`;
        reject(new Error(typeof detail === "string" ? detail : JSON.stringify(detail)));
        return;
      }
      resolve(body as T);
    };
    const form = new FormData();
    form.append("upload", file, file.name);
    form.append("mapping_json", JSON.stringify(mapping));
    request.send(form);
  });
}

export async function listMembers(session: EnterpriseSession, orgId: string) {
  return request<Array<{ user_id: string; email: string; role: string; is_active: boolean; joined_at: string }>>(
    "/api/v1/organizations/current/members", session, orgId,
  );
}

export async function updateMember(
  session: EnterpriseSession,
  orgId: string,
  userId: string,
  update: { role?: string; is_active?: boolean },
) {
  return request<{ user_id: string; role: string; is_active: boolean }>(
    `/api/v1/organizations/current/members/${encodeURIComponent(userId)}`,
    session,
    orgId,
    {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(update),
    },
  );
}

export async function createInvitation(
  session: EnterpriseSession,
  orgId: string,
  email: string,
  role: string,
) {
  return request<{ invitation_token: string; email: string; role: string; expires_at: string }>(
    "/api/v1/organizations/invitations", session, orgId, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, role }),
    },
  );
}

export async function listAuditLogs(session: EnterpriseSession, orgId: string) {
  return request<Array<{
    id: string;
    actor_user_id: string | null;
    action: string;
    target_type: string | null;
    target_id: string | null;
    details: Record<string, unknown>;
    created_at: string;
  }>>("/api/v1/organizations/current/audit-logs?limit=100", session, orgId);
}

export async function downloadImportErrors(
  importId: string,
  session: EnterpriseSession,
  orgId: string,
): Promise<Blob> {
  const response = await fetch(`${API_ROOT}/api/v1/enterprise/imports/${importId}/errors.csv`, {
    headers: {
      Authorization: `Bearer ${session.access_token}`,
      "X-Organization-ID": orgId,
    },
  });
  if (!response.ok) throw await decodeError(response);
  return response.blob();
}
