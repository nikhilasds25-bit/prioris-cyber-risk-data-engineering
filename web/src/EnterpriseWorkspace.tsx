import { useCallback, useEffect, useMemo, useRef, useState, type DragEvent, type FormEvent } from "react";
import {
  AlertCircle, ArrowDownToLine, Building2, Check, ChevronLeft, ChevronRight,
  CircleHelp, FileSpreadsheet, FileUp, Globe2, ListChecks, LoaderCircle,
  LogOut, RefreshCw, ShieldAlert, ShieldCheck, Users, Wrench, X,
} from "lucide-react";
import {
  acceptInvitation,
  authenticate,
  createInvitation,
  downloadImportErrors,
  getStoredSession,
  importFile,
  listAuditLogs,
  loadImports,
  listMembers,
  loadEnterpriseAssets,
  loadEnterpriseExposures,
  loadEnterpriseSummary,
  logoutRequest,
  previewFile,
  storeSession,
  updateMember,
  type DatasetPreview,
  type EnterpriseAsset,
  type EnterpriseExposure,
  type EnterpriseImport,
  type EnterpriseSession,
  type EnterpriseSummary,
} from "./lib/enterprise-api";
import { revokeAndClearLocalSession } from "./lib/logout";
import { formatNumber, formatScore, titleCase } from "./lib/format";

type EnterprisePage = "overview" | "upload" | "assets" | "findings" | "team" | "audit";

const pageLabels: Record<EnterprisePage, string> = {
  overview: "Company overview",
  upload: "Dataset onboarding",
  assets: "Asset inventory",
  findings: "Vulnerability findings",
  team: "Organisation team",
  audit: "Audit log",
};

const canonicalLabels: Record<string, string> = {
  asset_id: "Asset ID *",
  asset_name: "Asset name",
  asset_type: "Asset type",
  hostname: "Hostname",
  ip_address: "IP address",
  operating_system: "Operating system",
  software_name: "Software name",
  installed_version: "Installed version",
  cve_id: "CVE ID",
  vulnerability_name: "Vulnerability name",
  severity: "Severity",
  cvss_score: "CVSS score",
  business_criticality: "Business criticality",
  internet_exposed: "Internet exposed",
  exposure: "Network exposure class",
  known_exploited: "Known exploited",
  remediation_status: "Remediation status",
  first_detected: "First detected",
};

function sessionFromStorage(): EnterpriseSession | null {
  return getStoredSession();
}

function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

function StatusPill({ status }: { status: string }) {
  return <span className={`enterprise-status enterprise-status-${status}`}>{titleCase(status)}</span>;
}

function RiskTier({ tier }: { tier: string | null }) {
  return tier
    ? <span className={`enterprise-tier enterprise-tier-${tier}`}>{titleCase(tier)}</span>
    : <span className="enterprise-tier enterprise-tier-unrated">Unscored</span>;
}

export default function EnterpriseWorkspace() {
  const [session, setSession] = useState<EnterpriseSession | null>(sessionFromStorage);
  const [organizationId, setOrganizationId] = useState("");
  const [page, setPage] = useState<EnterprisePage>("overview");
  const [summary, setSummary] = useState<EnterpriseSummary | null>(null);
  const [imports, setImports] = useState<EnterpriseImport[]>([]);
  const [assets, setAssets] = useState<EnterpriseAsset[]>([]);
  const [exposures, setExposures] = useState<EnterpriseExposure[]>([]);
  const [team, setTeam] = useState<Array<{ user_id: string; email: string; role: string; is_active: boolean; joined_at: string }>>([]);
  const [auditLogs, setAuditLogs] = useState<Array<{
    id: string; actor_user_id: string | null; action: string;
    target_type: string | null; target_id: string | null;
    details: Record<string, unknown>; created_at: string;
  }>>([]);
  const [listTotal, setListTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    if (session?.organizations.length && !session.organizations.some((org) => org.id === organizationId)) {
      setOrganizationId(session.organizations[0].id);
    }
  }, [session, organizationId]);

  const refresh = useCallback(async () => {
    if (!session || !organizationId) return;
    setBusy(true);
    setError("");
    try {
      if (page === "overview" || page === "upload") {
        const [summaryResult, importResult] = await Promise.all([
          loadEnterpriseSummary(session, organizationId),
          loadImports(session, organizationId),
        ]);
        setSummary(summaryResult);
        setImports(importResult.items);
      } else if (page === "assets") {
        const result = await loadEnterpriseAssets(session, organizationId, offset, query.trim());
        setAssets(result.items);
        setListTotal(result.total);
      } else if (page === "findings") {
        const result = await loadEnterpriseExposures(
          session, organizationId, offset, query.trim(), statusFilter,
        );
        setExposures(result.items);
        setListTotal(result.total);
      } else if (page === "team" && activeOrganization?.role === "admin") {
        setTeam(await listMembers(session, organizationId));
      } else if (page === "audit" && activeOrganization?.role === "admin") {
        setAuditLogs(await listAuditLogs(session, organizationId));
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The company workspace could not be loaded.");
    } finally {
      setBusy(false);
    }
  }, [session, organizationId, page, offset, query, statusFilter]);

  const activeOrganization = session?.organizations.find((org) => org.id === organizationId);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const signOut = async () => {
    if (!session) return;
    setError("");
    setNotice("");
    const outcome = await revokeAndClearLocalSession(
      session,
      organizationId,
      logoutRequest,
      () => {
        setSession(null);
        setOrganizationId("");
        setSummary(null);
        setImports([]);
        setAssets([]);
        setExposures([]);
        setTeam([]);
        setAuditLogs([]);
        storeSession(null);
      },
    );
    if (outcome.revoked) {
      setNotice("Signed out. The server revoked this access token.");
    } else {
      setError(
        "Local session cleared, but server-side token revocation failed. " +
        "The access token may remain valid until it expires. Check API connectivity; " +
        "this browser tab will not reuse the discarded session.",
      );
    }
  };

  const handleAuthenticated = (value: EnterpriseSession) => {
    storeSession(value);
    setSession(value);
    setOrganizationId(value.organizations[0]?.id ?? "");
    setPage("overview");
    setError("");
    setNotice("Secure company workspace ready.");
  };

  if (!session) {
    return (
      <EnterpriseAuth
        notice={notice}
        onAuthenticated={handleAuthenticated}
        onError={setError}
        error={error}
      />
    );
  }

  return (
    <section className="enterprise-workspace" aria-label="Enterprise workspace">
      <header className="enterprise-header">
        <div className="enterprise-header-brand">
          <span className="enterprise-brand-mark"><Building2 size={18} /></span>
          <div><b>Company workspace</b><small>Tenant-scoped enterprise data</small></div>
        </div>
        <div className="enterprise-header-actions">
          {session.organizations.length > 1 && (
            <label className="enterprise-org-select">
              <span className="sr-only">Active organisation</span>
              <select value={organizationId} onChange={(event) => {
                setOrganizationId(event.target.value);
                setOffset(0);
              }}>
                {session.organizations.map((org) => <option value={org.id} key={org.id}>{org.name}</option>)}
              </select>
            </label>
          )}
          <span className="enterprise-user">{session.user.email} · {activeOrganization?.role}</span>
          <button className="enterprise-icon-button" onClick={signOut} title="Sign out" aria-label="Sign out">
            <LogOut size={16} />
          </button>
        </div>
      </header>

      <nav className="enterprise-nav" aria-label="Company workspace navigation">
        {(["overview", "upload", "assets", "findings", "team", "audit"] as const).map((item) => {
          if ((item === "team" || item === "audit") && activeOrganization?.role !== "admin") return null;
          const Icon = item === "upload" ? FileUp : item === "team" ? Users : item === "findings" ? ShieldAlert : item === "audit" ? CircleHelp : Building2;
          return (
            <button key={item} className={page === item ? "enterprise-nav-active" : ""} onClick={() => {
              setPage(item);
              setOffset(0);
              setError("");
            }}>
              <Icon size={15} />{pageLabels[item]}
            </button>
          );
        })}
      </nav>

      <div className="enterprise-page-heading">
        <div><span className="enterprise-eyebrow">PRIORIS / PRIVATE TENANT</span><h2>{pageLabels[page]}</h2></div>
        <div className="enterprise-heading-actions">
          {(page === "assets" || page === "findings") && (
            <input
              aria-label="Search company records"
              placeholder="Search asset, product or CVE"
              value={query}
              onChange={(event) => { setQuery(event.target.value); setOffset(0); }}
            />
          )}
          <button className="enterprise-button enterprise-button-quiet" onClick={() => void refresh()} disabled={busy}>
            {busy ? <LoaderCircle size={15} className="enterprise-spin" /> : <RefreshCw size={15} />}
            Refresh
          </button>
        </div>
      </div>

      {notice && <div className="enterprise-notice"><Check size={15} />{notice}<button onClick={() => setNotice("")} aria-label="Dismiss"><X size={14} /></button></div>}
      {error && <div className="enterprise-error" role="alert"><AlertCircle size={16} />{error}<button onClick={() => setError("")} aria-label="Dismiss error"><X size={14} /></button></div>}

      {page === "overview" && (
        <EnterpriseOverview
          summary={summary}
          imports={imports}
          busy={busy}
          onUpload={() => setPage("upload")}
          onFindings={() => setPage("findings")}
          onAsset={() => setPage("assets")}
        />
      )}
      {page === "upload" && (
        <UploadPanel
          session={session}
          organizationId={organizationId}
          imports={imports}
          refresh={refresh}
          onSuccess={(message) => { setNotice(message); setError(""); }}
          onError={setError}
        />
      )}
      {page === "assets" && (
        <AssetTable
          rows={assets}
          busy={busy}
          total={listTotal}
          offset={offset}
          onPage={setOffset}
          onFindings={() => setPage("findings")}
        />
      )}
      {page === "findings" && (
        <FindingsTable
          rows={exposures}
          busy={busy}
          total={listTotal}
          offset={offset}
          statusFilter={statusFilter}
          onStatus={setStatusFilter}
          onPage={setOffset}
        />
      )}
      {page === "team" && activeOrganization?.role === "admin" && (
        <TeamPanel
          session={session}
          organizationId={organizationId}
          rows={team}
          onInvite={(token) => setNotice(`Invitation created. Copy this one-time token: ${token}`)}
          onError={setError}
          refresh={refresh}
        />
      )}
      {page === "audit" && activeOrganization?.role === "admin" && <AuditPanel rows={auditLogs} />}
    </section>
  );
}

function EnterpriseAuth({
  notice,
  error,
  onAuthenticated,
  onError,
}: {
  notice: string;
  error: string;
  onAuthenticated: (session: EnterpriseSession) => void;
  onError: (message: string) => void;
}) {
  const [mode, setMode] = useState<"login" | "register" | "invite">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [organizationName, setOrganizationName] = useState("");
  const [inviteToken, setInviteToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [localNotice, setLocalNotice] = useState("");

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    onError("");
    setLocalNotice("");
    try {
      if (mode === "invite") {
        await acceptInvitation(inviteToken.trim(), password);
        setMode("login");
        setPassword("");
        setLocalNotice("Invitation accepted. Sign in to open the organisation.");
      } else {
        const session = await authenticate(mode, {
          email,
          password,
          ...(mode === "register" ? { organization_name: organizationName } : {}),
        });
        onAuthenticated(session);
      }
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Authentication failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="enterprise-auth-wrap">
      <div className="enterprise-auth-card">
        <div className="enterprise-auth-mark"><Building2 size={22} /></div>
        <span className="enterprise-eyebrow">PRIORIS / ENTERPRISE</span>
        <h2>{mode === "login" ? "Sign in to your company" : mode === "register" ? "Create your organisation" : "Accept an invitation"}</h2>
        <p>Private, organisation-scoped inventory and risk evidence.</p>
        {(notice || localNotice) && <div className="enterprise-notice"><Check size={15} />{notice || localNotice}</div>}
        {error && <div className="enterprise-error" role="alert"><AlertCircle size={15} />{error}</div>}
        <form onSubmit={submit} className="enterprise-auth-form">
          {mode === "invite" ? (
            <label>Invitation token<input value={inviteToken} onChange={(event) => setInviteToken(event.target.value)} required minLength={32} autoComplete="off" /></label>
          ) : (
            <label>Email address<input type="email" autoComplete="email" value={email} onChange={(event) => setEmail(event.target.value)} required maxLength={320} /></label>
          )}
          {mode === "register" && (
            <label>Organisation name<input value={organizationName} onChange={(event) => setOrganizationName(event.target.value)} required minLength={2} maxLength={160} /></label>
          )}
          <label>Password<input type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} value={password} onChange={(event) => setPassword(event.target.value)} required minLength={mode === "login" ? 1 : 12} maxLength={128} /></label>
          <button className="enterprise-button enterprise-button-primary" disabled={busy}>
            {busy ? <LoaderCircle size={16} className="enterprise-spin" /> : <ShieldCheck size={16} />}
            {mode === "login" ? "Sign in" : mode === "register" ? "Create workspace" : "Accept invitation"}
          </button>
        </form>
        <div className="enterprise-auth-switch">
          {mode !== "login" && <button onClick={() => { setMode("login"); onError(""); }}>Sign in</button>}
          {mode !== "register" && <button onClick={() => { setMode("register"); onError(""); }}>Create organisation</button>}
          {mode !== "invite" && <button onClick={() => { setMode("invite"); onError(""); }}>Accept an invite</button>}
        </div>
        <small className="enterprise-security-note">Access tokens are held only for this browser tab. Use HTTPS for deployed environments.</small>
      </div>
    </section>
  );
}

function EnterpriseOverview({
  summary, imports, busy, onUpload, onFindings, onAsset,
}: {
  summary: EnterpriseSummary | null;
  imports: EnterpriseImport[];
  busy: boolean;
  onUpload: () => void;
  onFindings: () => void;
  onAsset: () => void;
}) {
  if (!summary && busy) return <div className="enterprise-loading"><LoaderCircle size={20} className="enterprise-spin" />Loading private tenant data…</div>;
  if (!summary || !summary.latest_import_id) {
    return (
      <div className="enterprise-empty-state">
        <FileSpreadsheet size={28} />
        <h3>No company dataset yet</h3>
        <p>Upload an inventory or vulnerability report to create this organisation’s private workspace.</p>
        <button className="enterprise-button enterprise-button-primary" onClick={onUpload}><FileUp size={16} />Start dataset onboarding</button>
        <small>Company data is stored separately from the Synthetic Demo dashboard.</small>
      </div>
    );
  }
  const totalRisked = Object.values(summary.risk_tiers).reduce((sum, count) => sum + count, 0);
  const tierEntries = Object.entries(summary.risk_tiers) as Array<[string, number]>;
  return (
    <div className="enterprise-content">
      <div className="enterprise-snapshot-note"><ShieldCheck size={15} />Private tenant data · latest import only · not mixed with synthetic demo data</div>
      <div className="enterprise-metric-grid">
        <EnterpriseMetric label="Assets" value={summary.total_assets} caption="In the latest inventory snapshot" />
        <EnterpriseMetric label="Source records" value={summary.total_records} caption="Rows provided by the latest upload" />
        <EnterpriseMetric label="Installed software" value={summary.total_installed_software_records} caption="Distinct asset, product and version combinations" />
        <EnterpriseMetric label="Reported vulnerability records" value={summary.reported_vulnerability_records} caption="Rows with a supplied CVE identifier" />
        <EnterpriseMetric label="Distinct CVEs" value={summary.distinct_cves} caption="Unique supplied CVE identifiers" />
        <EnterpriseMetric label="Scored installations" value={summary.affected_installations} caption="Installations with supplied CVSS and usable score evidence" />
        <EnterpriseMetric label="Review required" value={summary.unresolved_records} caption="Unresolved products or manual review" />
        <EnterpriseMetric label="Multiple Critical / High" value={summary.multi_critical_high_assets} caption="Assets with at least two scored Critical/High reports" />
        <EnterpriseMetric label="Internet-facing assets" value={summary.internet_facing_assets} caption="Explicitly marked in this latest inventory" />
      </div>
      <section className="enterprise-panel enterprise-executive-summary">
        <div className="enterprise-panel-title">
          <div><span className="enterprise-eyebrow">EXECUTIVE BRIEF · LATEST IMPORT</span><h3>What needs attention first</h3></div>
          <ListChecks size={17} />
        </div>
        <div className="enterprise-executive-grid">
          <article><span>Biggest reported problem</span><b>{summary.executive_summary.biggest_security_problem}</b></article>
          <article><span>Greatest software exposure</span><b>{summary.executive_summary.greatest_software_exposure}</b></article>
          <article><span>First remediation step</span><b>{summary.executive_summary.fix_first}</b></article>
        </div>
        <div className="enterprise-attention-assets">
          <b>Assets for immediate review</b>
          {summary.executive_summary.immediate_attention.length ? (
            <ol>{summary.executive_summary.immediate_attention.map((asset) => (
              <li key={asset.asset_id}>
                <span><strong>{asset.asset_name || asset.asset_id}</strong><small>{asset.asset_id}</small></span>
                <span className="enterprise-attention-score">Score {formatScore(asset.risk_score)}</span>
                <small>{asset.reasons.join(" · ")}</small>
              </li>
            ))}</ol>
          ) : <p className="enterprise-muted">No scored assets are available for ranking.</p>}
        </div>
        <small>These are prioritisation signals from the authenticated organisation’s latest import, not independent confirmation that a reported vulnerability affects a product.</small>
      </section>
      <div className="enterprise-grid-two">
        <section className="enterprise-panel">
          <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">RISK SIGNAL</span><h3>Scored reported findings</h3></div><button className="enterprise-text-button" onClick={onFindings}>View records <ChevronRight size={14} /></button></div>
          {totalRisked === 0 ? <p className="enterprise-muted">No records have sufficient CVSS evidence to calculate a risk score.</p> : (
            <div className="enterprise-tier-bars">
              {tierEntries.map(([tier, count]) => (
                <div className="enterprise-tier-row" key={tier}>
                  <span>{titleCase(tier)}</span><div className="enterprise-tier-track"><i className={`enterprise-bar-${tier}`} style={{ width: `${count === 0 ? 0 : (count / totalRisked) * 100}%` }} /></div><b>{formatNumber(count)}</b>
                </div>
              ))}
            </div>
          )}
          <small>Score calculation uses the existing PRIORIS factor definitions and supplied evidence only.</small>
        </section>
        <section className="enterprise-panel">
          <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">DATA ONBOARDING</span><h3>Recent imports</h3></div><button className="enterprise-text-button" onClick={onUpload}>Upload data <ChevronRight size={14} /></button></div>
          {imports.length ? imports.slice(0, 5).map((item) => (
            <div className="enterprise-import-row" key={item.id}>
              <FileSpreadsheet size={15} /><span><b>{item.filename}</b><small>{new Date(item.created_at).toLocaleString()}</small></span><StatusPill status={item.status} />
            </div>
          )) : <p className="enterprise-muted">No imports yet.</p>}
        </section>
      </div>
      <div className="enterprise-grid-two">
        <section className="enterprise-panel">
          <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">ASSET PRIORITIZATION</span><h3>Highest-risk reported assets</h3></div><button className="enterprise-text-button" onClick={onAsset}>All assets <ChevronRight size={14} /></button></div>
          {summary.top_assets.length ? summary.top_assets.slice(0, 5).map((asset) => (
            <div className="enterprise-ranking-row" key={asset.asset_id}>
              <div><b>{asset.asset_name || asset.asset_id}</b><small>{asset.asset_id} · {titleCase(asset.business_criticality)} · {asset.critical_high_findings} Critical/High</small><small>{asset.risk_reasons.join(" · ")}</small></div>
              <span><RiskTier tier={asset.risk_tier} /><b>{formatScore(asset.max_risk_score)}</b></span>
            </div>
          )) : <p className="enterprise-muted">No asset-risk records are available.</p>}
        </section>
        <section className="enterprise-panel">
          <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">CVE INTELLIGENCE</span><h3>Highest-ranked reported CVEs</h3></div><button className="enterprise-text-button" onClick={onFindings}>All findings <ChevronRight size={14} /></button></div>
          {summary.top_cves.length ? summary.top_cves.slice(0, 5).map((cve) => (
            <div className="enterprise-ranking-row" key={cve.cve_id}>
              <div><b>{cve.cve_id}</b><small>{titleCase(cve.severity)} · supplied CVSS {formatScore(cve.cvss_score)} · {cve.known_exploited === true ? "Reported KEV" : cve.known_exploited === false ? "KEV false in supplied data" : "KEV status unknown"}</small></div>
              <span><b>{formatNumber(cve.affected_assets)} assets</b><small>Score {formatScore(cve.risk_score)}</small></span>
            </div>
          )) : <p className="enterprise-muted">No CVE identifiers were supplied.</p>}
        </section>
      </div>
      <div className="enterprise-grid-two">
        <section className="enterprise-panel">
          <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">EXPLOITATION SIGNAL</span><h3>Reported known-exploited vulnerabilities</h3></div><ShieldAlert size={17} /></div>
          {summary.known_exploited_cves.length ? summary.known_exploited_cves.slice(0, 8).map((cve) => (
            <div className="enterprise-ranking-row" key={cve.cve_id}>
              <div><b>{cve.cve_id}</b><small>{cve.vulnerability_name || "No vulnerability title supplied"} · {cve.internet_exposed_assets} internet-facing asset(s)</small></div>
              <span><b>{formatNumber(cve.affected_assets)} assets</b><small>Score {formatScore(cve.risk_score)}</small></span>
            </div>
          )) : <p className="enterprise-muted">No records explicitly report a known-exploited status. Missing KEV data is not treated as false.</p>}
          <small>KEV status is taken from the uploaded evidence; PRIORIS does not independently query CISA.</small>
        </section>
        <section className="enterprise-panel">
          <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">SOFTWARE EXPOSURE</span><h3>Products on the most reported assets</h3></div><Globe2 size={17} /></div>
          {summary.top_software.length ? summary.top_software.slice(0, 8).map((product, index) => (
            <div className="enterprise-ranking-row" key={`${product.software_name}-${product.installed_version ?? ""}`}>
              <div><b>{index + 1}. {product.software_name}</b><small>Version {product.installed_version || "not supplied"} · {product.distinct_cves} reported CVE(s)</small></div>
              <span><b>{formatNumber(product.affected_assets)} assets</b><small>Score {formatScore(product.risk_score)}</small></span>
            </div>
          )) : <p className="enterprise-muted">No software-level CVE records were supplied.</p>}
          <small>Counts represent assets with uploaded CVE records, not independently verified affected installations.</small>
        </section>
      </div>
      <section className="enterprise-panel enterprise-remediation">
        <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">ACTION QUEUE · EXISTING PRIORIS SCORES</span><h3>Prioritised remediation</h3></div><Wrench size={17} /></div>
        {!summary.prioritized_remediation.length ? <p className="enterprise-muted">No CVE-based remediation entries are available. Review unresolved and unscored records in the findings view.</p> : (
          <div className="enterprise-table-scroll">
            <table className="enterprise-remediation-table">
              <thead><tr><th>Finding / vulnerability</th><th>Affected assets</th><th>Severity</th><th>Risk</th><th>Evidence behind score</th><th>Recommended action</th><th>Suggested priority</th></tr></thead>
              <tbody>{summary.prioritized_remediation.map((finding) => (
                <tr key={finding.cve_id}>
                  <td><b>{finding.cve_id}</b><small>{finding.vulnerability_name || "No title supplied"}</small><StatusPill status={finding.applicability_status} /><small>{finding.applicability_statuses.map(titleCase).join(", ")}</small></td>
                  <td>{formatNumber(finding.affected_assets)}<small>{formatNumber(finding.reported_installations)} reported installation(s)</small></td>
                  <td>{titleCase(finding.severity)}<small>{finding.known_exploited === true ? "Reported KEV" : finding.known_exploited === false ? "KEV reported false" : "KEV unknown"}</small></td>
                  <td><RiskTier tier={finding.risk_tier} /><small>{formatScore(finding.risk_score)}</small></td>
                  <td><ul>{finding.risk_evidence.map((item) => <li key={item}>{item}</li>)}{finding.missing_evidence.map((item) => <li key={item} className="enterprise-missing-evidence">Missing on highest-scored record: {titleCase(item)}</li>)}</ul></td>
                  <td>{finding.recommended_action}</td>
                  <td><span className={`enterprise-priority enterprise-priority-${finding.suggested_priority.toLowerCase()}`}>{finding.suggested_priority}</span></td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        )}
        <small>Reported findings are not independently confirmed. P1–P4 reuse the existing score tiers; an explicitly reported KEV status can raise a finding to P1. “Review” means score evidence is insufficient, not low risk.</small>
      </section>
      <section className="enterprise-panel enterprise-limitations">
        <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">EVIDENCE POLICY</span><h3>Interpretation and limitations</h3></div><CircleHelp size={17} /></div>
        <ul>{summary.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
      </section>
    </div>
  );
}

function EnterpriseMetric({ label, value, caption }: { label: string; value: number; caption: string }) {
  return <div className="enterprise-metric"><span>{label}</span><b>{formatNumber(value)}</b><small>{caption}</small></div>;
}

function UploadPanel({
  session, organizationId, imports, refresh, onSuccess, onError,
}: {
  session: EnterpriseSession;
  organizationId: string;
  imports: EnterpriseImport[];
  refresh: () => Promise<void>;
  onSuccess: (message: string) => void;
  onError: (message: string) => void;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<DatasetPreview | null>(null);
  const [mapping, setMapping] = useState<Record<string, string | null>>({});
  const [progress, setProgress] = useState(0);
  const [busy, setBusy] = useState(false);
  const [dragging, setDragging] = useState(false);

  const chooseFile = async (candidate?: File) => {
    if (!candidate) return;
    onError("");
    setPreview(null);
    setMapping({});
    setFile(null);
    const extension = candidate.name.toLowerCase().split(".").pop();
    if (extension !== "csv" && extension !== "json") {
      onError("Choose a CSV or JSON file.");
      return;
    }
    if (candidate.size > 10 * 1024 * 1024) {
      onError("File exceeds the 10 MiB upload limit.");
      return;
    }
    setFile(candidate);
    setBusy(true);
    setProgress(0);
    try {
      const result = await previewFile(candidate, {}, session, organizationId, setProgress);
      setPreview(result);
      setMapping(result.suggested_mapping);
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "File preview failed.");
      setFile(null);
    } finally {
      setBusy(false);
    }
  };

  const handleDrop = (event: DragEvent<HTMLButtonElement>) => {
    event.preventDefault();
    setDragging(false);
    void chooseFile(event.dataTransfer.files[0]);
  };

  const validateAgain = async () => {
    if (!file) return;
    setBusy(true);
    setProgress(0);
    onError("");
    try {
      const result = await previewFile(file, mapping, session, organizationId, setProgress);
      setPreview(result);
      setMapping(result.suggested_mapping);
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Revalidation failed.");
    } finally {
      setBusy(false);
    }
  };

  const startImport = async () => {
    if (!file || !preview || preview.validation.rows_valid < 1 || preview.mapping_errors.length) return;
    setBusy(true);
    setProgress(0);
    onError("");
    try {
      const result = await importFile(file, mapping, session, organizationId, setProgress);
      onSuccess(`Imported ${formatNumber(result.records_imported)} records from ${file.name}.`);
      setFile(null);
      setPreview(null);
      setMapping({});
      await refresh();
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Import failed.");
    } finally {
      setBusy(false);
    }
  };

  const downloadPreviewErrors = () => {
    if (!preview) return;
    const csvRows = [
      ["row", "field", "message"],
      ...preview.validation_errors.map((error) => [error.row, error.field, error.message]),
    ];
    const content = csvRows.map((row) => row.map((field) => `"${String(field).replaceAll('"', '""')}"`).join(",")).join("\r\n");
    saveBlob(new Blob([content], { type: "text/csv" }), `${file?.name ?? "dataset"}-errors.csv`);
  };

  return (
    <div className="enterprise-content">
      <div className="enterprise-upload-layout">
        <section className="enterprise-panel enterprise-upload-panel">
          <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">STEP 1 · SELECT</span><h3>Upload company data</h3></div><FileUp size={17} /></div>
          <input
            ref={inputRef}
            className="sr-only"
            type="file"
            accept=".csv,.json,text/csv,application/json"
            onChange={(event) => {
              const candidate = event.target.files?.[0];
              event.target.value = "";
              void chooseFile(candidate);
            }}
          />
          <button
            type="button"
            className={`enterprise-dropzone ${dragging ? "enterprise-dropzone-active" : ""}`}
            onClick={() => inputRef.current?.click()}
            onDragOver={(event) => { event.preventDefault(); setDragging(true); }}
            onDragLeave={() => setDragging(false)}
            onDrop={handleDrop}
          >
            <span className="enterprise-drop-icon"><FileSpreadsheet size={23} /></span>
            <b>Drop a file here or browse</b>
            <small>CSV or JSON · Maximum 10 MiB and 100,000 rows</small>
          </button>
          {file && <div className="enterprise-selected-file"><FileSpreadsheet size={16} /><span><b>{file.name}</b><small>{(file.size / 1024).toFixed(1)} KiB</small></span><button onClick={() => { setFile(null); setPreview(null); }} aria-label="Remove selected file"><X size={15} /></button></div>}
          {busy && <div className="enterprise-progress"><div><span>{progress < 100 ? "Uploading and validating…" : "Processing…"}</span><b>{progress}%</b></div><i><span style={{ width: `${progress}%` }} /></i></div>}
          <div className="enterprise-upload-note"><ShieldCheck size={15} /><span>Each import is associated with <b>{session.organizations.find((org) => org.id === organizationId)?.name}</b>. Repeated file content is rejected rather than overwritten.</span></div>
        </section>

        {preview && (
          <section className="enterprise-panel">
            <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">STEP 2 · REVIEW</span><h3>Map detected columns</h3></div><span className="enterprise-record-count">{preview.detected_columns.length} input fields</span></div>
            <div className="enterprise-mapping-grid">
              {preview.canonical_fields.map((field) => (
                <label key={field}>{canonicalLabels[field] ?? titleCase(field)}
                  <select value={mapping[field] ?? ""} onChange={(event) => setMapping((previous) => ({ ...previous, [field]: event.target.value || null }))}>
                    <option value="">Not provided</option>
                    {preview.detected_columns.map((column) => <option key={column} value={column}>{column}</option>)}
                  </select>
                </label>
              ))}
            </div>
            <button className="enterprise-button enterprise-button-quiet" onClick={() => void validateAgain()} disabled={busy}><RefreshCw size={14} />Revalidate mapping</button>
            {preview.mapping_errors.length > 0 && <div className="enterprise-error"><AlertCircle size={15} />{preview.mapping_errors.join("; ")}</div>}
            <div className="enterprise-validation-grid">
              <EnterpriseMetric label="Total rows" value={preview.validation.rows_total} caption="Parsed from the source file" />
              <EnterpriseMetric label="Valid rows" value={preview.validation.rows_valid} caption="Ready to import" />
              <EnterpriseMetric label="Invalid rows" value={preview.validation.rows_invalid} caption="Skipped until corrected" />
              <EnterpriseMetric label="Duplicate rows" value={preview.validation.rows_duplicate} caption="Deduplicated within the file" />
            </div>
            {preview.validation_errors.length > 0 && (
              <div className="enterprise-validation-errors">
                <div><b>Validation details</b>{preview.validation_errors_truncated && <small> · Showing the first {preview.validation_errors.length} errors</small>}<button onClick={downloadPreviewErrors}><ArrowDownToLine size={14} />Download report</button></div>
                <div className="enterprise-error-list">{preview.validation_errors.slice(0, 20).map((item, index) => <p key={`${item.row}-${item.field}-${index}`}><b>Row {item.row}</b> · {item.field}: {item.message}</p>)}</div>
              </div>
            )}
            <button
              className="enterprise-button enterprise-button-primary enterprise-import-button"
              onClick={() => void startImport()}
              disabled={busy || preview.validation.rows_valid < 1 || preview.mapping_errors.length > 0}
            >
              {busy ? <LoaderCircle size={16} className="enterprise-spin" /> : <Check size={16} />}
              Import {formatNumber(preview.validation.rows_valid)} valid rows
            </button>
          </section>
        )}
      </div>

      <section className="enterprise-panel enterprise-import-history">
        <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">TENANT AUDIT</span><h3>Import history</h3></div><span className="enterprise-record-count">{imports.length} recent</span></div>
        {!imports.length ? <p className="enterprise-muted">No imports recorded.</p> : imports.map((item) => (
          <div className="enterprise-import-history-row" key={item.id}>
            <FileSpreadsheet size={16} />
            <div><b>{item.filename}</b><small>{new Date(item.created_at).toLocaleString()} · {formatNumber(item.records_imported)} imported · {formatNumber(item.rows_invalid)} invalid · {formatNumber(item.rows_duplicate)} duplicate{item.validation_errors_truncated ? " · error report capped at 500" : ""}</small></div>
            <StatusPill status={item.status} />
            {item.validation_errors.length > 0 && (
              <button
                className="enterprise-icon-button"
                title="Download validation errors"
                aria-label={`Download errors for ${item.filename}`}
                onClick={async () => {
                  try {
                    saveBlob(await downloadImportErrors(item.id, session, organizationId), `${item.filename}-errors.csv`);
                  } catch (cause) {
                    onError(cause instanceof Error ? cause.message : "Could not download error report.");
                  }
                }}
              ><ArrowDownToLine size={15} /></button>
            )}
          </div>
        ))}
      </section>
    </div>
  );
}

function AssetTable({
  rows, busy, total, offset, onPage, onFindings,
}: {
  rows: EnterpriseAsset[];
  busy: boolean;
  total: number;
  offset: number;
  onPage: (offset: number) => void;
  onFindings: () => void;
}) {
  if (busy && !rows.length) return <div className="enterprise-loading"><LoaderCircle size={20} className="enterprise-spin" />Loading assets…</div>;
  return (
    <section className="enterprise-panel enterprise-table-panel">
      <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">LATEST INVENTORY</span><h3>Assets</h3></div><span className="enterprise-record-count">{formatNumber(total)} records</span></div>
      {!rows.length ? <div className="enterprise-empty-inline">No assets match this search.</div> : (
        <div className="enterprise-table-scroll"><table><thead><tr><th>Asset</th><th>Type / OS</th><th>Criticality</th><th>Internet exposed</th><th>Affected installations</th><th>Top CVE</th><th>Max score</th></tr></thead>
          <tbody>{rows.map((row) => <tr key={row.asset_id}>
            <td><b>{row.asset_name || row.asset_id}</b><small>{row.asset_id}{row.hostname ? ` · ${row.hostname}` : ""}</small></td>
            <td>{row.asset_type || "—"}<small>{row.operating_system || "—"}</small></td>
            <td>{titleCase(row.business_criticality)}</td>
            <td>{row.internet_exposed == null ? "Unknown" : row.internet_exposed ? "Yes" : "No"}</td>
            <td>{formatNumber(row.affected_installations)}</td><td>{row.top_cve || "—"}</td>
            <td><RiskTier tier={row.risk_tier} /> {formatScore(row.max_risk_score)}</td>
          </tr>)}</tbody>
        </table></div>
      )}
      <Pagination total={total} offset={offset} onPage={onPage} />
      <button className="enterprise-text-button" onClick={onFindings}>Inspect reported findings <ChevronRight size={14} /></button>
    </section>
  );
}

function FindingsTable({
  rows, busy, total, offset, statusFilter, onStatus, onPage,
}: {
  rows: EnterpriseExposure[];
  busy: boolean;
  total: number;
  offset: number;
  statusFilter: string;
  onStatus: (value: string) => void;
  onPage: (offset: number) => void;
}) {
  const statusOptions = useMemo(() => [
    "all", "reported_unverified", "pending_manual_review", "unresolved_product", "unsupported_matching", "inventory_only",
  ], []);
  return (
    <section className="enterprise-panel enterprise-table-panel">
      <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">LATEST INVENTORY</span><h3>Reported findings and review cases</h3></div>
        <label className="enterprise-filter-select"><span className="sr-only">Applicability filter</span><select value={statusFilter} onChange={(event) => { onStatus(event.target.value); onPage(0); }}>{statusOptions.map((item) => <option value={item} key={item}>{item === "all" ? "All statuses" : titleCase(item)}</option>)}</select></label>
      </div>
      {busy && !rows.length ? <div className="enterprise-loading"><LoaderCircle size={20} className="enterprise-spin" />Loading findings…</div> : !rows.length ? <div className="enterprise-empty-inline">No records match this filter.</div> : (
        <div className="enterprise-table-scroll"><table><thead><tr><th>Asset</th><th>Software / version</th><th>CVE</th><th>CVSS</th><th>KEV</th><th>Applicability</th><th>Risk</th><th>Evidence</th></tr></thead>
          <tbody>{rows.map((row, index) => (
            <tr key={`${row.asset_id}-${row.cve_id}-${row.software_name}-${index}`}>
              <td><b>{row.asset_id}</b></td><td>{row.software_name || "—"}<small>{row.installed_version || "Version not supplied"}</small></td>
              <td>{row.cve_id || "—"}<small>{row.vulnerability_name || ""}</small></td><td>{formatScore(row.cvss_score)}<small>{titleCase(row.severity)}</small></td>
              <td>{row.known_exploited == null ? "Unknown" : row.known_exploited ? "Yes" : "No"}</td><td><StatusPill status={row.applicability_status} /></td>
              <td><RiskTier tier={row.risk_tier} /> {formatScore(row.risk_score)}</td>
              <td><details className="enterprise-evidence"><summary>Explain</summary><div><b>Factors</b>{Object.entries(row.risk_factors).length ? Object.entries(row.risk_factors).map(([name, value]) => <p key={name}>{titleCase(name)}: +{formatScore(value)}</p>) : <p>No score; required evidence is missing.</p>}<b>Missing evidence</b><p>{row.missing_evidence.length ? row.missing_evidence.map(titleCase).join(", ") : "No additional score factor is missing."}</p><small>Source: {String(row.source_evidence.source ?? "upload")}. Reported findings are not independently confirmed by PRIORIS.</small></div></details></td>
            </tr>
          ))}</tbody></table></div>
      )}
      <Pagination total={total} offset={offset} onPage={onPage} />
      <p className="enterprise-data-boundary"><ShieldAlert size={14} />Unresolved products, unsupported matching and manual-review cases remain separate. None are considered safe.</p>
    </section>
  );
}

function Pagination({ total, offset, onPage }: { total: number; offset: number; onPage: (offset: number) => void }) {
  const pageSize = 20;
  return <div className="enterprise-pagination"><span>{total ? `${offset + 1}–${Math.min(offset + pageSize, total)} of ${formatNumber(total)}` : "0 records"}</span><div>
    <button className="enterprise-icon-button" disabled={offset <= 0} onClick={() => onPage(Math.max(0, offset - pageSize))} aria-label="Previous page"><ChevronLeft size={16} /></button>
    <button className="enterprise-icon-button" disabled={offset + pageSize >= total} onClick={() => onPage(offset + pageSize)} aria-label="Next page"><ChevronRight size={16} /></button>
  </div></div>;
}

function TeamPanel({
  session, organizationId, rows, onInvite, onError, refresh,
}: {
  session: EnterpriseSession;
  organizationId: string;
  rows: Array<{ user_id: string; email: string; role: string; is_active: boolean; joined_at: string }>;
  onInvite: (token: string) => void;
  onError: (message: string) => void;
  refresh: () => Promise<void>;
}) {
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");
  const [busy, setBusy] = useState(false);
  const invite = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    onError("");
    try {
      const response = await createInvitation(session, organizationId, email, role);
      setEmail("");
      onInvite(response.invitation_token);
      await refresh();
    } catch (cause) {
      onError(cause instanceof Error ? cause.message : "Invitation could not be created.");
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="enterprise-team-layout">
      <section className="enterprise-panel">
        <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">ACCESS CONTROL</span><h3>Invite a colleague</h3></div><Users size={17} /></div>
        <form className="enterprise-invite-form" onSubmit={invite}>
          <label>Email address<input type="email" value={email} maxLength={320} onChange={(event) => setEmail(event.target.value)} required /></label>
          <label>Role<select value={role} onChange={(event) => setRole(event.target.value)}><option value="analyst">Analyst · import and view</option><option value="viewer">Viewer · view only</option><option value="admin">Admin · manage workspace</option></select></label>
          <button className="enterprise-button enterprise-button-primary" disabled={busy}>{busy ? <LoaderCircle size={15} className="enterprise-spin" /> : <Users size={15} />}Create invitation</button>
        </form>
        <p className="enterprise-muted">Invitation email delivery is not configured. The one-time token is shown only after creation; share it through a secure channel.</p>
      </section>
      <section className="enterprise-panel">
        <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">ACTIVE MEMBERS</span><h3>Organisation access</h3></div><span className="enterprise-record-count">{rows.length} members</span></div>
        {rows.map((member) => <div className="enterprise-member-row" key={member.user_id}>
          <span className="enterprise-member-avatar">{member.email.slice(0, 1).toUpperCase()}</span>
          <div><b>{member.email}</b><small>Joined {member.joined_at ? new Date(member.joined_at).toLocaleDateString() : "—"}</small></div>
          <select aria-label={`Role for ${member.email}`} value={member.role} onChange={async (event) => {
            try {
              await updateMember(session, organizationId, member.user_id, { role: event.target.value });
              await refresh();
            } catch (cause) {
              onError(cause instanceof Error ? cause.message : "Member role could not be updated.");
            }
          }}><option value="admin">Admin</option><option value="analyst">Analyst</option><option value="viewer">Viewer</option></select>
          <button className="enterprise-button enterprise-button-quiet" onClick={async () => {
            try {
              await updateMember(session, organizationId, member.user_id, { is_active: !member.is_active });
              await refresh();
            } catch (cause) {
              onError(cause instanceof Error ? cause.message : "Member status could not be updated.");
            }
          }}>{member.is_active ? "Suspend" : "Restore"}</button>
          <StatusPill status={member.is_active ? "active" : "inactive"} />
        </div>)}
      </section>
      <aside className="enterprise-role-note"><ShieldCheck size={16} /><span><b>Server-enforced roles</b><small>Admins manage membership; Analysts can upload and review data; Viewers have read-only access. Every query is scoped to the selected organisation on the API.</small></span></aside>
    </div>
  );
}

function AuditPanel({ rows }: { rows: Array<{
  id: string; actor_user_id: string | null; action: string;
  target_type: string | null; target_id: string | null;
  details: Record<string, unknown>; created_at: string;
}> }) {
  return (
    <section className="enterprise-panel enterprise-table-panel">
      <div className="enterprise-panel-title"><div><span className="enterprise-eyebrow">ACCOUNTABILITY</span><h3>Organisation activity</h3></div><span className="enterprise-record-count">{rows.length} events</span></div>
      {!rows.length ? <div className="enterprise-empty-inline">No audit events have been recorded.</div> : rows.map((row) => (
        <div className="enterprise-audit-row" key={row.id}><span className="enterprise-audit-dot" /><div><b>{titleCase(row.action)}</b><small>{row.target_type ? `${row.target_type} · ${row.target_id ?? "—"}` : "Account activity"} · {row.actor_user_id ?? "System"}</small></div><time>{new Date(row.created_at).toLocaleString()}</time><details><summary>Details</summary><pre>{JSON.stringify(row.details, null, 2)}</pre></details></div>
      ))}
    </section>
  );
}
