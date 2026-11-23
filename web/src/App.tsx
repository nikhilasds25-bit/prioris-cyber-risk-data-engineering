import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertCircle,
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  ArrowUpRight,
  Boxes,
  Building2,
  ChevronDown,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Command,
  Database,
  FileSearch,
  Filter,
  Gauge,
  Globe2,
  Layers3,
  Menu,
  MonitorCog,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldHalf,
  Target,
  X,
  type LucideIcon,
} from "lucide-react";
import type { ReactNode } from "react";
import {
  AnimatePresence,
  motion,
  useReducedMotion,
} from "framer-motion";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import {
  loadConfirmedExposures,
  loadReviewQueue,
  loadSummary,
} from "./lib/data";
import EnterpriseWorkspace from "./EnterpriseWorkspace";
import {
  formatNumber,
  formatScore,
  matchesQuery,
  statusClass,
  tierClass,
  titleCase,
} from "./lib/format";
import type {
  AssetSummary,
  CveSummary,
  DashboardSummary,
  DistributionRow,
  PageId,
  ReviewRecord,
  RiskExposure,
  SoftwareSummary,
} from "./types";

type Column<T> = {
  key: string;
  label: string;
  value: (row: T) => string | number | null | undefined;
  render?: (row: T) => ReactNode;
  className?: string;
};

type SelectedRecord =
  | { kind: "asset"; record: AssetSummary }
  | { kind: "cve"; record: CveSummary }
  | { kind: "exposure"; record: RiskExposure }
  | { kind: "review"; record: ReviewRecord };

type NavigationItem = {
  id: PageId;
  label: string;
  icon: LucideIcon;
  group: string;
};

const navigation: NavigationItem[] = [
  { id: "overview", label: "Overview", icon: Gauge, group: "Workspace" },
  { id: "assets", label: "Asset Intelligence", icon: MonitorCog, group: "Workspace" },
  { id: "vulnerabilities", label: "Vulnerability Intelligence", icon: ShieldAlert, group: "Workspace" },
  { id: "exposures", label: "Exposure Analysis", icon: Target, group: "Workspace" },
  { id: "analytics", label: "Risk Analytics", icon: Activity, group: "Insights" },
  { id: "review", label: "Review Queue", icon: FileSearch, group: "Insights" },
  { id: "enterprise", label: "Enterprise Workspace", icon: Building2, group: "Insights" },
  { id: "methodology", label: "Methodology", icon: CircleHelp, group: "System" },
];

const pageDescriptions: Record<PageId, string> = {
  overview: "A measured view of confirmed risk across your environment.",
  assets: "Prioritize the systems with the greatest confirmed exposure.",
  vulnerabilities: "Explore vulnerability intelligence ranked by enterprise impact.",
  exposures: "Inspect confirmed software-to-vulnerability relationships.",
  analytics: "Understand how risk is distributed across your estate.",
  review: "Cases requiring additional evidence or analyst attention.",
  enterprise: "Secure company onboarding, tenant-scoped inventory, and reported risk evidence.",
  methodology: "Scoring definitions, evidence policy, and dataset boundaries.",
};

const tierColors: Record<string, string> = {
  critical: "#f07178",
  high: "#e9a35a",
  medium: "#65a9d8",
  low: "#67b899",
};

function RiskBadge({ tier }: { tier: string | null | undefined }) {
  return <span className={`risk-badge ${tierClass(tier)}`}>{titleCase(tier)}</span>;
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status-badge ${statusClass(status)}`}>{titleCase(status)}</span>;
}

function CountUp({ value }: { value: number }) {
  const reducedMotion = useReducedMotion();
  const [shown, setShown] = useState(reducedMotion ? value : 0);

  useEffect(() => {
    if (reducedMotion) {
      setShown(value);
      return;
    }
    let frame = 0;
    const start = performance.now();
    const duration = 700;
    const animate = (now: number) => {
      const progress = Math.min((now - start) / duration, 1);
      setShown(Math.round(value * (1 - (1 - progress) ** 3)));
      if (progress < 1) frame = requestAnimationFrame(animate);
    };
    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [reducedMotion, value]);

  return <>{formatNumber(shown)}</>;
}

function DataTable<T>({
  rows,
  columns,
  rowKey,
  onRowClick,
  initialSortKey,
  initialDescending = true,
  emptyTitle = "No matching records",
  emptyDescription = "Try adjusting your search or filters.",
}: {
  rows: T[];
  columns: Column<T>[];
  rowKey: (row: T) => string;
  onRowClick?: (row: T) => void;
  initialSortKey?: string;
  initialDescending?: boolean;
  emptyTitle?: string;
  emptyDescription?: string;
}) {
  const [sortKey, setSortKey] = useState(initialSortKey ?? columns[0]?.key ?? "");
  const [descending, setDescending] = useState(initialDescending);
  const [page, setPage] = useState(0);
  const [pageSize, setPageSize] = useState(10);

  useEffect(() => setPage(0), [rows.length, pageSize]);
  const sorted = useMemo(() => {
    const column = columns.find((item) => item.key === sortKey) ?? columns[0];
    if (!column) return rows;
    return [...rows].sort((a, b) => {
      const left = column.value(a);
      const right = column.value(b);
      let order = 0;
      if (typeof left === "number" && typeof right === "number") order = left - right;
      else order = String(left ?? "").localeCompare(String(right ?? ""), undefined, {
        numeric: true,
        sensitivity: "base",
      });
      return descending ? -order : order;
    });
  }, [columns, descending, rows, sortKey]);
  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize));
  const pageRows = sorted.slice(page * pageSize, (page + 1) * pageSize);

  const changeSort = (column: Column<T>) => {
    if (sortKey === column.key) setDescending((value) => !value);
    else {
      setSortKey(column.key);
      setDescending(true);
    }
    setPage(0);
  };

  if (!rows.length) {
    return <EmptyState title={emptyTitle} description={emptyDescription} compact />;
  }

  return (
    <div className="table-frame">
      <div className="table-scroll">
        <table>
          <thead>
            <tr>
              {columns.map((column) => (
                <th key={column.key} className={column.className}>
                  <button
                    className="sort-button"
                    onClick={() => changeSort(column)}
                    aria-label={`Sort by ${column.label}`}
                  >
                    {column.label}
                    {sortKey === column.key ? (
                      descending ? <ArrowDown size={13} /> : <ArrowUp size={13} />
                    ) : (
                      <ArrowUpDown size={13} className="sort-muted" />
                    )}
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {pageRows.map((row) => (
              <tr
                key={rowKey(row)}
                onClick={onRowClick ? () => onRowClick(row) : undefined}
                onKeyDown={
                  onRowClick
                    ? (event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          onRowClick(row);
                        }
                      }
                    : undefined
                }
                tabIndex={onRowClick ? 0 : undefined}
                className={onRowClick ? "clickable-row" : undefined}
              >
                {columns.map((column) => (
                  <td key={column.key} className={column.className}>
                    {column.render ? column.render(row) : String(column.value(row) ?? "—")}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="table-footer">
        <span>
          {sorted.length ? page * pageSize + 1 : 0}–{Math.min((page + 1) * pageSize, sorted.length)} of{" "}
          {formatNumber(sorted.length)}
        </span>
        <div className="pagination">
          <label>
            <span className="sr-only">Rows per page</span>
            <select
              value={pageSize}
              onChange={(event) => setPageSize(Number(event.target.value))}
              aria-label="Rows per page"
            >
              {[10, 25, 50].map((size) => (
                <option key={size} value={size}>{size} / page</option>
              ))}
            </select>
          </label>
          <button
            className="icon-button"
            onClick={() => setPage((value) => Math.max(0, value - 1))}
            disabled={page === 0}
            aria-label="Previous page"
          >
            <ChevronLeft size={16} />
          </button>
          <span className="page-number">{page + 1} / {pageCount}</span>
          <button
            className="icon-button"
            onClick={() => setPage((value) => Math.min(pageCount - 1, value + 1))}
            disabled={page >= pageCount - 1}
            aria-label="Next page"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    </div>
  );
}

function EmptyState({
  title,
  description,
  compact = false,
}: {
  title: string;
  description: string;
  compact?: boolean;
}) {
  return (
    <div className={`empty-state ${compact ? "empty-compact" : ""}`}>
      <div className="empty-icon"><FileSearch size={20} /></div>
      <strong>{title}</strong>
      <span>{description}</span>
    </div>
  );
}

function MetricCard({
  label,
  value,
  subtitle,
  icon: Icon,
  accent,
  help,
}: {
  label: string;
  value: number;
  subtitle: string;
  icon: LucideIcon;
  accent: string;
  help: string;
}) {
  return (
    <motion.article className={`metric-card ${accent}`} whileHover={{ y: -3 }}>
      <div className="metric-top">
        <span>{label}</span>
        <span className="metric-help" tabIndex={0} aria-label={help} data-tooltip={help}>
          <CircleHelp size={15} />
        </span>
      </div>
      <div className="metric-value"><CountUp value={value} /></div>
      <div className="metric-bottom">
        <span>{subtitle}</span>
        <span className="metric-icon"><Icon size={18} /></span>
      </div>
    </motion.article>
  );
}

function SearchBox({
  value,
  onChange,
  placeholder = "Search records...",
}: {
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
}) {
  return (
    <label className="search-box">
      <Search size={16} aria-hidden="true" />
      <input
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
      />
      {value && (
        <button type="button" className="clear-search" onClick={() => onChange("")} aria-label="Clear search">
          <X size={14} />
        </button>
      )}
    </label>
  );
}

function ChartTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: Array<{ name?: string; value?: number; color?: string; payload?: Record<string, unknown> }>;
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      {label && <strong>{label}</strong>}
      {payload.map((item) => (
        <div key={item.name} className="tooltip-line">
          <span style={{ backgroundColor: item.color }} />
          {titleCase(item.name)} <b>{formatNumber(Number(item.value ?? 0))}</b>
        </div>
      ))}
    </div>
  );
}

function TierChart({ counts }: { counts: Record<string, number> }) {
  const data = ["critical", "high", "medium", "low"].map((tier) => ({
    name: titleCase(tier),
    value: counts[tier] ?? 0,
    fill: tierColors[tier],
  }));
  const total = data.reduce((sum, item) => sum + item.value, 0);
  if (!total) return <EmptyState title="No scored exposures" description="There is no confirmed risk to chart." />;
  return (
    <div className="tier-chart-layout">
      <div className="donut-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} dataKey="value" nameKey="name" innerRadius="69%" outerRadius="91%" paddingAngle={3} stroke="none">
              {data.map((item) => <Cell key={item.name} fill={item.fill} />)}
            </Pie>
            <Tooltip content={<ChartTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        <div className="donut-center"><strong>{formatNumber(total)}</strong><span>scored</span></div>
      </div>
      <div className="legend-list">
        {data.map((item) => (
          <div className="legend-row" key={item.name}>
            <span className="legend-swatch" style={{ background: item.fill }} />
            <span>{item.name}</span>
            <b>{formatNumber(item.value)}</b>
            <small>{total ? `${((item.value / total) * 100).toFixed(1)}%` : "0%"}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

function DistributionChart({
  rows,
  categoryKey,
  height = 270,
}: {
  rows: DistributionRow[];
  categoryKey: "assetType" | "vendor";
  height?: number;
}) {
  const data = rows.slice(0, 10);
  if (!data.length) return <EmptyState title="No distribution data" description="No confirmed records are available." />;
  return (
    <div className="bar-chart" style={{ height }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data} margin={{ top: 8, right: 12, left: -18, bottom: 8 }}>
          <CartesianGrid stroke="#25303b" strokeDasharray="3 5" vertical={false} />
          <XAxis
            dataKey={categoryKey}
            tick={{ fill: "#8794a2", fontSize: 10 }}
            axisLine={false}
            tickLine={false}
            interval={0}
            angle={data.length > 6 ? -25 : 0}
            textAnchor={data.length > 6 ? "end" : "middle"}
            height={data.length > 6 ? 56 : 30}
          />
          <YAxis tick={{ fill: "#8794a2", fontSize: 10 }} axisLine={false} tickLine={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill: "#ffffff08" }} />
          {["critical", "high", "medium", "low"].map((tier) => (
            <Bar key={tier} dataKey={tier} stackId="risk" fill={tierColors[tier]} maxBarSize={34} />
          ))}
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function App() {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [confirmed, setConfirmed] = useState<RiskExposure[] | null>(null);
  const [reviewRows, setReviewRows] = useState<ReviewRecord[] | null>(null);
  const [page, setPage] = useState<PageId>("overview");
  const [query, setQuery] = useState("");
  const [reviewFilter, setReviewFilter] = useState("all");
  const [selected, setSelected] = useState<SelectedRecord | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [dataError, setDataError] = useState("");
  const [collapsed, setCollapsed] = useState(false);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);
  const reducedMotion = useReducedMotion();

  useEffect(() => {
    loadSummary()
      .then(setSummary)
      .catch((cause: unknown) => setError(cause instanceof Error ? cause.message : "Dashboard data failed to load."))
      .finally(() => setLoading(false));
  }, []);

  const ensureConfirmed = useCallback(async () => {
    if (confirmed) return confirmed;
    const records = await loadConfirmedExposures();
    setConfirmed(records);
    return records;
  }, [confirmed]);

  const ensureReview = useCallback(async () => {
    if (reviewRows) return reviewRows;
    const records = await loadReviewQueue();
    setReviewRows(records);
    return records;
  }, [reviewRows]);

  useEffect(() => {
    setDataError("");
    if (page === "exposures" || page === "vulnerabilities") {
      ensureConfirmed().catch((cause: unknown) =>
        setDataError(cause instanceof Error ? cause.message : "Confirmed exposure data failed to load."),
      );
    } else if (page === "review") {
      ensureReview().catch((cause: unknown) =>
        setDataError(cause instanceof Error ? cause.message : "Review queue data failed to load."),
      );
    }
  }, [page, ensureConfirmed, ensureReview]);

  useEffect(() => {
    if (!selected || selected.kind === "review" || confirmed) return;
    let active = true;
    setDetailLoading(true);
    ensureConfirmed()
      .catch((cause: unknown) => {
        if (active) setDataError(cause instanceof Error ? cause.message : "Exposure evidence failed to load.");
      })
      .finally(() => {
        if (active) setDetailLoading(false);
      });
    return () => { active = false; };
  }, [selected, confirmed, ensureConfirmed]);

  const goTo = (next: PageId) => {
    setPage(next);
    setQuery("");
    setSelected(null);
    setMobileNavOpen(false);
  };

  const openSelected = (record: SelectedRecord) => {
    setSelected(record);
    setDataError("");
  };

  const assetRows = useMemo(() => (summary?.assets ?? []).filter((asset) =>
    matchesQuery([
      asset.assetId, asset.criticality, asset.exposure, asset.assetType, asset.businessUnit,
      asset.environment, asset.topCveId, asset.riskTier,
    ], query),
  ), [query, summary]);

  const cveRows = useMemo(() => (summary?.cves ?? []).filter((cve) =>
    matchesQuery([cve.cveId, cve.riskTier, cve.knownExploited ? "KEV" : "not KEV", ...cve.softwareProducts], query),
  ), [query, summary]);

  const softwareRows = useMemo(() => (summary?.software ?? []).filter((software) =>
    matchesQuery([software.vendor, software.product, software.installedVersion, ...software.cves], query),
  ), [query, summary]);

  const exposureRows = useMemo(() => (confirmed ?? []).filter((row) =>
    matchesQuery([
      row.assetId, row.softwareName, row.softwareProduct, row.installedVersion, row.cveId,
      row.cpeName, row.criteria, row.applicabilityStatus,
    ], query),
  ), [confirmed, query]);

  const reviewSearchRows = useMemo(() => (reviewRows ?? []).filter((row) =>
    matchesQuery([
      row.assetId, row.softwareName, row.softwareProduct, row.installedVersion,
      row.applicabilityStatus, row.cveId, row.matchCriteriaId,
    ], query),
  ), [query, reviewRows]);

  const closeDetail = () => setSelected(null);

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="brand-mark brand-mark-large"><ShieldHalf size={26} /></div>
        <div className="loading-line" />
        <p>Loading PRIORIS intelligence</p>
        <div className="skeleton-grid"><i /><i /><i /><i /></div>
      </div>
    );
  }
  if (error || !summary) {
    if (page === "enterprise") {
      return (
        <main className="enterprise-standalone">
          <button className="enterprise-button enterprise-button-quiet" onClick={() => setPage("overview")}>Back to Synthetic Demo</button>
          <EnterpriseWorkspace />
        </main>
      );
    }
    return (
      <div className="error-screen">
        <div className="empty-icon"><AlertCircle size={23} /></div>
        <h1>Dashboard data unavailable</h1>
        <p>{error || "No dashboard summary was found."}</p>
        <p className="muted">Generate the static dashboard export, then refresh this page.</p>
        <button className="button-primary" onClick={() => window.location.reload()}>Retry</button>
        <button className="button-secondary" onClick={() => setPage("enterprise")}>Open Enterprise Workspace</button>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <AnimatePresence>
        {mobileNavOpen && <motion.button className="mobile-backdrop" onClick={() => setMobileNavOpen(false)} initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} aria-label="Close navigation" />}
      </AnimatePresence>
      <aside className={`sidebar ${collapsed ? "sidebar-collapsed" : ""} ${mobileNavOpen ? "sidebar-mobile-open" : ""}`}>
        <div className="brand">
          <div className="brand-mark"><ShieldHalf size={20} strokeWidth={2.2} /></div>
          {!collapsed && <div className="brand-copy"><strong>PRIORIS</strong><span>CYBER RISK INTELLIGENCE</span></div>}
          <button className="collapse-button" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}>
            <ChevronLeft size={16} />
          </button>
        </div>
        <div className="workspace-switch">
          <div className="workspace-icon"><Command size={15} /></div>
          {!collapsed && <div><strong>{page === "enterprise" ? "Company workspace" : "Security workspace"}</strong><span>{page === "enterprise" ? "Private tenant data" : "Current snapshot"}</span></div>}
          {!collapsed && <ChevronDown size={14} className="workspace-chevron" />}
        </div>
        <nav className="side-nav" aria-label="Main navigation">
          {(["Workspace", "Insights", "System"] as const).map((group) => (
            <div className="nav-group" key={group}>
              {!collapsed && <div className="nav-group-label">{group}</div>}
              {navigation.filter((item) => item.group === group).map((item) => {
                const Icon = item.icon;
                const active = page === item.id;
                return (
                  <button
                    key={item.id}
                    className={`nav-item ${active ? "nav-active" : ""}`}
                    onClick={() => goTo(item.id)}
                    title={collapsed ? item.label : undefined}
                    aria-current={active ? "page" : undefined}
                  >
                    {active && <motion.span className="nav-indicator" layoutId="nav-indicator" transition={{ duration: reducedMotion ? 0 : 0.2 }} />}
                    <Icon size={18} />
                    {!collapsed && <span>{item.label}</span>}
                    {item.id === "review" && !collapsed && summary.metrics.applicabilityStatusCounts.pending_manual_review > 0 && (
                      <span className="nav-count">{formatNumber(summary.metrics.applicabilityStatusCounts.pending_manual_review)}</span>
                    )}
                  </button>
                );
              })}
            </div>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="data-source-indicator"><span className="live-dot" />{!collapsed && <><div><b>{page === "enterprise" ? "Tenant workspace" : "Dataset ready"}</b><small>{page === "enterprise" ? "Organisation scoped" : "Local snapshot"}</small></div><Database size={15} /></>}</div>
          {!collapsed && <div className="sidebar-footnote">PRIORIS · Risk intelligence<br />Framework v0.1</div>}
        </div>
      </aside>

      <div className="main-column">
        <header className="topbar">
          <button className="mobile-menu icon-button" onClick={() => setMobileNavOpen(true)} aria-label="Open navigation"><Menu size={19} /></button>
          <div className="breadcrumb">
            <span>Workspace</span><ChevronRight size={13} /><strong>{navigation.find((item) => item.id === page)?.label}</strong>
          </div>
          <div className="topbar-actions">
            {page !== "enterprise" && <SearchBox value={query} onChange={setQuery} placeholder="Search assets, CVEs, software..." />}
            <div className="snapshot-pill"><span className="snapshot-dot" />{page === "enterprise" ? "Tenant data" : summary.snapshotDate ? `Snapshot ${summary.snapshotDate}` : "Current snapshot"}</div>
            <span className="environment-pill"><span />{page === "enterprise" ? "Private Tenant" : summary.datasetEnvironment || "Synthetic Demo"}</span>
            {page !== "enterprise" && <button className="profile-button" aria-label="Profile placeholder" title="Profile placeholder">P</button>}
          </div>
        </header>

        <main className="content">
          <motion.div
            key={page}
            className="page-content"
            initial={{ opacity: 0, y: reducedMotion ? 0 : 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: reducedMotion ? 0 : 0.2 }}
          >
              <div className="page-heading">
                <div>
                  <div className="eyebrow"><span className="eyebrow-mark" />PRIORIS / {page.replaceAll("-", " ")}</div>
                  <h1>{navigation.find((item) => item.id === page)?.label}</h1>
                  <p>{pageDescriptions[page]}</p>
                </div>
                <div className="heading-actions">
                  <span className="data-badge"><span />{page === "enterprise" ? "Private Tenant" : summary.synthetic ? "Synthetic Demo" : summary.datasetEnvironment}</span>
                </div>
              </div>

              {dataError && <div className="inline-error"><AlertCircle size={16} />{dataError}<button onClick={() => setDataError("")} aria-label="Dismiss error"><X size={14} /></button></div>}

              {page === "overview" && (
                <Overview
                  summary={summary}
                  query={query}
                  onAsset={(record) => openSelected({ kind: "asset", record })}
                  onCve={(record) => openSelected({ kind: "cve", record })}
                  onSoftware={() => goTo("exposures")}
                />
              )}
              {page === "assets" && (
                <AssetsPage rows={assetRows} onSelect={(record) => openSelected({ kind: "asset", record })} />
              )}
              {page === "vulnerabilities" && (
                <VulnerabilitiesPage rows={cveRows} loaded={confirmed !== null} onSelect={(record) => openSelected({ kind: "cve", record })} />
              )}
              {page === "exposures" && (
                <ExposuresPage rows={exposureRows} softwareRows={softwareRows} loaded={confirmed !== null} query={query} onSelect={(record) => openSelected({ kind: "exposure", record })} />
              )}
              {page === "analytics" && (
                <AnalyticsPage summary={summary} assets={assetRows} cves={cveRows} onAsset={(record) => openSelected({ kind: "asset", record })} onCve={(record) => openSelected({ kind: "cve", record })} />
              )}
              {page === "review" && (
                <ReviewPage
                  rows={reviewSearchRows}
                  loaded={reviewRows !== null}
                  selectedStatus={reviewFilter}
                  setSelectedStatus={setReviewFilter}
                  onSelect={(record) => openSelected({ kind: "review", record })}
                />
              )}
              {page === "methodology" && <MethodologyPage summary={summary} />}
              {page === "enterprise" && <EnterpriseWorkspace />}
          </motion.div>
          <footer className="app-footer">
            <span>PRIORIS · Distributed Cyber Risk Intelligence and Prioritization Framework</span>
            <span><ShieldCheck size={13} /> Evidence-led · No historical trends fabricated</span>
          </footer>
        </main>
      </div>
      <DetailDrawer
        selected={selected}
        exposures={confirmed ?? []}
        loading={detailLoading}
        onClose={closeDetail}
      />
    </div>
  );
}

function Overview({
  summary,
  query,
  onAsset,
  onCve,
  onSoftware,
}: {
  summary: DashboardSummary;
  query: string;
  onAsset: (record: AssetSummary) => void;
  onCve: (record: CveSummary) => void;
  onSoftware: () => void;
}) {
  const metrics = summary.metrics;
  const topAssets = summary.assets
    .filter((asset) => asset.riskScore !== null)
    .sort((a, b) => (a.priorityRank ?? Number.MAX_SAFE_INTEGER) - (b.priorityRank ?? Number.MAX_SAFE_INTEGER))
    .slice(0, 5);
  const topCves = summary.cves.slice(0, 5);
  return (
    <>
      <section className="metric-grid">
        <MetricCard label="Total assets" value={metrics.totalAssets} subtitle="In current inventory" icon={Boxes} accent="accent-blue" help="Distinct enterprise assets represented in the current inventory snapshot." />
        <MetricCard label="Affected assets" value={metrics.affectedAssets} subtitle={`${metrics.totalAssets ? ((metrics.affectedAssets / metrics.totalAssets) * 100).toFixed(1) : 0}% of inventory`} icon={MonitorCog} accent="accent-cyan" help="Assets with at least one confirmed, scored vulnerable software exposure." />
        <MetricCard label="Affected installations" value={metrics.confirmedInstallations} subtitle={`${formatNumber(metrics.confirmedExposures)} confirmed exposure records`} icon={ShieldAlert} accent="accent-orange" help="Distinct software installations with confirmed vulnerable applicability. Exposure records count each installation-to-CVE relationship." />
        <MetricCard label="Distinct CVEs" value={metrics.distinctCves} subtitle="Affecting this inventory" icon={FileSearch} accent="accent-violet" help="Unique CVEs associated with confirmed, scored inventory exposures." />
      </section>
      <div className="alert-strip">
        <div className="alert-symbol"><ShieldAlert size={17} /></div>
        <div><strong>{formatNumber(metrics.criticalExposures + metrics.highExposures)} Critical &amp; High exposures</strong><span>Require prioritized remediation review based on the configured risk tiers.</span></div>
        <span className="alert-severity"><i /> {formatNumber(metrics.criticalExposures)} Critical <b>·</b> {formatNumber(metrics.highExposures)} High</span>
      </div>
      {query.trim() && (
        <SearchResults
          summary={summary}
          query={query}
          onAsset={onAsset}
          onCve={onCve}
          onSoftware={onSoftware}
        />
      )}

      <section className="content-grid overview-grid">
        <Panel title="Confirmed risk distribution" eyebrow="RISK POSTURE" action={<span className="panel-caption">By scored exposure</span>}>
          <TierChart counts={metrics.riskTierCounts} />
        </Panel>
        <Panel title="Risk by asset type" eyebrow="ASSET CONTEXT" action={<span className="panel-caption">Confirmed records</span>}>
          <DistributionChart rows={summary.assetTypeDistribution} categoryKey="assetType" />
        </Panel>
      </section>
      <section className="content-grid overview-grid overview-lower">
        <Panel title="Highest-priority assets" eyebrow="ASSET PRIORITIZATION" action={<span className="panel-caption">Top 5</span>}>
          <div className="compact-ranking">
            {topAssets.map((asset, index) => (
              <button className="ranking-row" key={asset.assetId} onClick={() => onAsset(asset)}>
                <span className="ranking-number">{String(index + 1).padStart(2, "0")}</span>
                <span className="ranking-main"><b>{asset.assetId}</b><small>{titleCase(asset.assetType)} · {titleCase(asset.criticality)}</small></span>
                <span className="ranking-risk"><RiskBadge tier={asset.riskTier} /><b>{formatScore(asset.riskScore)}</b></span>
                <ArrowUpRight size={15} className="row-arrow" />
              </button>
            ))}
          </div>
        </Panel>
        <Panel title="Highest-priority CVEs" eyebrow="VULNERABILITY INTELLIGENCE" action={<span className="panel-caption">Top 5</span>}>
          <div className="compact-ranking">
            {topCves.map((cve, index) => (
              <button className="ranking-row" key={cve.cveId} onClick={() => onCve(cve)}>
                <span className="ranking-number">{String(index + 1).padStart(2, "0")}</span>
                <span className="ranking-main"><b>{cve.cveId}</b><small>CVSS {formatScore(cve.cvssScore)} · {cve.knownExploited ? "KEV listed" : "Not listed as KEV"}</small></span>
                <span className="ranking-risk"><RiskBadge tier={cve.riskTier} /><b>{formatScore(cve.riskScore)}</b></span>
                <ArrowUpRight size={15} className="row-arrow" />
              </button>
            ))}
          </div>
        </Panel>
      </section>
      <div className="source-note"><Database size={14} /> Snapshot generated {new Date(summary.generatedAt).toLocaleString()} · Counts use the risk engine's current scored outputs.</div>
    </>
  );
}

function SearchResults({
  summary,
  query,
  onAsset,
  onCve,
  onSoftware,
}: {
  summary: DashboardSummary;
  query: string;
  onAsset: (record: AssetSummary) => void;
  onCve: (record: CveSummary) => void;
  onSoftware: () => void;
}) {
  const assets = summary.assets.filter((asset) =>
    matchesQuery([asset.assetId, asset.assetType, asset.businessUnit, asset.topCveId], query),
  ).slice(0, 4);
  const cves = summary.cves.filter((cve) =>
    matchesQuery([cve.cveId, ...cve.softwareProducts], query),
  ).slice(0, 4);
  const software = summary.software.filter((row) =>
    matchesQuery([row.vendor, row.product, row.installedVersion, ...row.cves], query),
  ).slice(0, 4);
  const total = assets.length + cves.length + software.length;
  return (
    <Panel title="Matching intelligence" eyebrow={`${formatNumber(total)} TOP RESULTS`} action={<span className="panel-caption">Search results for “{query}”</span>}>
      {!total ? <EmptyState title="No results found" description="No asset, CVE, or software record matches this search." compact /> : (
        <div className="search-results-grid">
          {[...assets.map((record) => ({ kind: "asset" as const, label: record.assetId, detail: `${titleCase(record.assetType)} · ${record.topCveId ?? "No top CVE"}`, onClick: () => onAsset(record) })),
            ...cves.map((record) => ({ kind: "cve" as const, label: record.cveId, detail: `${titleCase(record.riskTier)} · CVSS ${formatScore(record.cvssScore)}`, onClick: () => onCve(record) })),
            ...software.map((record) => ({ kind: "software" as const, label: record.product, detail: `${record.vendor} · ${record.installedVersion}`, onClick: onSoftware }))].map((item) => (
            <button className="search-result" key={`${item.kind}:${item.label}:${item.detail}`} onClick={item.onClick}>
              <span className={`search-result-icon search-result-${item.kind}`}>{item.kind === "asset" ? <MonitorCog size={14} /> : item.kind === "cve" ? <ShieldAlert size={14} /> : <Boxes size={14} />}</span>
              <span><b>{item.label}</b><small>{item.detail}</small></span><ArrowUpRight size={14} />
            </button>
          ))}
        </div>
      )}
    </Panel>
  );
}

function Panel({
  title,
  eyebrow,
  action,
  children,
  className = "",
}: {
  title: string;
  eyebrow?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <div className="panel-header">
        <div>{eyebrow && <div className="panel-eyebrow">{eyebrow}</div>}<h2>{title}</h2></div>
        {action}
      </div>
      {children}
    </section>
  );
}

function AssetsPage({ rows, onSelect }: { rows: AssetSummary[]; onSelect: (row: AssetSummary) => void }) {
  const [tier, setTier] = useState("all");
  const filtered = tierFilteredHelper(rows, tier);
  const columns: Column<AssetSummary>[] = [
    { key: "rank", label: "Rank", value: (row) => row.priorityRank ?? Number.MAX_SAFE_INTEGER, render: (row) => row.priorityRank == null ? "—" : `#${row.priorityRank}` },
    { key: "asset", label: "Asset", value: (row) => row.assetId, render: (row) => <span className="primary-cell"><b>{row.assetId}</b><small>{row.businessUnit || "—"}</small></span> },
    { key: "type", label: "Asset type", value: (row) => row.assetType },
    { key: "criticality", label: "Criticality", value: (row) => row.criticality, render: (row) => <span className={`criticality criticality-${row.criticality}`}>{titleCase(row.criticality)}</span> },
    { key: "exposure", label: "Network exposure", value: (row) => row.exposure, render: (row) => <span className="exposure-label">{row.exposure === "internet-facing" && <Globe2 size={13} />}{titleCase(row.exposure)}</span> },
    { key: "tier", label: "Risk tier", value: (row) => row.riskTier ?? "", render: (row) => <RiskBadge tier={row.riskTier} /> },
    { key: "score", label: "Max score", value: (row) => row.riskScore, render: (row) => <b className="numeric">{formatScore(row.riskScore)}</b> },
    { key: "cve", label: "Top CVE", value: (row) => row.topCveId },
    { key: "installations", label: "Affected installs", value: (row) => row.affectedInstallations, render: (row) => formatNumber(row.affectedInstallations) },
  ];
  return (
    <>
      <div className="page-toolbar">
        <div><b>{formatNumber(rows.length)}</b><span> assets in current snapshot</span></div>
        <div className="toolbar-controls">
          <label className="filter-control"><Filter size={15} /><span className="sr-only">Filter by risk tier</span>
            <select value={tier} onChange={(event) => setTier(event.target.value)}><option value="all">All tiers</option>{["critical", "high", "medium", "low"].map((item) => <option key={item} value={item}>{titleCase(item)}</option>)}</select>
          </label>
        </div>
      </div>
      <Panel title="Asset risk register" eyebrow="INVENTORY PRIORITIZATION" action={<span className="panel-caption">Select a row for asset context</span>}>
        <DataTable rows={filtered} columns={columns} rowKey={(row) => row.assetId} onRowClick={onSelect} initialSortKey="rank" initialDescending={false} emptyTitle="No assets match" />
      </Panel>
    </>
  );
}

function VulnerabilitiesPage({ rows, loaded, onSelect }: { rows: CveSummary[]; loaded: boolean; onSelect: (row: CveSummary) => void }) {
  const columns: Column<CveSummary>[] = [
    { key: "rank", label: "Rank", value: (row) => row.priorityRank, render: (row) => <span className="ranking-number">{String(row.priorityRank).padStart(2, "0")}</span> },
    { key: "cve", label: "CVE", value: (row) => row.cveId, render: (row) => <b className="link-cell">{row.cveId}</b> },
    { key: "tier", label: "Risk tier", value: (row) => row.riskTier, render: (row) => <RiskBadge tier={row.riskTier} /> },
    { key: "score", label: "Risk score", value: (row) => row.riskScore, render: (row) => <b className="numeric">{formatScore(row.riskScore)}</b> },
    { key: "cvss", label: "CVSS", value: (row) => row.cvssScore, render: (row) => <span>{formatScore(row.cvssScore)}</span> },
    { key: "kev", label: "KEV", value: (row) => row.knownExploited ? 1 : 0, render: (row) => row.knownExploited ? <span className="kev-chip">Known exploited</span> : <span className="muted">Not listed</span> },
    { key: "assets", label: "Affected assets", value: (row) => row.affectedAssets, render: (row) => formatNumber(row.affectedAssets) },
    { key: "installs", label: "Installations", value: (row) => row.affectedInstallations, render: (row) => formatNumber(row.affectedInstallations) },
  ];
  return (
    <>
      <div className="page-toolbar"><div><b>{formatNumber(rows.length)}</b><span> ranked vulnerabilities</span></div><div className="quiet-note"><ShieldCheck size={14} />{loaded ? "Exposure evidence loaded" : "Evidence loads on demand"}</div></div>
      <Panel title="CVE prioritization" eyebrow="ENTERPRISE IMPACT" action={<span className="panel-caption">Ranked from confirmed exposures</span>}>
        <DataTable rows={rows} columns={columns} rowKey={(row) => row.cveId} onRowClick={onSelect} initialSortKey="rank" initialDescending={false} emptyTitle="No CVEs match" />
      </Panel>
    </>
  );
}

function ExposuresPage({ rows, softwareRows, loaded, query, onSelect }: { rows: RiskExposure[]; softwareRows: SoftwareSummary[]; loaded: boolean; query: string; onSelect: (row: RiskExposure) => void }) {
  const [tier, setTier] = useState("all");
  const [view, setView] = useState<"installations" | "software">("installations");
  const visible = tierFilteredHelper(rows, tier);
  const columns: Column<RiskExposure>[] = [
    { key: "asset", label: "Asset", value: (row) => row.assetId, render: (row) => <b>{row.assetId}</b> },
    { key: "software", label: "Software", value: (row) => row.softwareName, render: (row) => <span className="primary-cell"><b>{row.softwareProduct || row.softwareName}</b><small>{row.softwareVendor}</small></span> },
    { key: "version", label: "Installed version", value: (row) => row.installedVersion },
    { key: "cve", label: "CVE", value: (row) => row.cveId, render: (row) => <span className="link-cell">{row.cveId ?? "—"}</span> },
    { key: "tier", label: "Risk tier", value: (row) => row.riskTier, render: (row) => <RiskBadge tier={row.riskTier} /> },
    { key: "score", label: "Score", value: (row) => row.riskScore, render: (row) => <b className="numeric">{formatScore(row.riskScore)}</b> },
    { key: "kev", label: "KEV", value: (row) => row.knownExploited ? 1 : 0, render: (row) => row.knownExploited ? <span className="kev-chip">Listed</span> : <span className="muted">—</span> },
    { key: "evidence", label: "Applicability", value: (row) => row.applicabilityStatus, render: (row) => <StatusBadge status={row.applicabilityStatus} /> },
  ];
  const softwareColumns: Column<SoftwareSummary>[] = [
    { key: "product", label: "Software product", value: (row) => row.product, render: (row) => <span className="primary-cell"><b>{row.product}</b><small>{row.vendor}</small></span> },
    { key: "version", label: "Installed version", value: (row) => row.installedVersion },
    { key: "assets", label: "Affected assets", value: (row) => row.affectedAssets, render: (row) => formatNumber(row.affectedAssets) },
    { key: "cves", label: "Associated CVEs", value: (row) => row.cveCount, render: (row) => <span>{formatNumber(row.cveCount)} CVEs</span> },
    { key: "tier", label: "Risk tier", value: (row) => row.riskTier, render: (row) => <RiskBadge tier={row.riskTier} /> },
    { key: "score", label: "Risk score", value: (row) => row.riskScore, render: (row) => <b className="numeric">{formatScore(row.riskScore)}</b> },
    { key: "kev", label: "KEV", value: (row) => row.knownExploited ? 1 : 0, render: (row) => row.knownExploited ? <span className="kev-chip">Listed</span> : <span className="muted">—</span> },
  ];
  return (
    <>
      <div className="page-toolbar"><div><b>{loaded ? formatNumber(view === "installations" ? visible.length : softwareRows.length) : "—"}</b><span> {view === "installations" ? "confirmed exposure records" : "ranked software products"}</span></div><div className="toolbar-controls"><div className="view-switch" role="group" aria-label="Exposure view"><button className={view === "installations" ? "view-active" : ""} onClick={() => setView("installations")}>Installations</button><button className={view === "software" ? "view-active" : ""} onClick={() => setView("software")}>Software products</button></div>{view === "installations" && <label className="filter-control"><Filter size={15} /><select value={tier} onChange={(event) => setTier(event.target.value)} aria-label="Filter by risk tier"><option value="all">All tiers</option>{["critical", "high", "medium", "low"].map((item) => <option key={item} value={item}>{titleCase(item)}</option>)}</select></label>}</div></div>
      <Panel title={view === "installations" ? "Confirmed software exposures" : "Software product exposure"} eyebrow={view === "installations" ? "AFFECTED INSTALLATIONS" : "PRODUCT PRIORITIZATION"} action={<span className="panel-caption">{view === "installations" ? `Showing ${formatNumber(visible.length)}${query ? " matching" : ""}` : "Aggregated from confirmed exposures"}</span>}>
        {!loaded ? <TableSkeleton /> : view === "installations" ? <DataTable rows={visible} columns={columns} rowKey={(row) => String(row.recordId)} onRowClick={onSelect} initialSortKey="score" emptyTitle="No exposures match" /> : <DataTable rows={softwareRows} columns={softwareColumns} rowKey={(row) => `${row.vendor}:${row.product}:${row.installedVersion}`} initialSortKey="score" emptyTitle="No software products match" />}
      </Panel>
      <p className="subtle-copy">Only confirmed, scored vulnerability applicability is shown here. Unresolved and unsupported cases remain in the Review Queue and are not treated as safe.</p>
    </>
  );
}

function AnalyticsPage({
  summary,
  assets,
  cves,
  onAsset,
  onCve,
}: {
  summary: DashboardSummary;
  assets: AssetSummary[];
  cves: CveSummary[];
  onAsset: (record: AssetSummary) => void;
  onCve: (record: CveSummary) => void;
}) {
  const assetColumns: Column<AssetSummary>[] = [
    { key: "rank", label: "Rank", value: (row) => row.priorityRank ?? 9999 },
    { key: "asset", label: "Asset", value: (row) => row.assetId },
    { key: "criticality", label: "Criticality", value: (row) => row.criticality },
    { key: "score", label: "Max score", value: (row) => row.riskScore, render: (row) => formatScore(row.riskScore) },
    { key: "tier", label: "Tier", value: (row) => row.riskTier ?? "", render: (row) => <RiskBadge tier={row.riskTier} /> },
    { key: "installations", label: "Affected installs", value: (row) => row.affectedInstallations },
  ];
  const cveColumns: Column<CveSummary>[] = [
    { key: "rank", label: "Rank", value: (row) => row.priorityRank },
    { key: "cve", label: "CVE", value: (row) => row.cveId },
    { key: "score", label: "Risk score", value: (row) => row.riskScore, render: (row) => formatScore(row.riskScore) },
    { key: "tier", label: "Tier", value: (row) => row.riskTier, render: (row) => <RiskBadge tier={row.riskTier} /> },
    { key: "assets", label: "Assets", value: (row) => row.affectedAssets },
    { key: "kev", label: "KEV", value: (row) => row.knownExploited ? 1 : 0, render: (row) => row.knownExploited ? "Listed" : "—" },
  ];
  return (
    <>
      <section className="metric-grid compact-metrics">
        <MetricCard label="Critical exposures" value={summary.metrics.riskTierCounts.critical} subtitle="Highest configured tier" icon={ShieldAlert} accent="accent-red" help="Confirmed scored exposures at or above the configured critical threshold." />
        <MetricCard label="High exposures" value={summary.metrics.riskTierCounts.high} subtitle="Priority remediation" icon={ShieldCheck} accent="accent-orange" help="Confirmed scored exposures in the configured high risk band." />
        <MetricCard label="Assets with scored risk" value={summary.metrics.affectedAssets} subtitle="Confirmed impact" icon={Boxes} accent="accent-blue" help="Distinct assets with confirmed and scored exposures." />
        <MetricCard label="Known exploited CVEs" value={summary.cves.filter((cve) => cve.knownExploited).length} subtitle="CISA KEV members" icon={Globe2} accent="accent-cyan" help="Distinct prioritized CVEs explicitly present in the known exploited catalog." />
      </section>
      <section className="content-grid analytics-chart-grid">
        <Panel title="Risk by asset type" eyebrow="ASSET CONTEXT"><DistributionChart rows={summary.assetTypeDistribution} categoryKey="assetType" height={320} /></Panel>
        <Panel title="Risk by software vendor" eyebrow="PRODUCT CONTEXT"><DistributionChart rows={summary.vendorDistribution} categoryKey="vendor" height={320} /></Panel>
      </section>
      <Panel title="Ranked asset exposure" eyebrow="ASSET PRIORITIZATION" action={<span className="panel-caption">Highest risk first</span>}>
        <DataTable rows={assets.filter((row) => row.riskScore !== null).sort((a, b) => (a.priorityRank ?? 9999) - (b.priorityRank ?? 9999)).slice(0, 20)} columns={assetColumns} rowKey={(row) => row.assetId} onRowClick={onAsset} initialSortKey="rank" initialDescending={false} />
      </Panel>
      <Panel title="Ranked vulnerability impact" eyebrow="CVE PRIORITIZATION" action={<span className="panel-caption">Highest risk first</span>}>
        <DataTable rows={cves.slice(0, 20)} columns={cveColumns} rowKey={(row) => row.cveId} onRowClick={onCve} initialSortKey="rank" initialDescending={false} />
      </Panel>
    </>
  );
}

function ReviewPage({
  rows,
  loaded,
  selectedStatus,
  setSelectedStatus,
  onSelect,
}: {
  rows: ReviewRecord[];
  loaded: boolean;
  selectedStatus: string;
  setSelectedStatus: (value: string) => void;
  onSelect: (record: ReviewRecord) => void;
}) {
  const statusCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const record of rows) counts.set(record.applicabilityStatus, (counts.get(record.applicabilityStatus) ?? 0) + 1);
    return counts;
  }, [rows]);
  const columns: Column<ReviewRecord>[] = [
    { key: "asset", label: "Asset", value: (row) => row.assetId, render: (row) => <b>{row.assetId}</b> },
    { key: "software", label: "Software", value: (row) => row.softwareName, render: (row) => <span className="primary-cell"><b>{row.softwareProduct || row.softwareName}</b><small>{row.softwareVendor} · {row.installedVersion || "version unknown"}</small></span> },
    { key: "status", label: "Review status", value: (row) => row.applicabilityStatus, render: (row) => <StatusBadge status={row.applicabilityStatus} /> },
    { key: "cve", label: "Candidate CVE", value: (row) => row.cveId },
    { key: "reason", label: "Risk tier", value: (row) => row.riskTier ?? "", render: () => <span className="muted">Not scored</span> },
  ];
  const unresolvedCount = rows.filter((row) => row.applicabilityStatus === "unresolved_product").length;
  const visibleRows = selectedStatus === "all"
    ? rows
    : rows.filter((row) => row.applicabilityStatus === selectedStatus);
  return (
    <>
      <div className="review-callout"><div className="review-callout-icon"><AlertCircle size={18} /></div><div><strong>Unconfirmed is not safe</strong><p>These records lack sufficient automated evidence for a confirmed match. They remain unscored and should be reviewed, not interpreted as unaffected.</p></div></div>
      <div className="review-summary-grid">
        {[
          ["All review cases", "all", rows.length],
          ["Unresolved products", "unresolved_product", unresolvedCount],
          ["Unsupported matching", "unsupported_matching", statusCounts.get("unsupported_matching") ?? 0],
          ["Manual review", "pending_manual_review", statusCounts.get("pending_manual_review") ?? 0],
        ].map(([label, status, count]) => (
          <button key={String(status)} className={`review-count-card ${selectedStatus === status ? "review-count-active" : ""}`} onClick={() => setSelectedStatus(String(status))}>
            <span>{label}</span><b>{formatNumber(Number(count))}</b><ArrowUpRight size={15} />
          </button>
        ))}
      </div>
      <div className="page-toolbar"><div><b>{loaded ? formatNumber(visibleRows.length) : "—"}</b><span> cases in current filter</span></div><label className="filter-control"><Filter size={15} /><select value={selectedStatus} onChange={(event) => setSelectedStatus(event.target.value)} aria-label="Filter review status"><option value="all">All statuses</option><option value="unresolved_product">Unresolved product</option><option value="unsupported_matching">Unsupported matching</option><option value="pending_manual_review">Pending manual review</option><option value="no_candidate_match_not_cleared">No candidate match, not cleared</option><option value="configuration_not_satisfied">Configuration not satisfied</option></select></label></div>
      <Panel title="Cases requiring analyst review" eyebrow="NOT CLEARED AS SAFE" action={<span className="panel-caption">Candidate evidence retained</span>}>
        {loaded ? <DataTable rows={visibleRows} columns={columns} rowKey={(row) => String(row.recordId)} onRowClick={onSelect} emptyTitle="No review cases match" /> : <TableSkeleton />}
      </Panel>
    </>
  );
}

function MethodologyPage({ summary }: { summary: DashboardSummary }) {
  const config = summary.scoringMethod.configuration;
  return (
    <>
      <div className="method-hero">
        <div className="method-icon"><Layers3 size={21} /></div>
        <div><div className="panel-eyebrow">TRANSPARENT PRIORITIZATION</div><h2>{summary.scoringMethod.formula}</h2><p>Risk tiers and factor contributions shown below come directly from the existing Phase 4 scoring output. This frontend does not recalculate scores.</p></div>
      </div>
      <div className="content-grid method-grid">
        <Panel title="Scoring factors" eyebrow="EXISTING SCORE CONFIGURATION">
          <div className="factor-list">
            <Factor label="CVSS" detail="Base severity contribution from the vulnerability record." value="Source CVSS" />
            <Factor label="Known Exploited Vulnerability" detail="Additional configured contribution for explicit KEV membership." value={`+${config.kev_bonus}`} />
            <Factor label="Asset criticality" detail="Contribution increases by criticality level." value={`+${config.criticality_step} / level`} />
            <Factor label="Network exposure" detail="Configured adjustment based on known network exposure." value={`Internet +${config.internet_facing_bonus} · Internal +${config.internal_bonus}`} />
          </div>
          <div className="formula-box"><span>Score bounds</span><b>{config.score_bounds[0]} — {config.score_bounds[1]}</b></div>
        </Panel>
        <Panel title="Risk tier thresholds" eyebrow="CONFIGURED BANDS">
          <div className="threshold-list">
            {[
              ["Critical", `Score ≥ ${config.critical_threshold}`, "critical"],
              ["High", `${config.high_threshold} ≤ score < ${config.critical_threshold}`, "high"],
              ["Medium", `${config.medium_threshold} ≤ score < ${config.high_threshold}`, "medium"],
              ["Low", `Score < ${config.medium_threshold}`, "low"],
            ].map(([, threshold, tier]) => <div className="threshold-row" key={tier}><RiskBadge tier={tier} /><span>{threshold}</span></div>)}
          </div>
        </Panel>
      </div>
      <Panel title="Evidence and uncertainty policy" eyebrow="INTERPRETATION">
        <div className="policy-grid">
          <div className="policy-item policy-positive"><ShieldCheck size={18} /><div><b>Confirmed match</b><p>Only confirmed vulnerable applicability with complete scoring evidence contributes a risk score and tier.</p></div></div>
          <div className="policy-item policy-caution"><AlertCircle size={18} /><div><b>Unresolved, unsupported, or manual review</b><p>These remain distinct statuses and are never presented as safe. Missing or invalid score evidence does not become zero risk.</p></div></div>
        </div>
        <div className="method-note"><b>Missing evidence policy</b><p>{summary.scoringMethod.missing_evidence_policy}</p></div>
      </Panel>
      <Panel title="Data boundaries and limitations" eyebrow="CURRENT SNAPSHOT">
        <ul className="limitation-list">
          {summary.limitations.map((item, index) => <li key={`${index}-${item}`}>{item}</li>)}
          {summary.sourceSummary.inventoryDirectory && <li>Inventory source: <code>{summary.sourceSummary.inventoryDirectory}</code></li>}
          <li>Snapshot generated at {new Date(summary.generatedAt).toLocaleString()}. No historical trend values are implied.</li>
        </ul>
      </Panel>
    </>
  );
}

function Factor({ label, detail, value }: { label: string; detail: string; value: string }) {
  return <div className="factor-row"><div><b>{label}</b><span>{detail}</span></div><strong>{value}</strong></div>;
}

function TableSkeleton() {
  return <div className="table-skeleton">{Array.from({ length: 7 }, (_, index) => <div key={index}><i /><i /><i /><i /></div>)}</div>;
}

function tierFilteredHelper<T extends { riskTier?: string | null }>(rows: T[], tier: string): T[] {
  return tier === "all" ? rows : rows.filter((row) => row.riskTier === tier);
}

function DetailDrawer({
  selected,
  exposures,
  loading,
  onClose,
}: {
  selected: SelectedRecord | null;
  exposures: RiskExposure[];
  loading: boolean;
  onClose: () => void;
}) {
  const related = useMemo(() => {
    if (!selected || selected.kind === "review") return [];
    if (selected.kind === "asset") return exposures.filter((row) => row.assetId === selected.record.assetId);
    if (selected.kind === "cve") return exposures.filter((row) => row.cveId === selected.record.cveId);
    return [selected.record];
  }, [exposures, selected]);
  const heading = selected ? selected.kind === "asset" ? selected.record.assetId : selected.kind === "cve" ? selected.record.cveId : selected.record.softwareName : "";
  const columns: Column<RiskExposure>[] = [
    { key: "cve", label: "CVE", value: (row) => row.cveId },
    { key: "software", label: "Software", value: (row) => row.softwareProduct },
    { key: "score", label: "Score", value: (row) => row.riskScore, render: (row) => formatScore(row.riskScore) },
    { key: "tier", label: "Tier", value: (row) => row.riskTier ?? "", render: (row) => <RiskBadge tier={row.riskTier} /> },
  ];
  return (
    <AnimatePresence>
      {selected && (
        <>
          <motion.button className="drawer-backdrop" onClick={onClose} aria-label="Close details" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} />
          <motion.aside className="detail-drawer" role="dialog" aria-modal="true" aria-labelledby="drawer-heading" initial={{ x: "100%" }} animate={{ x: 0 }} exit={{ x: "100%" }} transition={{ duration: 0.22 }}>
            <div className="drawer-header"><div><span className="panel-eyebrow">{selected.kind === "review" ? "REVIEW CASE" : "RISK EVIDENCE"}</span><h2 id="drawer-heading">{heading}</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details"><X size={18} /></button></div>
            <div className="drawer-body">
              {selected.kind === "asset" && <AssetDetail asset={selected.record} />}
              {selected.kind === "cve" && <CveDetail cve={selected.record} />}
              {selected.kind === "exposure" && <ExposureDetail exposure={selected.record} />}
              {selected.kind === "review" && <ReviewDetail record={selected.record} />}
              {selected.kind !== "review" && (
                <section className="drawer-section">
                  <div className="drawer-section-heading"><h3>Related confirmed exposures</h3><span>{formatNumber(related.length)}</span></div>
                  {loading ? <TableSkeleton /> : related.length ? <DataTable rows={related.slice(0, 100)} columns={columns} rowKey={(row) => `${row.assetId}:${row.installationId}:${row.cveId}`} /> : <EmptyState title="No related exposure details" description="The summary is available, but no matching detailed record was returned." compact />}
                </section>
              )}
            </div>
          </motion.aside>
        </>
      )}
    </AnimatePresence>
  );
}

function DetailField({ label, children }: { label: string; children: ReactNode }) {
  return <div className="detail-field"><span>{label}</span><b>{children ?? "—"}</b></div>;
}

function AssetDetail({ asset }: { asset: AssetSummary }) {
  return (
    <div className="detail-card">
      <div className="detail-score-row"><RiskBadge tier={asset.riskTier} /><strong>{formatScore(asset.riskScore)}<small> max score</small></strong></div>
      <div className="detail-fields">
        <DetailField label="Asset type">{titleCase(asset.assetType)}</DetailField>
        <DetailField label="Criticality">{titleCase(asset.criticality)}</DetailField>
        <DetailField label="Network exposure">{titleCase(asset.exposure)}</DetailField>
        <DetailField label="Environment">{titleCase(asset.environment)}</DetailField>
        <DetailField label="Business unit">{asset.businessUnit}</DetailField>
        <DetailField label="Top associated CVE">{asset.topCveId}</DetailField>
        <DetailField label="Affected installations">{formatNumber(asset.affectedInstallations)}</DetailField>
        <DetailField label="Affected CVEs">{formatNumber(asset.affectedCves)}</DetailField>
      </div>
    </div>
  );
}

function CveDetail({ cve }: { cve: CveSummary }) {
  return (
    <div className="detail-card">
      <div className="detail-score-row"><RiskBadge tier={cve.riskTier} /><strong>{formatScore(cve.riskScore)}<small> enterprise risk score</small></strong></div>
      <div className="detail-fields">
        <DetailField label="CVSS score">{formatScore(cve.cvssScore)}</DetailField>
        <DetailField label="Known exploited">{cve.knownExploited ? <span className="kev-chip">CISA KEV</span> : "Not listed as KEV"}</DetailField>
        <DetailField label="KEV date added">{cve.kevDateAdded}</DetailField>
        <DetailField label="Affected assets">{formatNumber(cve.affectedAssets)}</DetailField>
        <DetailField label="Affected installations">{formatNumber(cve.affectedInstallations)}</DetailField>
      </div>
      <div className="detail-sublist"><span>Related software</span>{cve.softwareProducts.map((product) => <i key={product}>{product}</i>)}</div>
    </div>
  );
}

function ExposureDetail({ exposure }: { exposure: RiskExposure }) {
  const components = exposure.riskFactorComponents ?? {};
  const evidence = exposure.riskFactorEvidence ?? {};
  const match = exposure.matchEvidence ?? {};
  return (
    <>
      <div className="detail-card">
        <div className="detail-score-row"><RiskBadge tier={exposure.riskTier} /><strong>{formatScore(exposure.riskScore)}<small> risk score</small></strong></div>
        <div className="detail-fields">
          <DetailField label="Asset">{exposure.assetId}</DetailField>
          <DetailField label="Software">{exposure.softwareProduct || exposure.softwareName}</DetailField>
          <DetailField label="Installed version">{exposure.installedVersion}</DetailField>
          <DetailField label="CVE">{exposure.cveId}</DetailField>
          <DetailField label="CVSS">{exposure.cvssScore == null ? "—" : formatScore(Number(exposure.cvssScore))}</DetailField>
          <DetailField label="Known exploited">{exposure.knownExploited ? "Yes" : "No"}</DetailField>
          <DetailField label="Configuration index">{exposure.configurationIndex}</DetailField>
          <DetailField label="Node path">{exposure.nodePath}</DetailField>
          <DetailField label="Match index">{exposure.matchIndex}</DetailField>
          <DetailField label="Match criteria ID">{exposure.matchCriteriaId}</DetailField>
          <DetailField label="CPE name">{exposure.cpeName}</DetailField>
        </div>
      </div>
      <section className="drawer-section"><h3>Version boundaries</h3><div className="detail-fields">
        <DetailField label="Start including">{exposure.versionStartIncluding}</DetailField>
        <DetailField label="Start excluding">{exposure.versionStartExcluding}</DetailField>
        <DetailField label="End including">{exposure.versionEndIncluding}</DetailField>
        <DetailField label="End excluding">{exposure.versionEndExcluding}</DetailField>
      </div></section>
      <section className="drawer-section"><h3>Score explanation</h3><div className="factor-evidence">
        {Object.keys(components).length ? Object.entries(components).map(([key, value]) => <div key={key}><span>{titleCase(key)}</span><b>{formatScore(Number(value))}</b></div>) : <span className="muted">No factor components exported.</span>}
      </div>
      <JsonEvidence title="Scoring evidence" value={evidence} />
      <JsonEvidence title="Applicability evidence" value={match} />
      </section>
    </>
  );
}

function ReviewDetail({ record }: { record: ReviewRecord }) {
  return (
    <>
      <div className="review-detail-callout"><StatusBadge status={record.applicabilityStatus} /><p>This case is not confirmed or scored. It must not be interpreted as safe.</p></div>
      <div className="detail-card"><div className="detail-fields">
        <DetailField label="Asset">{record.assetId}</DetailField>
        <DetailField label="Software">{record.softwareProduct || record.softwareName}</DetailField>
        <DetailField label="Installed version">{record.installedVersion}</DetailField>
        <DetailField label="Candidate CVE">{record.cveId}</DetailField>
        <DetailField label="CPE criteria">{record.criteria}</DetailField>
        <DetailField label="Match criteria ID">{record.matchCriteriaId}</DetailField>
        <DetailField label="Configuration index">{record.configurationIndex}</DetailField>
        <DetailField label="Node path">{record.nodePath}</DetailField>
      </div></div>
      <JsonEvidence title="Matching evidence" value={record.matchEvidence ?? {}} />
      {record.missingScoreEvidence?.length ? <div className="missing-evidence"><b>Missing score evidence</b><ul>{record.missingScoreEvidence.map((item) => <li key={item}>{item}</li>)}</ul></div> : null}
    </>
  );
}

function JsonEvidence({ title, value }: { title: string; value: Record<string, unknown> }) {
  if (!Object.keys(value).length) return null;
  return <details className="json-evidence"><summary>{title}<ChevronDown size={14} /></summary><pre>{JSON.stringify(value, null, 2)}</pre></details>;
}

export default App;
