export type RiskTier = "critical" | "high" | "medium" | "low";

export interface RiskMetrics {
  totalAssets: number;
  affectedAssets: number;
  confirmedInstallations: number;
  confirmedExposures: number;
  distinctCves: number;
  criticalExposures: number;
  highExposures: number;
  riskTierCounts: Record<RiskTier, number>;
  applicabilityStatusCounts: Record<string, number>;
  scoringStatusCounts: Record<string, number>;
}

export interface AssetSummary {
  assetId: string;
  criticality: string;
  exposure: string;
  assetType: string;
  businessUnit: string;
  environment: string;
  scoredExposureRows: number;
  affectedInstallations: number;
  affectedCves: number;
  kevExposureRows: number;
  criticalExposureRows: number;
  highExposureRows: number;
  mediumExposureRows: number;
  lowExposureRows: number;
  riskScore: number | null;
  riskTier: RiskTier | null;
  topCveId: string | null;
  topInstallationId: string | null;
  riskStatus: string;
  priorityRank: number | null;
}

export interface CveSummary {
  cveId: string;
  riskScore: number;
  riskTier: RiskTier;
  cvssScore: number;
  knownExploited: boolean;
  kevDateAdded: string | null;
  affectedAssets: number;
  affectedInstallations: number;
  softwareProducts: string[];
  priorityRank: number;
}

export interface SoftwareSummary {
  vendor: string;
  product: string;
  installedVersion: string;
  affectedAssets: number;
  cves: string[];
  cveCount: number;
  riskScore: number;
  riskTier: RiskTier;
  knownExploited: boolean;
}

export interface DistributionRow {
  assetType?: string;
  vendor?: string;
  critical?: number;
  high?: number;
  medium?: number;
  low?: number;
}

export interface DashboardSummary {
  product: string;
  description: string;
  datasetEnvironment: string;
  snapshotDate: string | null;
  generatedAt: string;
  synthetic: boolean;
  scoringMethod: {
    formula: string;
    configuration: {
      kev_bonus: number;
      criticality_step: number;
      internet_facing_bonus: number;
      internal_bonus: number;
      medium_threshold: number;
      high_threshold: number;
      critical_threshold: number;
      score_bounds: [number, number];
    };
    risk_tiers: Record<string, string>;
    missing_evidence_policy: string;
  };
  limitations: string[];
  metrics: RiskMetrics;
  assets: AssetSummary[];
  cves: CveSummary[];
  software: SoftwareSummary[];
  assetTypeDistribution: DistributionRow[];
  vendorDistribution: DistributionRow[];
  exports: {
    confirmedExposures: { file: string; records: number };
    reviewQueue: { file: string; records: number };
  };
  sourceSummary: {
    phase3ExposureRows: number;
    confirmedInstallationCvePairs: number;
    inventoryDirectory: string;
  };
}

export interface RiskExposure {
  recordId: number;
  assetId: string;
  installationId: string;
  softwareName: string;
  softwareProduct: string;
  installedVersion: string;
  installedCpeName: string;
  cveId: string | null;
  vulnerable: boolean | null;
  cvssScore: string | number | null;
  knownExploited: boolean | null;
  kevDateAdded: string | null;
  criticality: string | null;
  exposure: string | null;
  assetType: string | null;
  businessUnit: string | null;
  environment: string | null;
  applicabilityStatus: string;
  riskScore: number | null;
  riskTier: RiskTier | null;
  scoringStatus: string;
  riskFactorComponents: Record<string, number> | null;
  riskFactorEvidence: Record<string, unknown> | null;
  missingScoreEvidence: string[] | null;
  matchEvidence: Record<string, unknown> | null;
  configurationIndex: number | null;
  nodePath: string | null;
  matchIndex: number | null;
  matchCriteriaId: string | null;
  criteria: string | null;
  versionStartIncluding: string | null;
  versionStartExcluding: string | null;
  versionEndIncluding: string | null;
  versionEndExcluding: string | null;
  cpeName: string | null;
  cpeNameId: string | null;
  softwareVendor: string;
}

export interface ReviewRecord extends RiskExposure {}

export type PageId =
  | "overview"
  | "assets"
  | "vulnerabilities"
  | "exposures"
  | "analytics"
  | "review"
  | "methodology";

export interface ExportedDashboardData {
  summary: DashboardSummary;
  confirmedExposures: RiskExposure[];
  reviewQueue: ReviewRecord[];
}
