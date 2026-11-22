# PRIORIS — Big Data Capstone Starter (Phase 1)

This starter establishes a reproducible data-ingestion and first-join pipeline for **PRIORIS: A Distributed Big Data Framework for Context-Aware Cyber Risk Prioritization**. It is an initial milestone, not the finished capstone or risk-scoring method.

## What it does

1. Retrieves an NVD sample marked as known exploited and a second sample from a fixed publication window.
2. Retrieves the public CISA Known Exploited Vulnerabilities (KEV) catalog.
3. Preserves the original JSON responses and a provenance manifest under `data/raw/YYYY-MM-DD/`.
4. Writes simplified JSONL records under `data/processed/YYYY-MM-DD/`.
5. Runs a local PySpark CVE-ID join and writes a Parquet dataset under `results/YYYY-MM-DD/`.

The mixed NVD sample is only for demonstrating the join; it is not representative of global vulnerability prevalence. A CVE absent from CISA KEV is not necessarily unexploited. This join also does not determine whether the affected product/version is present in any organization's assets.

## Phase 3 — Local vulnerability matching

With the existing synthetic inventory and processed snapshot in place, run:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe src\match_vulnerabilities.py --date 2026-10-19
```

The matcher parses inventory CPEs once, indexes distinct installed CPEs by part/vendor/product, caches repeated criterion evaluations, and evaluates configuration trees only for assets with a vulnerable-criterion candidate. It produces:

- `results/YYYY-MM-DD/vulnerability_asset_matches.csv` — locally evaluated CVE-to-installation-to-asset candidate relationships.
- `results/YYYY-MM-DD/cve_configuration_audit.csv` — matched, failed candidate configuration, no-product/version-match, and missing-configuration statuses.
- `results/YYYY-MM-DD/asset_exposure_summary.csv` — per-asset candidate counts and explicit unresolved-evidence / risk-input withholding fields; this is not the final PRIORIS risk score.
- `results/YYYY-MM-DD/cpe_coverage.csv` — vulnerable criterion and installed-inventory coverage.
- `results/YYYY-MM-DD/phase3_summary.json` — input counts, cache/index work, results, limitations, and elapsed time.

Existing Phase 3 reports are not overwritten unless `--force` is supplied. That option replaces only the five Phase 3 reports and leaves raw/processed inputs, synthetic inventory, and the Phase 1 Parquet output untouched. Zero matches are reported as zero; descriptions and CVSS scores are never used to infer applicability.

## Separate NVD-aligned coverage experiment

The baseline inventory is intentionally preserved. To create a separate synthetic experiment from the raw configurations in an existing snapshot:

```powershell
.\.venv\Scripts\python.exe src\generate_coverage_inventory.py --date 2026-10-19 --seed 42 --output-dir data\synthetic_nvd_aligned
.\.venv\Scripts\python.exe src\match_vulnerabilities.py --date 2026-10-19 --inventory-dir data\synthetic_nvd_aligned --output-dir results\2026-10-19-nvd-aligned
```

The generator writes `enterprise_assets.csv`, `software_inventory.csv`, `configuration_cases.csv`, and `generation_manifest.json`. Each generated installation carries its source CVE, configuration, criterion, and generation reason. Positive cases preserve the NVD criteria and satisfy the selected configuration path; negative controls are checked against all structured configurations for their source CVE. `--force` replaces only the generator's four files in its selected output directory. Negated configurations and configurations without a supported positive version are explicitly excluded, not simplified.

The matcher accepts `--inventory-dir` and `--output-dir` to keep this experiment separate; without those flags its existing `data\synthetic` and `results\<date>` defaults remain unchanged. The experiment is synthetic test coverage—not actual enterprise exposure. Its seed, source hashes, case counts, and exclusions are recorded in `generation_manifest.json`.

## Independent CPE matcher validation

Run the provenance-checked golden cases against the staged snapshot without changing the baseline inventories or Phase 3 reports:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe src\validate_matcher_golden.py --date 2026-10-19
```

The fixtures in `tests\fixtures\matcher_validation\golden_cases.json` record source CVEs, exact source criteria, the staged snapshot hashes, expected behavior, rationale, and evidence references. The validator confirms that each embedded source criterion and configuration still matches the staged raw NVD snapshot before evaluating the cases. Its CSV and JSON reports are written to `results\2026-10-19-matcher-validation\`; use `--force` only to replace those two validation reports.

Only `supported` cases are scored as passing or failing. Unsupported and pending cases have no expected outcome and are not counted as passes.

The five previous pending cases were investigated individually:

- **`1.0` versus `1.0.0`: pending review.** NIST CPE Name Matching describes name attribute matching; the NVD API schema stores range boundaries as strings and does not prescribe a universal vendor-version ordering or zero-padding equivalence. The matcher now treats numeric dotted versions with different component counts as unsupported instead of padding with zero.
- **Nested AND/OR templates: unsupported pending authoritative semantics.** The published [NVD CVE API 2.0 schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema) defines configuration objects with a `nodes` array; its node definition includes `operator`, `negate`, and `cpeMatch`, but does not define a recursive child `nodes` property. Because the schema does not describe these deeper templates, they are not scored as verified NVD applicability behavior. This is not treated as proof that extra fields are forbidden. Any such input is withheld for manual review.
- **Negation templates: pending review.** The same schema confirms `negate` is a boolean but does not define how a negated applicability expression contributes to vulnerability applicability. No true negated node occurs in the staged snapshot. Configurations containing negation are withheld from automatic matches and scoring rather than interpreted as safe or vulnerable.
- **CVE-2014-0160 OpenSSL versions: narrowly supported for documented versions only.** The [OpenSSL advisory](https://www.openssl.org/news/secadv/20140407.txt) says OpenSSL 1.0.1 releases, including 1.0.1f, are affected and directs users to upgrade to 1.0.1g. Upstream [OpenSSL 1.0.1 release history](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_1-stable/NEWS) records the 1.0.1f-to-1.0.1g release and CVE fix. A source-backed ordering applies only to the exact staged NVD match-criteria ID and versions `1.0.1`, `1.0.1f`, and `1.0.1g`. Other suffixes remain unsupported; no lexical version ordering is used.

Phase 3 reports `evaluation_status` as one of `confirmed_candidate_match`, `evaluated_no_match`, `unsupported_version_comparison`, `missing_configuration_data`, or `pending_manual_review`. The CVE audit's `risk_scoring_disposition` withholds unsupported versions, missing configurations, and manual-review cases. The asset summary likewise carries per-asset pending-review and unsupported-version counts, a global missing-configuration count, and a `risk_scoring_disposition`; unresolved candidates are withheld, and global configuration gaps prevent interpreting an asset as cleared. A candidate match means only that this local implementation evaluated the staged CPE/configuration successfully; it does not establish real asset exposure. `evaluated_no_match` is not proof that a product is safe. Candidate relationships for a CVE with unresolved version or configuration semantics are withheld from the match output so that downstream scoring cannot mistake uncertainty for a confirmed exposure or a negative finding.

## Separate NVD configuration enrichment

To retrieve the current official NVD CVE API records for CVEs without a structured configuration tree in the dated snapshot, run:

```powershell
.\.venv\Scripts\python.exe src\enrich_nvd_configurations.py --date 2026-10-19 --enrichment-date 2026-10-24
```

The script writes original response bodies, `manifest.json`, and the one-row-per-CVE `cve_classification.csv` under `data\enrichment\<enrichment-date>\`. The manifest records each response URL, retrieval timestamp, HTTP status, byte count, SHA-256, and conservative sequential request policy. It also records a per-CVE evidence class: `configuration_recovered`, `affected_products_only`, `criteria_only`, `no_usable_configuration`, `api_error`, or `pending_review`. The optional NVD CPE Match Criteria API is queried only when a returned CVE record references match-criteria IDs but has no usable structured tree. Affected-products statements or match-criteria records are never converted into configuration trees.

The enrichment directory is separate from all staged snapshots. To evaluate only hash-verified API records classified as containing recovered structured configurations, choose a new results directory:

```powershell
.\.venv\Scripts\python.exe src\match_vulnerabilities.py --date 2026-10-19 --enrichment-dir data\enrichment\2026-10-24 --output-dir results\2026-10-19-enriched-2026-10-24
```

The matcher rejects an enrichment directory for a different source snapshot, a missing response, a hash mismatch, or a response without its declared configuration tree. Its CVE audit and CPE coverage reports identify whether a configuration came from `nvd_api_enrichment`, the staged raw snapshot, or is missing; the summary records the verified manifest hash and enriched CVE IDs. Records without recovered trees continue to carry the existing missing-configuration, unsupported, and manual-review states. Existing Phase 1/Phase 3 results and original raw/normalized snapshots are not modified. The latest NVD records are a dated evidence supplement, not a retroactive replacement for the October 19 snapshot.

### Diagnostic for affected-products-only evidence

Some saved NVD CVE records include product/version statements but no structured NVD configuration tree. Inspect this evidence without creating applicability expressions or asset matches by running:

```powershell
.\.venv\Scripts\python.exe src\diagnose_affected_products.py
```

The diagnostic verifies the saved response hashes against the enrichment manifest and writes two reports to `results\2026-10-19-affected-products-experiment\`. It reports product identifiers, version fields and statuses, available bounds/fix changes, and exact identifier overlap with the existing synthetic inventory. It does not modify enrichment evidence or existing results and refuses to overwrite its own output.

Affected-product version entries with `versionType=custom` are not automatically compared to software versions: the package-specific version rules and inventory identifiers must be established first. The diagnostic is not a matcher, and its product/version candidates are not verified enterprise exposure.

### Patchstack custom-version semantics validation

The isolated validation command checks the saved Patchstack response hashes and records every raw version statement without comparing versions or matching assets:

```powershell
.\.venv\Scripts\python.exe src\validate_custom_version_semantics.py
```

It writes `custom_version_semantics_validation.json` and `custom_version_evidence.csv` under `results\2026-10-19-affected-products-experiment\version-validation\` and refuses to overwrite existing outputs. The [NVD affected-product schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_affected_1.0.json) says comparison semantics are determined by `versionType`; it describes `custom` as unspecified and recommends avoiding it where possible. It also describes `changes` ordering in terms of the same version type. Therefore the 77 records are provenance-verifiable, but none are testable for comparison semantics until an authoritative custom-version rule is established. No synthetic boundary fixtures or vulnerability matches are generated.

## Prerequisites

- Windows 10/11 and PowerShell or the VS Code terminal
- Python 3.13 and PySpark 4.2
- Java 17 or 21
- Internet access for the official data sources

The workspace already contains a virtual environment. These instructions use it without recreating it or reinstalling packages.

On Windows, Spark may also require a Hadoop-compatible `winutils.exe` configured under `%HADOOP_HOME%\bin` to write local Parquet output. Without it, the Spark transformations can run but the final write to `results\` fails. The current workspace does not have this utility configured.

## Run in PowerShell

From the `Prioris` workspace root:

```powershell
.\.venv\Scripts\python.exe src\verify_spark.py
.\.venv\Scripts\python.exe src\download_data.py
```

Use the UTC snapshot date printed by the downloader:

```powershell
.\.venv\Scripts\python.exe src\first_join.py --date YYYY-MM-DD
```

The downloader refuses to overwrite an existing raw snapshot for the same UTC date. To reproduce a join, reuse the already-saved processed files and run only `first_join.py`. The join also refuses to overwrite an existing result for that snapshot.

If NVD rejects a request (for example, HTTP 403 or 429), avoid repeated requests and try later or set an NVD API key in the current PowerShell session with `$env:NVD_API_KEY = '...'`. Do not commit API keys.

## Project and generated data

```text
src/
  verify_spark.py
  download_data.py
  first_join.py
data/
  raw/YYYY-MM-DD/
    nvd_known_exploited.json
    nvd_general.json
    cisa_kev.json
    manifest.json
  processed/YYYY-MM-DD/
    nvd_cves.jsonl
    cisa_kev.jsonl
results/YYYY-MM-DD/
  enriched_cves.parquet/
```

Spark writes Parquet as a directory containing part files. The manifest records the retrieval timestamp, source URLs, catalog version, and record counts. Raw and generated data are excluded from Git by `.gitignore`; they remain in the local workspace.

## Phase 4 — Isolated synthetic risk-scoring prototype

Score only NVD-aligned generated positive asset/CVE relationships that are traceable to a positive case, its source-derived installation, a Phase 3 match row, and a CVE audit status of `matched_assets_under_local_configuration_evaluation`:

```powershell
.\.venv\Scripts\python.exe src\score_risks.py
```

Outputs go to `results\2026-10-19-risk-scoring-prototype\`; the script refuses to overwrite report files. It writes a ranked relationship CSV, per-asset summary CSV, relationship eligibility audit, scoring evidence-gap CSV, and JSON methodology/input summary.

The configurable additive score is `CVSS + KEV bonus * KEV membership + criticality step * criticality level + exposure bonus`. Defaults are a 2-point KEV bonus; criticality levels low/medium/high/critical = 0/1/2/3 with a 1-point step; exposure bonuses restricted/internal/internet-facing = 0/1/2; tiers low below 6, medium from 6, high from 10, critical from 14. CLI options can change each bonus and tier threshold. Missing or invalid CVSS, KEV membership, criticality, or exposure withholds the relationship instead of substituting a value.

The NVD-aligned generator assigns criticality, exposure, environment, asset type, and business unit as synthetic scenario fields; in particular, criticality, exposure, and environment are selected independently at random. This prototype uses only criticality and exposure as illustrative context components. It reports but does not weight environment or asset type because their risk significance is not established. Scores are a configurable demonstration, not a calibrated organizational risk model. All inventories and scenarios are synthetic test data, and output rankings are not confirmed real-world enterprise exposure. The 77 affected-products records with unverified `versionType=custom` semantics are not inputs.

The originally generated Phase 4 reports are preserved unchanged and contain 369 scored relationships, including one pair withheld because a second Phase 3 configuration row did not match the positive case's configuration index. The Phase 4 quality audit found that one matching row did support that case, and that the embedded `case_id` was copied incorrectly into 368 ranked rows. After fixing those provenance issues, a corrected run was written separately to `results\2026-10-19-risk-scoring-prototype\quality-audit\corrected-results\`:

```powershell
.\.venv\Scripts\python.exe src\score_risks.py --output-dir results\2026-10-19-risk-scoring-prototype\quality-audit\corrected-results
```

The corrected run summarizes all 1,168 synthetic assets and scores 370 unique asset/CVE relationships across 370 assets. Of 6,481 unique Phase 3 relationships, 6,111 are withheld; the corrected tier counts are 80 critical, 237 high, 49 medium, and 4 low. The 370 scored rows include 361 CVSS 3.1 and 9 CVSS 4.0 base scores. The quality audit and correction notes are in `results\2026-10-19-risk-scoring-prototype\quality-audit\`. These counts describe generated test scenarios only, not real-world enterprise exposure.

The prototype explicitly does not calibrate CVSS 3.1 and 4.0 scores against one another. A separate sensitivity analysis should precede any operational interpretation of rankings that compare scores from both versions.

## Phase 5 — Local PRIORIS risk intelligence dashboard

The dashboard's **Risk intelligence** mode reads the generated Phase 4 outputs from `data\processed\risk_prioritization\` together with the Phase 3 applicability evidence and the existing synthetic asset context. It displays the executive overview, risk distributions, ranked assets and CVEs, software exposure, score components, and unresolved/unsupported/manual-review statuses. It reads only selected columns from the prioritized Parquet output, caches the dashboard data, and does not load the CPE association dataset or recalculate risk scores. The existing **Try Demo** and **Analyze My Data** modes remain available.

From PowerShell at the project root, start the dashboard with the project virtual environment:

```powershell
Set-Location D:\Projects\Prioris
.\.venv\Scripts\python.exe -m streamlit run src\risk_dashboard.py
```

Risk prioritization uses synthetic enterprise inventory; results are not confirmed real-world exposure. Unresolved, unsupported, and manual-review cases remain separate and unscored, not safe. The **Try Demo** mode continues to display the separately corrected NVD-aligned scoring experiment reports and their existing audit views.

## Phase 6 — Analyze an uploaded inventory locally

The dashboard's **Analyze My Data** mode accepts an enterprise asset CSV and a software inventory CSV. It validates both files, previews the uploaded rows, then runs the existing local Phase 3 CPE/configuration matcher against the staged NVD and CISA snapshot dated `2026-10-19`. The output scoring reuses the existing Phase 4 `score_components` formula for candidate relationships that pass the matcher's evidence audit; it does not read or copy demo findings. Phase 4's `score_experiment` itself is not used because its generated positive-case provenance requirements deliberately apply only to the synthetic experiment.

Use the downloadable templates in the dashboard. Their headers come from the existing `data\synthetic\enterprise_assets.csv` and `data\synthetic\software_inventory.csv` schemas:

- Asset CSV required columns: `asset_id`, `criticality`, `exposure`. Optional project-schema context columns are `asset_type`, `business_unit`, `environment`, and `data_origin`.
- Software CSV required columns: `installation_id`, `asset_id`, `software_vendor`, `software_product`, `software_name`, `software_version`, and `cpe23_uri`.
- Criticality values: `low`, `medium`, `high`, `critical`. Exposure values: `restricted`, `internal`, `internet-facing`.
- `cpe23_uri` must be an explicit CPE 2.3 formatted identifier with a concrete `a`, `o`, or `h` part, vendor, product, and version. The CPE version must equal the provided `software_version`. Wildcard and `-` version placeholders are rejected. Software product/vendor text is descriptive; the CPE identifier is what the matcher evaluates.
- Asset IDs must be unique, software installation IDs must be unique, and every software `asset_id` must refer to an uploaded asset. Empty files, missing fields, invalid context labels, invalid CPEs, and orphan rows stop the analysis; rows are not silently discarded.

The only matching evidence available to this mode is the already-staged local snapshot. It makes no network/API calls and does not retrieve newer data. If the staged raw NVD files, normalized NVD/CISA files, or manifest are missing or empty, analysis stops with an error. A local Phase 3 match is a candidate—not confirmation of real asset exposure. The matcher conservatively withholds unsupported version comparisons and configuration-review cases; these and CVE-level source-data gaps are available in the audit view. Missing CVSS or other required score evidence also prevents scoring. An asset with no match or no score is **not cleared** and must not be considered safe.

Uploaded CSV contents are handled in the local Streamlit process. The matcher uses an operating-system temporary directory during analysis, which is removed on completion; uploaded inventories are not written to project datasets or reports. Analysis outputs are generated in memory for download and never overwrite Phase 3, Phase 4, or demo files. Do not upload confidential inventory data to any publicly hosted dashboard instance.

Run the complete application in PowerShell:

```powershell
Set-Location C:\Users\Nikhil\Desktop\Prioris
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run src\risk_dashboard.py
```

Upload scoring uses the existing illustrative Phase 4 formula and weights, not a validated operational risk model. Uploaded criticality and exposure values are user-provided and not independently verified. CVSS 3.1 and 4.0 scores are not cross-version calibrated. The 77 `versionType=custom` affected-product records are excluded because their comparator semantics remain unverified.

## Research limitations and next steps

- NVD raw configurations are preserved for product and version applicability matching. Phase 3 evaluates local CPE component patterns, supported numeric dotted-version boundaries, configuration/node operators in the published schema shape, and non-vulnerable supporting criteria. It does not claim complete CPE/NVD conformance. Generic alphanumeric versions, different-length numeric version tokens, negated configurations, and tree shapes not defined by the published NVD API schema are withheld or reported as unsupported/manual review. Numeric dotted ordering with equal component counts is still a local heuristic, not universal vendor-version semantics.
- Synthetic CPEs and software versions are illustrative. Phase 3 matches are local candidates, not verified production vulnerabilities. Missing structured configurations are reported explicitly, not inferred from descriptions.
- `local[2]` demonstrates local Spark execution, not multi-machine scaling.
- Any future synthetic asset inventory must use a fixed seed, document its assumptions, and never be represented as a real organization's systems.

Official data and documentation:

- [NVD CVE API documentation](https://nvd.nist.gov/developers/vulnerabilities)
- [NVD Products and Match Criteria API documentation](https://nvd.nist.gov/developers/products)
- [NVD CPE FAQs](https://nvd.nist.gov/general/faq-sections/cpe-faqs)
- [NVD CVE API 2.0 JSON Schema](https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema)
- [NIST IR 7696 — CPE 2.3 Name Matching Specification](https://csrc.nist.gov/pubs/ir/7696/final)
- [OpenSSL CVE-2014-0160 security advisory](https://www.openssl.org/news/secadv/20140407.txt)
- [OpenSSL 1.0.1 release history](https://raw.githubusercontent.com/openssl/openssl/OpenSSL_1_0_1-stable/NEWS)
- [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA KEV data repository mirror](https://github.com/cisagov/kev-data)
- [PySpark installation documentation](https://spark.apache.org/docs/latest/api/python/getting_started/install.html)
