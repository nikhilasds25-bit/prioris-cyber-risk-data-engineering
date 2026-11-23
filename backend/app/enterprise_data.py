"""Bounded CSV/JSON parsing, canonical validation and transparent scoring."""
from __future__ import annotations

import csv
import hashlib
import ipaddress
import io
import json
import math
import os
import re
from datetime import date, datetime
from typing import Any, BinaryIO, Iterator

import ijson

from app.scoring import RiskScoringConfig, risk_tier, score_components


MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_ROWS = 100_000
MAX_REPORTED_ERRORS = 500
CANONICAL_FIELDS = (
    "asset_id", "asset_name", "asset_type", "hostname", "ip_address",
    "operating_system", "software_name", "installed_version", "cve_id",
    "vulnerability_name", "severity", "cvss_score", "business_criticality",
    "internet_exposed", "known_exploited", "remediation_status", "first_detected",
    "applicability_status", "match_evidence", "exposure",
)

ALIASES = {
    "asset_id": {"assetid", "asset_id", "asset", "device_id", "host_id", "system_id"},
    "asset_name": {"assetname", "asset_name", "device_name", "system_name"},
    "asset_type": {"assettype", "asset_type", "device_type", "system_type"},
    "hostname": {"hostname", "host_name", "computer_name", "fqdn"},
    "ip_address": {"ip", "ipaddress", "ip_address", "ip_addr"},
    "operating_system": {"os", "operating_system", "operatingsystem", "platform"},
    "software_name": {"software", "software_name", "product", "product_name", "application"},
    "installed_version": {"version", "installed_version", "software_version", "product_version"},
    "cve_id": {"cve", "cve_id", "cveid", "vulnerability_id"},
    "vulnerability_name": {"vulnerability", "vulnerability_name", "finding", "title"},
    "severity": {"severity", "risk", "risk_level", "priority"},
    "cvss_score": {"cvss", "cvss_score", "cvss_v3_score", "base_score"},
    "business_criticality": {"criticality", "business_criticality", "asset_criticality", "business_impact"},
    "internet_exposed": {"internet_exposed", "internet_facing", "publicly_accessible", "external"},
    "known_exploited": {"known_exploited", "kev", "cisa_kev", "known_exploited_vulnerability"},
    "remediation_status": {"remediation_status", "patch_status", "status", "remediation"},
    "first_detected": {"first_detected", "discovered_at", "detection_date", "first_seen"},
    "applicability_status": {"applicability_status", "match_status", "finding_status"},
    "match_evidence": {"match_evidence", "matching_evidence", "evidence", "match_details"},
    "exposure": {"exposure", "network_exposure", "network_zone", "network_access"},
}

_HEADER_RE = re.compile(r"[^a-z0-9]+")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_SEVERITY_MAP = {"critical": "critical", "high": "high", "medium": "medium", "moderate": "medium", "low": "low"}
_CRITICALITY_MAP = {
    "critical": "critical", "mission critical": "critical", "tier 0": "critical", "tier 1": "critical",
    "high": "high", "important": "high", "tier 2": "high",
    "medium": "medium", "moderate": "medium", "tier 3": "medium",
    "low": "low", "tier 4": "low",
}


class DatasetValidationError(ValueError):
    pass


def risk_tier_for_score(score: float | None) -> str | None:
    if score is None:
        return None
    return risk_tier(score, RiskScoringConfig())


def safe_filename(filename: str | None) -> str:
    value = os.path.basename((filename or "").replace("\\", "/")).strip()
    if not value or len(value) > 255:
        raise DatasetValidationError("A filename of at most 255 characters is required")
    suffix = os.path.splitext(value)[1].lower()
    if suffix not in {".csv", ".json"}:
        raise DatasetValidationError("Only .csv and .json files are supported")
    return value


def file_size_and_sha256(file: BinaryIO) -> tuple[int, str]:
    file.seek(0)
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: file.read(1024 * 1024), b""):
        size += len(chunk)
        if size > MAX_UPLOAD_BYTES:
            raise DatasetValidationError(f"Upload exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MiB limit")
        digest.update(chunk)
    file.seek(0)
    return size, digest.hexdigest()


def _normalise_header(value: str) -> str:
    return _HEADER_RE.sub("_", value.strip().lower()).strip("_")


def suggest_mapping(columns: list[str]) -> dict[str, str | None]:
    normalised = {_normalise_header(column): column for column in columns}
    aliases = {
        field: {_normalise_header(alias) for alias in names}
        for field, names in ALIASES.items()
    }
    return {
        field: next((normalised[key] for key in aliases[field] if key in normalised), None)
        for field in CANONICAL_FIELDS
    }


def validate_mapping(mapping: dict[str, Any], columns: list[str]) -> dict[str, str | None]:
    if set(mapping) - set(CANONICAL_FIELDS):
        raise DatasetValidationError("Column mapping contains unsupported PRIORIS fields")
    selected: dict[str, str | None] = {field: None for field in CANONICAL_FIELDS}
    for field, source in mapping.items():
        if source in (None, ""):
            continue
        if not isinstance(source, str) or source not in columns:
            raise DatasetValidationError(f"Column mapping for {field} must select a detected input column")
        selected[field] = source
    used = [value for value in selected.values() if value is not None]
    if len(used) != len(set(used)):
        raise DatasetValidationError("Each input column can be mapped to only one PRIORIS field")
    if not selected["asset_id"]:
        raise DatasetValidationError("Map a source column to the required asset_id field")
    return selected


def _json_rows(file: BinaryIO) -> Iterator[Any]:
    file.seek(0)
    first = file.read(1)
    while first in (b" ", b"\t", b"\r", b"\n"):
        first = file.read(1)
    file.seek(0)
    if first == b"[":
        yield from ijson.items(file, "item", use_float=True)
        return
    rows = ijson.items(file, "records.item", use_float=True)
    found = False
    for row in rows:
        found = True
        yield row
    if not found:
        file.seek(0)
        try:
            parsed = json.load(file)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise DatasetValidationError("JSON file is not valid UTF-8 JSON") from exc
        if isinstance(parsed, dict) and isinstance(parsed.get("records"), list):
            return
        if isinstance(parsed, dict):
            yield parsed
        else:
            raise DatasetValidationError("JSON must be an array, an object with a records array, or one record object")


def source_rows(file: BinaryIO, extension: str) -> tuple[list[str], Iterator[dict[str, Any]]]:
    file.seek(0)
    if extension == ".csv":
        try:
            wrapper = io.TextIOWrapper(file, encoding="utf-8-sig", newline="")
            reader = csv.DictReader(wrapper)
            columns = [str(column).strip() if column is not None else "" for column in (reader.fieldnames or [])]
        except (UnicodeDecodeError, csv.Error) as exc:
            raise DatasetValidationError("CSV file could not be decoded") from exc
        if not columns or any(not column for column in columns):
            wrapper.detach()
            raise DatasetValidationError("CSV must include non-empty column names")
        if len({_normalise_header(column) for column in columns}) != len(columns):
            wrapper.detach()
            raise DatasetValidationError("CSV header names must be unique")

        def csv_iter() -> Iterator[dict[str, Any]]:
            try:
                for row_number, row in enumerate(reader, start=2):
                    extra = row.get(None)
                    if extra and any(value not in (None, "") for value in extra):
                        raise DatasetValidationError(f"CSV row {row_number} has more fields than the header")
                    yield {str(key).strip(): value for key, value in row.items() if key is not None}
            except (UnicodeDecodeError, csv.Error) as exc:
                raise DatasetValidationError("CSV contains invalid text or quoting") from exc
            finally:
                wrapper.detach()

        return columns, csv_iter()

    if extension != ".json":
        raise DatasetValidationError("Only .csv and .json files are supported")
    try:
        rows = _json_rows(file)
        first_row = next(rows, None)
    except (ijson.common.JSONError, UnicodeDecodeError) as exc:
        raise DatasetValidationError("JSON file is malformed or is not valid UTF-8") from exc
    if first_row is None:
        return [], iter(())
    if not isinstance(first_row, dict):
        raise DatasetValidationError("Every JSON record must be an object")
    columns = [str(key) for key in first_row]

    def json_iter() -> Iterator[dict[str, Any]]:
        yield first_row
        try:
            for row in rows:
                if not isinstance(row, dict):
                    raise DatasetValidationError("Every JSON record must be an object")
                yield {str(key): value for key, value in row.items()}
        except (ijson.common.JSONError, UnicodeDecodeError) as exc:
            raise DatasetValidationError("JSON file is malformed or is not valid UTF-8") from exc

    return columns, json_iter()


def _text(value: Any, field: str, max_length: int, errors: list[dict[str, str]]) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool) or isinstance(value, (dict, list)):
        errors.append({"field": field, "message": "Expected a scalar text value"})
        return None
    if not isinstance(value, str) and field != "asset_id":
        errors.append({"field": field, "message": "Expected a text value"})
        return None
    rendered = str(value).strip()
    if not rendered:
        return None
    if len(rendered) > max_length:
        errors.append({"field": field, "message": f"Value exceeds {max_length} characters"})
        return None
    return rendered


def _boolean(value: Any, field: str, errors: list[dict[str, str]]) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and value in (0, 1):
        return bool(value)
    normalised = str(value).strip().lower()
    if normalised in {"true", "yes", "y", "1", "exposed", "public", "internet"}:
        return True
    if normalised in {"false", "no", "n", "0", "internal", "not exposed", "not_exposed"}:
        return False
    errors.append({"field": field, "message": "Expected a true/false value"})
    return None


def canonical_record(row: dict[str, Any], mapping: dict[str, str | None]) -> tuple[dict[str, Any], list[dict[str, str]]]:
    errors: list[dict[str, str]] = []
    raw = {field: row.get(source) if source else None for field, source in mapping.items()}
    result: dict[str, Any] = {}
    result["asset_id"] = _text(raw.get("asset_id"), "asset_id", 255, errors)
    if not result["asset_id"]:
        errors.append({"field": "asset_id", "message": "Asset ID is required"})

    limits = {
        "asset_name": 255, "asset_type": 120, "hostname": 255, "ip_address": 64,
        "operating_system": 255, "software_name": 255, "installed_version": 255,
        "vulnerability_name": 500, "remediation_status": 120,
        "applicability_status": 40, "match_evidence": 4000,
        "exposure": 40,
    }
    for field, limit in limits.items():
        result[field] = _text(raw.get(field), field, limit, errors)
    if result.get("ip_address"):
        try:
            ipaddress.ip_address(result["ip_address"])
        except ValueError:
            errors.append({"field": "ip_address", "message": "Expected a valid IPv4 or IPv6 address"})

    cve = _text(raw.get("cve_id"), "cve_id", 32, errors)
    if cve and not _CVE_RE.fullmatch(cve):
        errors.append({"field": "cve_id", "message": "CVE identifier must match CVE-YYYY-NNNN"})
        cve = None
    result["cve_id"] = cve.upper() if cve else None

    severity = _text(raw.get("severity"), "severity", 24, errors)
    if severity:
        normalised_severity = _SEVERITY_MAP.get(severity.lower())
        if normalised_severity is None:
            errors.append({"field": "severity", "message": "Expected Critical, High, Medium, Low or empty"})
        severity = normalised_severity
    result["severity"] = severity

    cvss_value = raw.get("cvss_score")
    if cvss_value in (None, ""):
        result["cvss_score"] = None
    else:
        try:
            if isinstance(cvss_value, bool):
                raise ValueError
            score = float(cvss_value)
        except (TypeError, ValueError):
            score = math.nan
        if not math.isfinite(score) or score < 0 or score > 10:
            errors.append({"field": "cvss_score", "message": "CVSS score must be a number from 0 to 10"})
            result["cvss_score"] = None
        else:
            result["cvss_score"] = score

    criticality = _text(raw.get("business_criticality"), "business_criticality", 32, errors)
    if criticality:
        criticality = _CRITICALITY_MAP.get(criticality.lower())
        if criticality is None:
            errors.append({"field": "business_criticality", "message": "Expected Critical, High, Medium, Low or empty"})
    result["business_criticality"] = criticality
    result["internet_exposed"] = _boolean(raw.get("internet_exposed"), "internet_exposed", errors)
    result["known_exploited"] = _boolean(raw.get("known_exploited"), "known_exploited", errors)

    exposure = _text(raw.get("exposure"), "exposure", 40, errors)
    if exposure:
        exposure = exposure.strip().lower().replace("_", "-")
        if exposure not in {"internet-facing", "internal", "restricted"}:
            errors.append({
                "field": "exposure",
                "message": "Expected internet-facing, internal, restricted or empty",
            })
            exposure = None
        elif (
            (result["internet_exposed"] is True and exposure != "internet-facing")
            or (result["internet_exposed"] is False and exposure == "internet-facing")
        ):
            errors.append({
                "field": "exposure",
                "message": "Exposure class conflicts with the internet_exposed value",
            })
    result["exposure"] = exposure

    detected = _text(raw.get("first_detected"), "first_detected", 40, errors)
    if detected:
        try:
            try:
                result["first_detected"] = date.fromisoformat(detected)
            except ValueError:
                result["first_detected"] = datetime.fromisoformat(
                    detected.replace("Z", "+00:00")
                ).date()
        except ValueError:
            errors.append({
                "field": "first_detected",
                "message": "Expected a complete ISO date (YYYY-MM-DD) or ISO datetime",
            })
            result["first_detected"] = None
    else:
        result["first_detected"] = None
    status_value = result.get("applicability_status")
    if status_value:
        status_value = status_value.lower().replace(" ", "_")
        status_aliases = {
            "confirmed": "confirmed_match",
            "matched": "confirmed_match",
            "manual_review": "pending_manual_review",
            "review": "pending_manual_review",
            "unsupported": "unsupported_matching",
        }
        status_value = status_aliases.get(status_value, status_value)
        if status_value not in {
            "confirmed_match", "reported_unverified", "pending_manual_review",
            "unresolved_product", "unsupported_matching",
        }:
            errors.append({"field": "applicability_status", "message": "Unsupported applicability status"})
            status_value = None
    result["applicability_status"] = status_value
    return result, errors


def row_fingerprint(record: dict[str, Any]) -> str:
    serialisable = {
        key: value.isoformat() if isinstance(value, date) else value
        for key, value in record.items()
    }
    encoded = json.dumps(serialisable, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def evaluate_risk(record: dict[str, Any]) -> dict[str, Any]:
    reported_status = record.get("applicability_status")
    if reported_status in {"unsupported_matching", "pending_manual_review", "unresolved_product"}:
        missing = ["independent_applicability_verification"]
        if reported_status == "unsupported_matching":
            missing.append("supported_matching_method")
        if reported_status == "unresolved_product":
            missing.append("canonical_product_identity")
        return {
            "applicability_status": reported_status,
            "risk_score": None,
            "risk_tier": None,
            "risk_factors": {},
            "missing_evidence": missing,
        }
    cve_id = record.get("cve_id")
    if not isinstance(cve_id, str) or not _CVE_RE.fullmatch(cve_id):
        source_claimed_confirmation = reported_status == "confirmed_match"
        if reported_status == "confirmed_match":
            status = "pending_manual_review"
        else:
            status = reported_status or (
                "unresolved_product" if record.get("software_name") else "inventory_only"
            )
        missing = ["valid_cve_identifier"] if cve_id else ["cve_id"]
        missing.append("independent_applicability_verification")
        if source_claimed_confirmation:
            missing.append("source_confirmation_not_independently_verified")
        return {
            "applicability_status": status,
            "risk_score": None,
            "risk_tier": None,
            "risk_factors": {},
            "missing_evidence": missing,
        }

    exposure = record.get("exposure")
    if exposure is None and record.get("internet_exposed") is True:
        exposure = "internet-facing"
    if (
        (record.get("internet_exposed") is True and exposure not in (None, "internet-facing"))
        or (record.get("internet_exposed") is False and exposure == "internet-facing")
    ):
        return {
            "applicability_status": (
                "reported_unverified" if reported_status in (None, "confirmed_match") else reported_status
            ),
            "risk_score": None,
            "risk_tier": None,
            "risk_factors": {},
            "missing_evidence": [
                "conflicting_network_exposure_evidence",
                "independent_applicability_verification",
            ],
        }
    scored = score_components(
        record.get("cvss_score"),
        record.get("known_exploited"),
        record.get("business_criticality"),
        exposure,
    )
    missing_evidence = []
    evidence_names = {
        "valid_cvss_score_0_to_10": "cvss_score",
        "explicit_cisa_kev_membership": "known_exploited",
        "recognized_asset_criticality": "business_criticality",
        "recognized_asset_exposure": "exposure_class",
    }
    for item in scored["missing_evidence"]:
        missing_evidence.append(evidence_names[item])
    if record.get("internet_exposed") is None and record.get("exposure") is None:
        missing_evidence.append("internet_exposed")
    missing_evidence.append("independent_applicability_verification")

    components = scored.get("components", {})
    factors = {
        "cvss": components["severity"],
        "known_exploited": components["kev"],
        "business_criticality": components["criticality"],
        "network_exposure": components["exposure"],
    } if components else {}
    source_status = reported_status
    if source_status == "confirmed_match" or source_status is None:
        applicability_status = (
            "pending_manual_review"
            if source_status is None and scored["score"] is None
            else "reported_unverified"
        )
    else:
        applicability_status = source_status
    return {
        "applicability_status": applicability_status,
        "risk_score": scored["score"],
        "risk_tier": scored["tier"],
        "risk_factors": factors,
        "missing_evidence": missing_evidence,
    }


def prioritize_remediation(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    priorities = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}
    result = []
    for record in records:
        score = record.get("risk_score")
        tier = risk_tier_for_score(score)
        known_exploited = record.get("known_exploited")
        if score is None:
            priority = "Review"
        elif known_exploited is True or tier == "critical":
            priority = "P1"
        elif tier:
            priority = priorities[tier]
        else:
            priority = priorities["low"]

        evidence = []
        factors = record.get("risk_factors") or {}
        cvss = factors.get("cvss", record.get("cvss_score"))
        if cvss is not None:
            evidence.append(f"Supplied CVSS base score: {cvss}")
        factor_labels = {
            "known_exploited": "KEV contribution",
            "business_criticality": "Business criticality contribution",
            "network_exposure": "Network exposure contribution",
        }
        for factor, label in factor_labels.items():
            if factor in factors:
                evidence.append(f"{label}: +{factors[factor]}")
        if known_exploited is True:
            evidence.append(
                f"Known-exploited status was explicitly true for "
                f"{record.get('known_exploited_records', 1)} reported record(s)"
            )
        elif known_exploited is False:
            evidence.append("Known-exploited status was explicitly false in the supplied records")
        else:
            evidence.append("Known-exploited status is missing or inconsistent in the supplied records")
        if record.get("internet_exposed_assets", 0):
            evidence.append(
                f"{record['internet_exposed_assets']} affected asset(s) were marked internet-exposed"
            )
        if record.get("criticality_assets", 0):
            evidence.append(
                f"{record['criticality_assets']} affected asset(s) were marked high or critical business criticality"
            )
        evidence.append(
            f"Score uses the existing PRIORIS factors; highest reported score: "
            f"{score if score is not None else 'unavailable'}"
        )

        if score is None:
            action = (
                "Review this reported finding and collect sufficient CVSS and "
                "product/applicability evidence before deciding on remediation."
            )
        elif known_exploited is True:
            action = (
                "Validate the reported product and version, then prioritize a vendor-supported "
                "patch or mitigation if the installation is affected; verify remediation."
            )
        elif tier in {"critical", "high"}:
            action = (
                "Validate product/version applicability and prioritize a vendor-supported "
                "patch or mitigation; verify the result after remediation."
            )
        elif score is not None:
            action = (
                "Validate product/version applicability and schedule a vendor-supported "
                "patch or mitigation according to the supplied evidence."
            )
        else:
            action = (
                "Review the reported finding and collect missing CVSS, product/version, "
                "or applicability evidence before assigning remediation."
            )

        result.append({
            **record,
            "risk_tier": tier,
            "suggested_priority": priority,
            "risk_evidence": evidence,
            "recommended_action": action,
            "applicability_status": record.get("applicability_status") or "reported_unverified",
        })

    return sorted(
        result,
        key=lambda item: (
            {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "Review": 4}.get(
                item["suggested_priority"], 4
            ),
            item.get("risk_score") is None,
            -(item.get("risk_score") if item.get("risk_score") is not None else 0),
            item.get("known_exploited") is not True,
            -item.get("affected_assets", 0),
            item.get("cve_id") or "",
        ),
    )


def prioritize_assets(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for record in records:
        reasons = []
        critical_high = record.get("critical_high_findings", 0)
        if critical_high:
            reasons.append(f"{critical_high} reported Critical/High scored finding(s)")
        if record.get("known_exploited_findings", 0):
            reasons.append(
                f"{record['known_exploited_findings']} finding(s) with explicitly reported KEV status"
            )
        if record.get("internet_exposed") is True:
            reasons.append("Asset was marked internet-exposed in the latest inventory")
        elif record.get("internet_exposed") is None:
            reasons.append("Internet exposure was not supplied for this asset")
        if record.get("business_criticality"):
            reasons.append(
                f"Business criticality supplied as {record['business_criticality']}"
            )
        if record.get("known_exploited_unknown_findings", 0):
            reasons.append(
                f"KEV status was missing for {record['known_exploited_unknown_findings']} finding(s)"
            )
        if record.get("unscored_findings", 0):
            reasons.append(
                f"{record['unscored_findings']} finding(s) had insufficient evidence for a score"
            )
        if record.get("max_risk_score") is not None:
            reasons.append(f"Maximum existing PRIORIS score: {record['max_risk_score']}")
        if not reasons:
            reasons.append("No scored finding evidence was available for this asset")
        result.append({**record, "risk_reasons": reasons})
    return sorted(
        result,
        key=lambda item: (
            item.get("max_risk_score") is None,
            -(item.get("max_risk_score") if item.get("max_risk_score") is not None else 0),
            -item.get("critical_high_findings", 0),
            item.get("internet_exposed") is not True,
            item.get("asset_id", ""),
        ),
    )


def build_executive_summary(
    assets: list[dict[str, Any]],
    cves: list[dict[str, Any]],
    software: list[dict[str, Any]],
    remediation: list[dict[str, Any]],
) -> dict[str, Any]:
    top_asset = assets[0] if assets else None
    top_cve = cves[0] if cves else None
    top_software = software[0] if software else None
    top_fix = remediation[0] if remediation else None

    return {
        "biggest_security_problem": (
            f"{top_cve['cve_id']} is the highest-ranked reported CVE, associated with "
            f"{top_cve['affected_assets']} asset(s)."
            if top_cve else "No CVE identifiers with prioritizable evidence were supplied."
        ),
        "immediate_attention": [
            {
                "asset_id": asset["asset_id"],
                "asset_name": asset.get("asset_name"),
                "risk_score": asset.get("max_risk_score"),
                "reasons": asset.get("risk_reasons", []),
            }
            for asset in assets[:3]
        ],
        "greatest_software_exposure": (
            f"{top_software['software_name']}"
            f"{' ' + top_software['installed_version'] if top_software.get('installed_version') else ''} "
            f"has reported findings on {top_software['affected_assets']} asset(s)."
            if top_software else "No software products with reported vulnerability records were identified."
        ),
        "fix_first": (
            f"Review {top_fix['cve_id']} first ({top_fix['suggested_priority']}); "
            f"{top_fix['recommended_action']}"
            if top_fix else "Review unscored and unresolved records for missing evidence."
        ),
    }
