"""Organization-scoped company dataset onboarding and risk views."""
from __future__ import annotations

import csv
import io
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import case, desc, distinct, func, or_, select, tuple_
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session, aliased

from app.database import get_db
from app.dependencies import get_current_membership, get_current_user, require_roles
from app.enterprise_data import (
    CANONICAL_FIELDS,
    MAX_REPORTED_ERRORS,
    MAX_ROWS,
    DatasetValidationError,
    canonical_record,
    evaluate_risk,
    file_size_and_sha256,
    build_executive_summary,
    prioritize_assets,
    prioritize_remediation,
    row_fingerprint,
    safe_filename,
    source_rows,
    risk_tier_for_score,
    suggest_mapping,
    validate_mapping,
)
from app.models import (
    AuditLog,
    EnterpriseAsset,
    EnterpriseExposure,
    EnterpriseImport,
    OrganizationMembership,
    User,
)

logger = logging.getLogger("prioris.api.enterprise")
router = APIRouter(prefix="/api/v1/enterprise", tags=["enterprise"])
REVIEW_STATUSES = ("pending_manual_review", "unresolved_product", "unsupported_matching")


def _read_mapping(value: str) -> dict[str, Any]:
    try:
        mapping = json.loads(value)
    except json.JSONDecodeError as exc:
        raise DatasetValidationError("Column mapping must be valid JSON") from exc
    if not isinstance(mapping, dict):
        raise DatasetValidationError("Column mapping must be an object")
    return mapping


def _scan_dataset(rows, mapping: dict[str, str | None]):
    seen: set[str] = set()
    errors: list[dict[str, Any]] = []
    stats = {"rows_total": 0, "rows_valid": 0, "rows_invalid": 0, "rows_duplicate": 0}
    error_count = 0
    for row_number, row in enumerate(rows, start=1):
        stats["rows_total"] += 1
        if stats["rows_total"] > MAX_ROWS:
            raise DatasetValidationError(f"Dataset exceeds the {MAX_ROWS:,}-row limit")
        canonical, row_errors = canonical_record(row, mapping)
        row_hash = row_fingerprint(canonical) if not row_errors else None
        if row_hash and row_hash in seen:
            stats["rows_duplicate"] += 1
            row_errors.append({"field": "record", "message": "Duplicate row"})
        elif row_hash:
            seen.add(row_hash)
        if row_errors:
            error_count += len(row_errors)
            if not (len(row_errors) == 1 and row_errors[0]["message"] == "Duplicate row"):
                stats["rows_invalid"] += 1
            remaining = MAX_REPORTED_ERRORS - len(errors)
            if remaining > 0:
                errors.extend(
                    {"row": row_number, **error} for error in row_errors[:remaining]
                )
        else:
            stats["rows_valid"] += 1
    return stats, errors, error_count


def _upload_metadata(upload: UploadFile) -> tuple[str, str, int]:
    try:
        filename = safe_filename(upload.filename)
        size, fingerprint = file_size_and_sha256(upload.file)
    except DatasetValidationError as exc:
        code = 413 if "exceeds" in str(exc) else 422
        raise HTTPException(status_code=code, detail=str(exc)) from exc
    if size == 0:
        raise HTTPException(status_code=422, detail="Uploaded file is empty")
    return filename, fingerprint, size


def _latest_import_id(db: Session, organization_id: uuid.UUID) -> uuid.UUID | None:
    return db.scalar(
        select(EnterpriseImport.id)
        .where(EnterpriseImport.organization_id == organization_id, EnterpriseImport.status == "completed")
        .order_by(desc(EnterpriseImport.completed_at), desc(EnterpriseImport.created_at))
        .limit(1)
    )


def _asset_values(record: dict[str, Any], organization_id: uuid.UUID, import_id: uuid.UUID) -> dict[str, Any]:
    return {
        "organization_id": organization_id,
        "import_id": import_id,
        "asset_id": record["asset_id"],
        "asset_name": record.get("asset_name"),
        "asset_type": record.get("asset_type"),
        "hostname": record.get("hostname"),
        "ip_address": record.get("ip_address"),
        "operating_system": record.get("operating_system"),
        "business_criticality": record.get("business_criticality"),
        "internet_exposed": record.get("internet_exposed"),
    }


def _exposure_values(
    record: dict[str, Any], organization_id: uuid.UUID, import_id: uuid.UUID, fingerprint: str
) -> dict[str, Any]:
    scoring = evaluate_risk(record)
    return {
        "organization_id": organization_id,
        "import_id": import_id,
        "asset_id": record["asset_id"],
        "row_sha256": fingerprint,
        "software_name": record.get("software_name"),
        "installed_version": record.get("installed_version"),
        "cve_id": record.get("cve_id"),
        "vulnerability_name": record.get("vulnerability_name"),
        "severity": record.get("severity"),
        "cvss_score": record.get("cvss_score"),
        "known_exploited": record.get("known_exploited"),
        "remediation_status": record.get("remediation_status"),
        "first_detected": record.get("first_detected"),
        "applicability_status": scoring["applicability_status"],
        "risk_score": scoring["risk_score"],
        "risk_tier": scoring["risk_tier"],
        "risk_factors": scoring["risk_factors"],
        "missing_evidence": scoring["missing_evidence"],
        "source_evidence": {
            "source": "organization_upload",
            "reported_applicability_status": record.get("applicability_status"),
            "matching_evidence": record.get("match_evidence"),
            "reported_exposure_class": record.get("exposure"),
        },
    }


@router.post("/imports/preview")
def preview_import(
    upload: UploadFile = File(...),
    mapping_json: str = Form(default="{}"),
    membership: OrganizationMembership = Depends(require_roles("admin", "analyst")),
):
    filename, _, size = _upload_metadata(upload)
    extension = filename.rsplit(".", 1)[-1].lower()
    extension = f".{extension}"
    try:
        columns, rows = source_rows(upload.file, extension)
        submitted_mapping = _read_mapping(mapping_json)
        mapping = validate_mapping(submitted_mapping, columns) if submitted_mapping else suggest_mapping(columns)
        if not mapping.get("asset_id"):
            mapping_errors = ["Map an input column to the required asset_id field"]
        else:
            mapping_errors = []
        stats, errors, error_count = _scan_dataset(rows, mapping)
        return {
            "filename": filename,
            "file_size_bytes": size,
            "detected_columns": columns,
            "canonical_fields": list(CANONICAL_FIELDS),
            "suggested_mapping": mapping,
            "mapping_errors": mapping_errors,
            "validation": stats,
            "validation_errors": errors,
            "validation_errors_truncated": error_count > len(errors),
        }
    except DatasetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/imports", status_code=status.HTTP_201_CREATED)
def create_import(
    upload: UploadFile = File(...),
    mapping_json: str = Form(default="{}"),
    membership: OrganizationMembership = Depends(require_roles("admin", "analyst")),
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    filename, fingerprint, _ = _upload_metadata(upload)
    organization_id = membership.organization_id
    existing = db.scalar(
        select(EnterpriseImport).where(
            EnterpriseImport.organization_id == organization_id,
            EnterpriseImport.content_sha256 == fingerprint,
        )
    )
    if existing:
        raise HTTPException(status_code=409, detail=f"This file was already imported as {existing.id}")

    extension = f".{filename.rsplit('.', 1)[-1].lower()}"
    try:
        columns, rows = source_rows(upload.file, extension)
        provided_mapping = _read_mapping(mapping_json)
        mapping = validate_mapping(provided_mapping or suggest_mapping(columns), columns)
        stats, errors, error_count = _scan_dataset(rows, mapping)
        if stats["rows_valid"] == 0:
            raise HTTPException(status_code=422, detail={
                "message": "No valid rows to import",
                "validation": stats,
                "validation_errors": errors,
            })
    except DatasetValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    import_record = EnterpriseImport(
        organization_id=organization_id,
        uploaded_by=user.id,
        filename=filename,
        content_sha256=fingerprint,
        status="processing",
        rows_total=stats["rows_total"],
        rows_valid=stats["rows_valid"],
        rows_invalid=stats["rows_invalid"],
        rows_duplicate=stats["rows_duplicate"],
        detected_columns=columns,
        column_mapping=mapping,
        validation_errors=errors,
        validation_errors_truncated=error_count > len(errors),
    )
    db.add(import_record)
    db.commit()
    upload.file.seek(0)
    try:
        _, rows = source_rows(upload.file, extension)
        batch: list[dict[str, Any]] = []
        imported_hashes: set[str] = set()
        for row in rows:
            canonical, row_errors = canonical_record(row, mapping)
            if row_errors:
                continue
            row_hash = row_fingerprint(canonical)
            if row_hash in imported_hashes:
                continue
            imported_hashes.add(row_hash)
            batch.append(canonical)
            if len(batch) >= 1000:
                _insert_batch(db, batch, organization_id, import_record.id)
                batch.clear()
        if batch:
            _insert_batch(db, batch, organization_id, import_record.id)

        import_record.status = "completed"
        import_record.records_imported = stats["rows_valid"]
        import_record.completed_at = datetime.now(timezone.utc)
        db.add(AuditLog(
            organization_id=organization_id,
            actor_user_id=user.id,
            action="enterprise.dataset_imported",
            target_type="enterprise_import",
            target_id=str(import_record.id),
            details={
                "rows_total": stats["rows_total"],
                "rows_imported": stats["rows_valid"],
                "rows_invalid": stats["rows_invalid"],
                "rows_duplicate": stats["rows_duplicate"],
            },
        ))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Enterprise import %s failed", import_record.id)
        failed = db.get(EnterpriseImport, import_record.id)
        if failed:
            failed.status = "failed"
            db.commit()
        raise

    return {
        "id": str(import_record.id),
        "status": import_record.status,
        "filename": import_record.filename,
        "validation": stats,
        "records_imported": import_record.records_imported,
        "completed_at": import_record.completed_at,
    }


def _insert_batch(db: Session, records: list[dict[str, Any]], organization_id: uuid.UUID, import_id: uuid.UUID) -> None:
    asset_by_id: dict[str, dict[str, Any]] = {}
    exposures = []
    for record in records:
        values = _asset_values(record, organization_id, import_id)
        existing = asset_by_id.get(record["asset_id"])
        if existing:
            for key, value in values.items():
                if key in {"organization_id", "import_id", "asset_id"} or value is not None:
                    existing[key] = value
        else:
            asset_by_id[record["asset_id"]] = values
        exposures.append(_exposure_values(record, organization_id, import_id, row_fingerprint(record)))
    asset_values = list(asset_by_id.values())
    asset_insert = pg_insert(EnterpriseAsset).values(asset_values)
    asset_insert = asset_insert.on_conflict_do_update(
        index_elements=[EnterpriseAsset.organization_id, EnterpriseAsset.asset_id],
        set_={
            "import_id": asset_insert.excluded.import_id,
            "asset_name": case(
                (EnterpriseAsset.import_id != asset_insert.excluded.import_id, asset_insert.excluded.asset_name),
                else_=func.coalesce(asset_insert.excluded.asset_name, EnterpriseAsset.asset_name),
            ),
            "asset_type": case(
                (EnterpriseAsset.import_id != asset_insert.excluded.import_id, asset_insert.excluded.asset_type),
                else_=func.coalesce(asset_insert.excluded.asset_type, EnterpriseAsset.asset_type),
            ),
            "hostname": case(
                (EnterpriseAsset.import_id != asset_insert.excluded.import_id, asset_insert.excluded.hostname),
                else_=func.coalesce(asset_insert.excluded.hostname, EnterpriseAsset.hostname),
            ),
            "ip_address": case(
                (EnterpriseAsset.import_id != asset_insert.excluded.import_id, asset_insert.excluded.ip_address),
                else_=func.coalesce(asset_insert.excluded.ip_address, EnterpriseAsset.ip_address),
            ),
            "operating_system": case(
                (EnterpriseAsset.import_id != asset_insert.excluded.import_id, asset_insert.excluded.operating_system),
                else_=func.coalesce(asset_insert.excluded.operating_system, EnterpriseAsset.operating_system),
            ),
            "business_criticality": case(
                (EnterpriseAsset.import_id != asset_insert.excluded.import_id, asset_insert.excluded.business_criticality),
                else_=func.coalesce(asset_insert.excluded.business_criticality, EnterpriseAsset.business_criticality),
            ),
            "internet_exposed": case(
                (EnterpriseAsset.import_id != asset_insert.excluded.import_id, asset_insert.excluded.internet_exposed),
                else_=func.coalesce(asset_insert.excluded.internet_exposed, EnterpriseAsset.internet_exposed),
            ),
            "updated_at": func.now(),
        },
    )
    db.execute(asset_insert)
    db.execute(pg_insert(EnterpriseExposure), exposures)


@router.get("/imports")
def list_imports(
    membership: OrganizationMembership = Depends(get_current_membership),
    limit: int = Query(25, ge=1, le=100),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    filters = [EnterpriseImport.organization_id == membership.organization_id]
    total = db.scalar(select(func.count()).select_from(EnterpriseImport).where(*filters)) or 0
    records = db.scalars(
        select(EnterpriseImport).where(*filters)
        .order_by(desc(EnterpriseImport.created_at)).offset(offset).limit(limit)
    ).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [_import_dict(record) for record in records],
    }


def _import_dict(record: EnterpriseImport) -> dict[str, Any]:
    return {
        "id": str(record.id),
        "filename": record.filename,
        "status": record.status,
        "rows_total": record.rows_total,
        "rows_valid": record.rows_valid,
        "rows_invalid": record.rows_invalid,
        "rows_duplicate": record.rows_duplicate,
        "records_imported": record.records_imported,
        "created_at": record.created_at,
        "completed_at": record.completed_at,
        "detected_columns": record.detected_columns,
        "column_mapping": record.column_mapping,
        "validation_errors": record.validation_errors,
        "validation_errors_truncated": record.validation_errors_truncated,
    }


@router.get("/imports/{import_id}/errors.csv")
def import_error_report(
    import_id: uuid.UUID,
    membership: OrganizationMembership = Depends(get_current_membership),
    db: Session = Depends(get_db),
):
    record = db.scalar(select(EnterpriseImport).where(
        EnterpriseImport.id == import_id,
        EnterpriseImport.organization_id == membership.organization_id,
    ))
    if record is None:
        raise HTTPException(status_code=404, detail="Import not found")
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["row", "field", "message"])
    writer.writeheader()
    writer.writerows(record.validation_errors or [])
    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="import-{record.id}-errors.csv"'},
    )


@router.get("/summary")
def enterprise_summary(
    membership: OrganizationMembership = Depends(get_current_membership),
    db: Session = Depends(get_db),
):
    organization_id = membership.organization_id
    latest = _latest_import_id(db, organization_id)
    if latest is None:
        return {
            "latest_import_id": None,
            "total_assets": 0,
            "total_records": 0,
            "total_installed_software_records": 0,
            "affected_installations": 0,
            "reported_vulnerability_records": 0,
            "distinct_cves": 0,
            "unresolved_records": 0,
            "multi_critical_high_assets": 0,
            "internet_facing_assets": 0,
            "risk_tiers": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "status_counts": {},
            "top_assets": [],
            "top_cves": [],
            "top_software": [],
            "known_exploited_cves": [],
            "prioritized_remediation": [],
            "executive_summary": build_executive_summary([], [], [], []),
            "limitations": ["Upload findings to create an organization-scoped inventory."],
        }
    totals = db.execute(
        select(
            func.count(distinct(EnterpriseAsset.asset_id)),
            func.count(EnterpriseExposure.id),
            func.count(distinct(tuple_(
                EnterpriseExposure.asset_id,
                EnterpriseExposure.software_name,
                EnterpriseExposure.installed_version,
            ))).filter(EnterpriseExposure.software_name.is_not(None)),
            func.count(distinct(tuple_(
                EnterpriseExposure.asset_id,
                EnterpriseExposure.software_name,
                EnterpriseExposure.installed_version,
            ))).filter(
                EnterpriseExposure.software_name.is_not(None)
                & EnterpriseExposure.risk_score.is_not(None)
            ),
            func.count(EnterpriseExposure.id).filter(EnterpriseExposure.cve_id.is_not(None)),
            func.count(distinct(EnterpriseExposure.cve_id)),
            func.count(EnterpriseExposure.id).filter(
                EnterpriseExposure.applicability_status.in_(REVIEW_STATUSES)
            ),
        )
        .select_from(EnterpriseAsset)
        .outerjoin(
            EnterpriseExposure,
            (EnterpriseExposure.organization_id == EnterpriseAsset.organization_id)
            & (EnterpriseExposure.import_id == latest)
            & (EnterpriseExposure.asset_id == EnterpriseAsset.asset_id),
        )
        .where(EnterpriseAsset.organization_id == organization_id, EnterpriseAsset.import_id == latest)
    ).one()
    tier_counts = db.execute(
        select(EnterpriseExposure.risk_tier, func.count())
        .where(
            EnterpriseExposure.organization_id == organization_id,
            EnterpriseExposure.import_id == latest,
            EnterpriseExposure.risk_tier.is_not(None),
        )
        .group_by(EnterpriseExposure.risk_tier)
    ).all()
    status_counts = db.execute(
        select(EnterpriseExposure.applicability_status, func.count())
        .where(EnterpriseExposure.organization_id == organization_id, EnterpriseExposure.import_id == latest)
        .group_by(EnterpriseExposure.applicability_status)
    ).all()
    tier_map = {name: count for name, count in tier_counts}
    best_exposure = aliased(EnterpriseExposure)
    best_risk_factors = (
        select(best_exposure.risk_factors)
        .where(
            best_exposure.organization_id == organization_id,
            best_exposure.import_id == latest,
            best_exposure.cve_id == EnterpriseExposure.cve_id,
        )
        .order_by(best_exposure.risk_score.desc().nullslast())
        .limit(1)
        .correlate(EnterpriseExposure)
        .scalar_subquery()
    )
    best_missing_evidence = (
        select(best_exposure.missing_evidence)
        .where(
            best_exposure.organization_id == organization_id,
            best_exposure.import_id == latest,
            best_exposure.cve_id == EnterpriseExposure.cve_id,
        )
        .order_by(best_exposure.risk_score.desc().nullslast())
        .limit(1)
        .correlate(EnterpriseExposure)
        .scalar_subquery()
    )
    severity_rank = case(
        (EnterpriseExposure.severity == "critical", 4),
        (EnterpriseExposure.severity == "high", 3),
        (EnterpriseExposure.severity == "medium", 2),
        (EnterpriseExposure.severity == "low", 1),
        else_=0,
    )
    cve_statement = (
        select(
            EnterpriseExposure.cve_id.label("cve_id"),
            func.max(EnterpriseExposure.vulnerability_name).label("vulnerability_name"),
            func.max(EnterpriseExposure.cvss_score).label("cvss_score"),
            func.max(EnterpriseExposure.risk_score).label("risk_score"),
            func.max(severity_rank).label("severity_rank"),
            func.count(distinct(EnterpriseExposure.asset_id)).label("affected_assets"),
            func.count(distinct(tuple_(
                EnterpriseExposure.asset_id,
                EnterpriseExposure.software_name,
                EnterpriseExposure.installed_version,
            ))).filter(EnterpriseExposure.software_name.is_not(None)).label("reported_installations"),
            func.count(EnterpriseExposure.id).label("record_count"),
            func.count(EnterpriseExposure.id).filter(
                EnterpriseExposure.known_exploited.is_(True)
            ).label("known_exploited_records"),
            func.count(EnterpriseExposure.id).filter(
                EnterpriseExposure.known_exploited.is_(False)
            ).label("known_not_exploited_records"),
            func.count(distinct(EnterpriseExposure.asset_id)).filter(
                EnterpriseAsset.internet_exposed.is_(True)
            ).label("internet_exposed_assets"),
            func.count(distinct(EnterpriseExposure.asset_id)).filter(
                EnterpriseAsset.business_criticality.in_(("high", "critical"))
            ).label("criticality_assets"),
            func.array_agg(distinct(EnterpriseExposure.applicability_status)).label(
                "applicability_statuses"
            ),
            best_risk_factors.label("risk_factors"),
            best_missing_evidence.label("missing_evidence"),
        )
        .where(
            EnterpriseExposure.organization_id == organization_id,
            EnterpriseExposure.import_id == latest,
            EnterpriseExposure.cve_id.is_not(None),
        )
        .join(
            EnterpriseAsset,
            (EnterpriseAsset.organization_id == EnterpriseExposure.organization_id)
            & (EnterpriseAsset.import_id == latest)
            & (EnterpriseAsset.asset_id == EnterpriseExposure.asset_id),
        )
        .group_by(EnterpriseExposure.cve_id)
    )
    cve_rows = db.execute(
        cve_statement
        .order_by(desc(func.max(EnterpriseExposure.risk_score)).nullslast(),
                  desc(func.count(distinct(EnterpriseExposure.asset_id))),
                  EnterpriseExposure.cve_id)
        .limit(50)
    ).mappings().all()
    kev_rows = db.execute(
        cve_statement
        .having(func.count(EnterpriseExposure.id).filter(
            EnterpriseExposure.known_exploited.is_(True)
        ) > 0)
        .order_by(desc(func.max(EnterpriseExposure.risk_score)).nullslast(),
                  desc(func.count(distinct(EnterpriseExposure.asset_id))),
                  EnterpriseExposure.cve_id)
        .limit(10)
    ).mappings().all()

    def cve_record(row):
        kev_count = row["known_exploited_records"] or 0
        not_kev_count = row["known_not_exploited_records"] or 0
        risk_factors = row["risk_factors"] or {}
        score = row["risk_score"]
        statuses = sorted(row["applicability_statuses"] or [])
        return {
            "cve_id": row["cve_id"],
            "vulnerability_name": row["vulnerability_name"],
            "cvss_score": risk_factors.get("cvss", row["cvss_score"]),
            "reported_cvss_max": row["cvss_score"],
            "severity": {4: "critical", 3: "high", 2: "medium", 1: "low"}.get(
                row["severity_rank"]
            ),
            "risk_score": score,
            "risk_tier": risk_tier_for_score(score),
            "known_exploited": (
                True if kev_count else False
                if not_kev_count == row["record_count"] else None
            ),
            "known_exploited_records": kev_count,
            "affected_assets": row["affected_assets"],
            "reported_installations": row["reported_installations"],
            "internet_exposed_assets": row["internet_exposed_assets"],
            "criticality_assets": row["criticality_assets"],
            "risk_factors": risk_factors,
            "missing_evidence": row["missing_evidence"] or [],
            "applicability_status": statuses[0] if len(statuses) == 1 else "mixed_status",
            "applicability_statuses": statuses,
        }

    cve_records = [cve_record(row) for row in cve_rows]
    prioritized_remediation = prioritize_remediation(cve_records)[:20]
    prioritized_assets = prioritize_assets(
        _asset_rows(db, organization_id, latest, limit=50, offset=0, query=None)
    )
    software = db.execute(
        select(
            EnterpriseExposure.software_name,
            EnterpriseExposure.installed_version,
            func.count(distinct(EnterpriseExposure.asset_id)),
            func.count(distinct(EnterpriseExposure.cve_id)),
            func.max(EnterpriseExposure.risk_score),
        )
        .where(
            EnterpriseExposure.organization_id == organization_id,
            EnterpriseExposure.import_id == latest,
            EnterpriseExposure.software_name.is_not(None),
            EnterpriseExposure.cve_id.is_not(None),
        )
        .group_by(EnterpriseExposure.software_name, EnterpriseExposure.installed_version)
        .order_by(
            desc(func.count(distinct(EnterpriseExposure.asset_id))),
            desc(func.max(EnterpriseExposure.risk_score)).nullslast(),
            EnterpriseExposure.software_name,
        )
        .limit(10)
    ).all()
    high_risk_asset_count = db.scalar(
        select(func.count()).select_from(
            select(EnterpriseExposure.asset_id)
            .where(
                EnterpriseExposure.organization_id == organization_id,
                EnterpriseExposure.import_id == latest,
                EnterpriseExposure.risk_tier.in_(("critical", "high")),
            )
            .group_by(EnterpriseExposure.asset_id)
            .having(func.count(EnterpriseExposure.id) >= 2)
            .subquery()
        )
    ) or 0
    internet_facing_assets = db.scalar(
        select(func.count(distinct(EnterpriseAsset.asset_id)))
        .where(
            EnterpriseAsset.organization_id == organization_id,
            EnterpriseAsset.import_id == latest,
            EnterpriseAsset.internet_exposed.is_(True),
        )
    ) or 0
    executive_summary = build_executive_summary(
        prioritized_assets,
        cve_records,
        [
            {
                "software_name": name,
                "installed_version": version,
                "affected_assets": assets_count,
                "risk_score": risk,
            }
            for name, version, assets_count, _, risk in software
        ],
        prioritized_remediation,
    )
    return {
        "latest_import_id": str(latest),
        "total_assets": totals[0] or 0,
        "total_records": totals[1] or 0,
        "total_installed_software_records": totals[2] or 0,
        "affected_installations": totals[3] or 0,
        "reported_vulnerability_records": totals[4] or 0,
        "distinct_cves": totals[5] or 0,
        "unresolved_records": totals[6] or 0,
        "multi_critical_high_assets": high_risk_asset_count,
        "internet_facing_assets": internet_facing_assets,
        "risk_tiers": {name: tier_map.get(name, 0) for name in ("critical", "high", "medium", "low")},
        "status_counts": {name: count for name, count in status_counts},
        "top_assets": prioritized_assets[:10],
        "top_cves": [
            {
                "cve_id": record["cve_id"],
                "severity": record["severity"],
                "cvss_score": record["cvss_score"],
                "risk_score": record["risk_score"],
                "risk_tier": record["risk_tier"],
                "known_exploited": record["known_exploited"],
                "affected_assets": record["affected_assets"],
                "reported_installations": record["reported_installations"],
            }
            for record in cve_records[:10]
        ],
        "top_software": [
            {
                "software_name": name, "installed_version": version,
                "affected_assets": assets_count, "distinct_cves": cves_count,
                "risk_score": risk, "risk_tier": risk_tier_for_score(risk),
            }
            for name, version, assets_count, cves_count, risk in software
        ],
        "known_exploited_cves": [
            cve_record(row) for row in kev_rows
        ],
        "prioritized_remediation": prioritized_remediation,
        "executive_summary": executive_summary,
        "limitations": [
            "Uploaded findings are reported evidence; PRIORIS does not independently verify CVE applicability or product versions.",
            "Risk scores use supplied CVSS and only explicitly supplied KEV, criticality and network evidence.",
            "No missing CPE, KEV, CVSS or network evidence is inferred.",
            "Risk tiers count scored reported findings and are prioritization categories, not confirmed-exposure counts.",
            "The asset and CVE rankings use the highest stored PRIORIS score; product impact is grouped by supplied software name and version.",
            "Recommended actions are generic workflow guidance; confirm the vendor, affected version and applicable fix before remediation.",
        ],
    }


def _asset_rows(
    db: Session, organization_id: uuid.UUID, import_id: uuid.UUID,
    limit: int, offset: int, query: str | None,
):
    filters = [
        EnterpriseExposure.organization_id == organization_id,
        EnterpriseExposure.import_id == import_id,
    ]
    aggregate = (
        select(
            EnterpriseExposure.asset_id.label("asset_id"),
            func.count(distinct(EnterpriseExposure.cve_id)).label("distinct_cves"),
            func.max(EnterpriseExposure.risk_score).label("risk_score"),
            func.count(distinct(tuple_(
                EnterpriseExposure.asset_id,
                EnterpriseExposure.software_name,
                EnterpriseExposure.installed_version,
            ))).filter(
                EnterpriseExposure.software_name.is_not(None)
                & EnterpriseExposure.risk_score.is_not(None)
            ).label("affected_installations"),
            func.count(EnterpriseExposure.id).filter(
                EnterpriseExposure.risk_tier.in_(("critical", "high"))
            ).label("critical_high_findings"),
            func.count(EnterpriseExposure.id).filter(
                EnterpriseExposure.cve_id.is_not(None)
                & EnterpriseExposure.known_exploited.is_(True)
            ).label("known_exploited_findings"),
            func.count(EnterpriseExposure.id).filter(
                EnterpriseExposure.cve_id.is_not(None)
                & EnterpriseExposure.known_exploited.is_(None)
            ).label("known_exploited_unknown_findings"),
            func.count(EnterpriseExposure.id).filter(
                EnterpriseExposure.risk_score.is_(None)
                & or_(
                    EnterpriseExposure.cve_id.is_not(None),
                    EnterpriseExposure.applicability_status.in_(REVIEW_STATUSES),
                )
            ).label("unscored_findings"),
        )
        .where(*filters)
        .group_by(EnterpriseExposure.asset_id)
        .subquery()
    )
    top_cve = (
        select(EnterpriseExposure.cve_id)
        .where(
            EnterpriseExposure.organization_id == organization_id,
            EnterpriseExposure.import_id == import_id,
            EnterpriseExposure.asset_id == EnterpriseAsset.asset_id,
            EnterpriseExposure.cve_id.is_not(None),
        )
        .order_by(EnterpriseExposure.risk_score.desc().nullslast())
        .limit(1)
        .scalar_subquery()
    )
    top_tier = (
        select(EnterpriseExposure.risk_tier)
        .where(
            EnterpriseExposure.organization_id == organization_id,
            EnterpriseExposure.import_id == import_id,
            EnterpriseExposure.asset_id == EnterpriseAsset.asset_id,
            EnterpriseExposure.risk_tier.is_not(None),
        )
        .order_by(EnterpriseExposure.risk_score.desc().nullslast())
        .limit(1)
        .scalar_subquery()
    )
    rows = db.execute(
        select(
            EnterpriseAsset,
            aggregate.c.distinct_cves,
            aggregate.c.risk_score,
            aggregate.c.affected_installations,
            aggregate.c.critical_high_findings,
            aggregate.c.known_exploited_findings,
            aggregate.c.known_exploited_unknown_findings,
            aggregate.c.unscored_findings,
            top_cve,
            top_tier,
        )
        .outerjoin(
            aggregate,
            (aggregate.c.asset_id == EnterpriseAsset.asset_id),
        )
        .where(
            EnterpriseAsset.organization_id == organization_id,
            EnterpriseAsset.import_id == import_id,
            *([
                EnterpriseAsset.asset_id.ilike(f"%{query}%")
                | EnterpriseAsset.asset_name.ilike(f"%{query}%")
                | EnterpriseAsset.hostname.ilike(f"%{query}%")
            ] if query else []),
        )
        .order_by(
            aggregate.c.risk_score.desc().nullslast(),
            aggregate.c.critical_high_findings.desc(),
            EnterpriseAsset.internet_exposed.desc().nullslast(),
            EnterpriseAsset.asset_id,
        )
        .offset(offset)
        .limit(limit)
    ).all()
    return [
        {
            "asset_id": asset.asset_id,
            "asset_name": asset.asset_name,
            "asset_type": asset.asset_type,
            "hostname": asset.hostname,
            "ip_address": asset.ip_address,
            "operating_system": asset.operating_system,
            "business_criticality": asset.business_criticality,
            "internet_exposed": asset.internet_exposed,
            "affected_installations": affected_installations or 0,
            "critical_high_findings": critical_high_findings or 0,
            "known_exploited_findings": known_exploited_findings or 0,
            "known_exploited_unknown_findings": known_exploited_unknown_findings or 0,
            "unscored_findings": unscored_findings or 0,
            "distinct_cves": distinct_cves or 0,
            "max_risk_score": risk_score,
            "risk_tier": risk_tier,
            "top_cve": top_cve,
        }
        for (
            asset, distinct_cves, risk_score, affected_installations,
            critical_high_findings, known_exploited_findings,
            known_exploited_unknown_findings, unscored_findings, top_cve, risk_tier,
        ) in rows
    ]


@router.get("/assets")
def enterprise_assets(
    membership: OrganizationMembership = Depends(get_current_membership),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None, max_length=255),
    db: Session = Depends(get_db),
):
    latest = _latest_import_id(db, membership.organization_id)
    if latest is None:
        return {"total": 0, "offset": offset, "limit": limit, "items": []}
    filters = [
        EnterpriseAsset.organization_id == membership.organization_id,
        EnterpriseAsset.import_id == latest,
    ]
    if q:
        pattern = f"%{q}%"
        filters.append(
            EnterpriseAsset.asset_id.ilike(pattern)
            | EnterpriseAsset.asset_name.ilike(pattern)
            | EnterpriseAsset.hostname.ilike(pattern)
        )
    total = db.scalar(select(func.count()).select_from(EnterpriseAsset).where(*filters)) or 0
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": prioritize_assets(
            _asset_rows(db, membership.organization_id, latest, limit, offset, q)
        ),
    }


@router.get("/exposures")
def enterprise_exposures(
    membership: OrganizationMembership = Depends(get_current_membership),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    q: str | None = Query(None, max_length=255),
    applicability_status: str | None = Query(None, max_length=40),
    db: Session = Depends(get_db),
):
    latest = _latest_import_id(db, membership.organization_id)
    if latest is None:
        return {"total": 0, "offset": offset, "limit": limit, "items": []}
    filters = [
        EnterpriseExposure.organization_id == membership.organization_id,
        EnterpriseExposure.import_id == latest,
    ]
    if q:
        pattern = f"%{q}%"
        filters.append(
            EnterpriseExposure.asset_id.ilike(pattern)
            | EnterpriseExposure.software_name.ilike(pattern)
            | EnterpriseExposure.cve_id.ilike(pattern)
        )
    if applicability_status:
        filters.append(EnterpriseExposure.applicability_status == applicability_status)
    total = db.scalar(select(func.count()).select_from(EnterpriseExposure).where(*filters)) or 0
    rows = db.scalars(
        select(EnterpriseExposure).where(*filters)
        .order_by(EnterpriseExposure.risk_score.desc().nullslast(), EnterpriseExposure.id)
        .offset(offset).limit(limit)
    ).all()
    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "asset_id": row.asset_id,
                "software_name": row.software_name,
                "installed_version": row.installed_version,
                "cve_id": row.cve_id,
                "vulnerability_name": row.vulnerability_name,
                "severity": row.severity,
                "cvss_score": row.cvss_score,
                "known_exploited": row.known_exploited,
                "remediation_status": row.remediation_status,
                "first_detected": row.first_detected,
                "applicability_status": row.applicability_status,
                "risk_score": row.risk_score,
                "risk_tier": row.risk_tier,
                "risk_factors": row.risk_factors,
                "missing_evidence": row.missing_evidence,
                "source_evidence": row.source_evidence,
            }
            for row in rows
        ],
    }
