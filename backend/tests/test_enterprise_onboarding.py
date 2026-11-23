import io
import json
import sys
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from sqlalchemy.dialects import postgresql

from app.database import get_db
from app.dependencies import get_current_membership, get_current_user
from app.enterprise import _insert_batch
from app.enterprise_data import (
    DatasetValidationError,
    canonical_record,
    build_executive_summary,
    evaluate_risk,
    prioritize_assets,
    prioritize_remediation,
    source_rows,
    suggest_mapping,
    validate_mapping,
)
from app.main import app
from app.organizations import InvitationRequest
from app.security import create_access_token, decode_access_token_payload

PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.scoring import score_components
from src.score_risks import score_components as existing_score_components


def test_column_mapping_detects_common_aliases_and_can_be_corrected():
    columns = ["Device ID", "Host Name", "Product Name", "Software Version", "CVE", "Base Score"]
    suggested = suggest_mapping(columns)

    assert suggested["asset_id"] == "Device ID"
    assert suggested["hostname"] == "Host Name"
    assert suggested["software_name"] == "Product Name"
    assert suggested["installed_version"] == "Software Version"
    assert suggested["cve_id"] == "CVE"
    assert suggested["cvss_score"] == "Base Score"

    corrected = validate_mapping({"asset_id": "Host Name", "hostname": "Device ID"}, columns)
    assert corrected["asset_id"] == "Host Name"
    assert corrected["hostname"] == "Device ID"


def test_column_mapping_rejects_reused_or_missing_asset_columns():
    with pytest.raises(DatasetValidationError, match="only one"):
        validate_mapping({"asset_id": "ID", "hostname": "ID"}, ["ID"])
    with pytest.raises(DatasetValidationError, match="required asset_id"):
        validate_mapping({"hostname": "Host"}, ["Host"])


def test_csv_records_normalize_and_validate_inputs():
    source = io.BytesIO(
        b"asset_id,product,cve,cvss,kev,business_criticality,internet_exposed\n"
        b"host-01,OpenSSL,CVE-2024-1234,8.2,true,critical,yes\n"
    )
    columns, rows = source_rows(source, ".csv")
    mapping = validate_mapping(suggest_mapping(columns), columns)
    records = list(rows)
    record, errors = canonical_record(records[0], mapping)

    assert not errors
    assert record["asset_id"] == "host-01"
    assert record["software_name"] == "OpenSSL"
    assert record["cve_id"] == "CVE-2024-1234"
    assert record["cvss_score"] == 8.2
    assert record["known_exploited"] is True
    assert record["business_criticality"] == "critical"
    assert record["internet_exposed"] is True


@pytest.mark.parametrize("content", [
    b'[{"asset_id":"host-01","cve_id":"CVE-2024-1234"}]',
    b' \r\n [{"asset_id":"host-01","cve_id":"CVE-2024-1234"}]',
    b'{"records":[{"asset_id":"host-01","cve_id":"CVE-2024-1234"}]}',
    b'{"asset_id":"host-01","cve_id":"CVE-2024-1234"}',
])
def test_json_arrays_wrapped_records_and_single_record_are_supported(content):
    columns, rows = source_rows(io.BytesIO(content), ".json")
    assert columns == ["asset_id", "cve_id"]
    assert list(rows) == [{"asset_id": "host-01", "cve_id": "CVE-2024-1234"}]


def test_malformed_json_is_rejected_with_actionable_error():
    with pytest.raises(DatasetValidationError, match="JSON"):
        source_rows(io.BytesIO(b'{"records":['), ".json")


def test_csv_rejects_duplicate_headers_and_extra_unmapped_cells():
    with pytest.raises(DatasetValidationError, match="unique"):
        source_rows(io.BytesIO(b"asset_id,Asset ID\nhost-01,other\n"), ".csv")
    _, rows = source_rows(io.BytesIO(b"asset_id,software_name\nhost-01,Product,unexpected\n"), ".csv")
    with pytest.raises(DatasetValidationError, match="more fields"):
        list(rows)


def test_bad_cve_cvss_and_severity_are_rejected_as_row_errors():
    mapping = suggest_mapping(["asset_id", "cve_id", "cvss_score", "severity"])
    _, errors = canonical_record(
        {"asset_id": "host-01", "cve_id": "not-a-cve", "cvss_score": 11, "severity": "urgent"},
        mapping,
    )
    assert {error["field"] for error in errors} == {"cve_id", "cvss_score", "severity"}


def test_risk_scores_use_existing_factors_and_keep_missing_cases_unscored():
    scored = evaluate_risk({
        "cve_id": "CVE-2024-1234",
        "cvss_score": 9.8,
        "known_exploited": True,
        "business_criticality": "critical",
        "internet_exposed": True,
        "software_name": "OpenSSL",
    })
    assert scored["risk_score"] == 16.8
    assert scored["risk_tier"] == "critical"
    assert scored["applicability_status"] == "reported_unverified"
    assert "independent_applicability_verification" in scored["missing_evidence"]

    review = evaluate_risk({"cve_id": "CVE-2024-1234", "cvss_score": None})
    assert review["applicability_status"] == "pending_manual_review"
    assert review["risk_score"] is None

    unresolved = evaluate_risk({"software_name": "Unknown product", "cve_id": None})
    assert unresolved["applicability_status"] == "unresolved_product"
    assert unresolved["risk_score"] is None

    unsupported = evaluate_risk({
        "cve_id": "CVE-2024-1234",
        "cvss_score": 9.0,
        "applicability_status": "unsupported_matching",
    })
    assert unsupported["applicability_status"] == "unsupported_matching"
    assert unsupported["risk_score"] is None


@pytest.mark.parametrize(
    ("field", "value", "missing_evidence"),
    [
        ("known_exploited", None, "known_exploited"),
        ("business_criticality", None, "business_criticality"),
        ("internet_exposed", False, "exposure_class"),
        ("internet_exposed", None, "exposure_class"),
    ],
)
def test_enterprise_scoring_requires_all_existing_engine_evidence(field, value, missing_evidence):
    record = {
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.0,
        "known_exploited": False,
        "business_criticality": "high",
        "internet_exposed": True,
    }
    record[field] = value
    result = evaluate_risk(record)

    assert result["risk_score"] is None
    assert result["risk_tier"] is None
    assert missing_evidence in result["missing_evidence"]


def test_false_internet_exposure_does_not_infer_internal_or_restricted():
    record = {
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.0,
        "known_exploited": False,
        "business_criticality": "high",
        "internet_exposed": False,
    }
    enterprise = evaluate_risk(record)
    existing = existing_score_components(8.0, False, "high", None)

    assert enterprise["risk_score"] == existing["score"] is None
    assert "exposure_class" in enterprise["missing_evidence"]


def test_explicit_exposure_class_scores_identically_to_existing_engine():
    assert score_components is existing_score_components
    record = {
        "cve_id": "CVE-2024-1234",
        "cvss_score": 9.8,
        "known_exploited": True,
        "business_criticality": "critical",
        "internet_exposed": True,
        "exposure": "internet-facing",
    }
    enterprise = evaluate_risk(record)
    existing = existing_score_components(9.8, True, "critical", "internet-facing")

    assert enterprise["risk_score"] == existing["score"] == 16.8
    assert enterprise["risk_tier"] == existing["tier"] == "critical"
    assert enterprise["risk_factors"] == {
        "cvss": existing["components"]["severity"],
        "known_exploited": existing["components"]["kev"],
        "business_criticality": existing["components"]["criticality"],
        "network_exposure": existing["components"]["exposure"],
    }
    assert "independent_applicability_verification" in enterprise["missing_evidence"]


@pytest.mark.parametrize(
    ("exposure", "internet_exposed"),
    [("internal", False), ("restricted", False)],
)
def test_non_internet_exposure_requires_explicit_class_and_matches_engine(exposure, internet_exposed):
    record = {
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.0,
        "known_exploited": False,
        "business_criticality": "medium",
        "internet_exposed": internet_exposed,
        "exposure": exposure,
    }
    enterprise = evaluate_risk(record)
    existing = existing_score_components(8.0, False, "medium", exposure)

    assert enterprise["risk_score"] == existing["score"]
    assert enterprise["risk_tier"] == existing["tier"]


@pytest.mark.parametrize(
    ("date_value", "valid"),
    [
        ("2026-01-15-not-a-date", False),
        ("2026-02-30", False),
        ("2026-01-15", True),
        ("2026-01-15T12:30:45Z", True),
    ],
)
def test_first_detected_requires_a_complete_supported_iso_date(date_value, valid):
    mapping = suggest_mapping(["asset_id", "first_detected"])
    result, errors = canonical_record(
        {"asset_id": "host-01", "first_detected": date_value},
        mapping,
    )
    date_errors = [error for error in errors if error["field"] == "first_detected"]

    assert bool(date_errors) is not valid
    assert (result["first_detected"] is not None) is valid
    if not valid:
        assert "complete ISO date" in date_errors[0]["message"]


@pytest.mark.parametrize(
    ("cve_id", "expected_status", "expected_missing"),
    [
        (None, "pending_manual_review", "cve_id"),
        ("not-a-cve", "pending_manual_review", "valid_cve_identifier"),
    ],
)
def test_source_confirmation_without_valid_cve_is_not_confirmed(cve_id, expected_status, expected_missing):
    result = evaluate_risk({
        "cve_id": cve_id,
        "software_name": "Example product",
        "applicability_status": "confirmed_match",
    })

    assert result["applicability_status"] == expected_status
    assert result["risk_score"] is None
    assert expected_missing in result["missing_evidence"]
    assert "source_confirmation_not_independently_verified" in result["missing_evidence"]


def test_source_confirmed_match_with_valid_cve_remains_reported_unverified():
    result = evaluate_risk({
        "cve_id": "CVE-2024-1234",
        "cvss_score": 8.0,
        "known_exploited": True,
        "business_criticality": "critical",
        "internet_exposed": True,
        "applicability_status": "confirmed_match",
    })

    assert result["applicability_status"] == "reported_unverified"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("internet-facing", "internet-facing"),
        ("INTERNAL", "internal"),
        ("restricted", "restricted"),
    ],
)
def test_explicit_exposure_class_is_normalized(value, expected):
    mapping = suggest_mapping(["asset_id", "exposure"])
    record, errors = canonical_record(
        {"asset_id": "host-01", "exposure": value},
        mapping,
    )
    assert not errors
    assert record["exposure"] == expected


def test_remediation_ranking_reuses_scores_and_preserves_missing_evidence():
    rows = prioritize_remediation([
        {
            "cve_id": "CVE-2024-1000",
            "risk_score": 8.0,
            "cvss_score": 7.0,
            "known_exploited": None,
            "affected_assets": 9,
            "risk_factors": {"cvss": 7.0, "network_exposure": 1.0},
            "missing_evidence": ["known_exploited", "independent_applicability_verification"],
        },
        {
            "cve_id": "CVE-2024-2000",
            "risk_score": 15.0,
            "cvss_score": 9.0,
            "known_exploited": False,
            "affected_assets": 2,
            "risk_factors": {"cvss": 9.0, "business_criticality": 3.0},
            "missing_evidence": ["internet_exposed"],
        },
        {
            "cve_id": "CVE-2024-3000",
            "risk_score": 4.0,
            "cvss_score": None,
            "known_exploited": True,
            "affected_assets": 1,
            "risk_factors": {},
            "missing_evidence": ["cvss_score", "independent_applicability_verification"],
        },
        {
            "cve_id": "CVE-2024-4000",
            "risk_score": None,
            "cvss_score": None,
            "known_exploited": True,
            "affected_assets": 4,
            "risk_factors": {},
            "missing_evidence": ["cvss_score", "known_exploited"],
            "applicability_status": "unsupported_matching",
        },
    ])

    assert [row["cve_id"] for row in rows] == [
        "CVE-2024-2000", "CVE-2024-3000", "CVE-2024-1000", "CVE-2024-4000",
    ]
    assert rows[0]["suggested_priority"] == "P1"
    assert rows[0]["risk_tier"] == "critical"
    assert rows[2]["suggested_priority"] == "P3"
    assert rows[1]["suggested_priority"] == "P1"
    assert rows[1]["risk_tier"] == "low"
    assert rows[3]["suggested_priority"] == "Review"
    assert rows[3]["applicability_status"] == "unsupported_matching"
    assert "known_exploited" in rows[2]["missing_evidence"]
    assert rows[2]["applicability_status"] == "reported_unverified"


def test_asset_ranking_explains_multi_finding_kev_and_internet_evidence():
    assets = prioritize_assets([
        {
            "asset_id": "asset-low",
            "max_risk_score": 5.0,
            "critical_high_findings": 0,
            "known_exploited_findings": 0,
            "internet_exposed": False,
        },
        {
            "asset_id": "asset-priority",
            "max_risk_score": 15.0,
            "critical_high_findings": 3,
            "known_exploited_findings": 1,
            "internet_exposed": True,
            "business_criticality": "critical",
        },
    ])

    assert assets[0]["asset_id"] == "asset-priority"
    assert "3 reported Critical/High scored finding(s)" in assets[0]["risk_reasons"]
    assert "1 finding(s) with explicitly reported KEV status" in assets[0]["risk_reasons"]
    assert "Asset was marked internet-exposed in the latest inventory" in assets[0]["risk_reasons"]


def test_executive_summary_uses_supplied_rankings_without_fabrication():
    summary = build_executive_summary(
        [{"asset_id": "asset-1", "asset_name": "Gateway", "max_risk_score": 15.0, "risk_reasons": ["Internet exposed"]}],
        [{"cve_id": "CVE-2024-1234", "affected_assets": 2}],
        [{"software_name": "Example", "installed_version": "1.2", "affected_assets": 2}],
        [{"cve_id": "CVE-2024-1234", "suggested_priority": "P1", "recommended_action": "Validate and remediate."}],
    )

    assert "CVE-2024-1234" in summary["biggest_security_problem"]
    assert summary["immediate_attention"][0]["asset_id"] == "asset-1"
    assert "Example 1.2" in summary["greatest_software_exposure"]
    assert "Validate and remediate." in summary["fix_first"]
    empty = build_executive_summary([], [], [], [])
    assert "No CVE identifiers" in empty["biggest_security_problem"]


def test_access_token_has_revocable_identifier(monkeypatch):
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "auth_secret_key", "test-secret-key-with-at-least-32-characters")
    token, _ = create_access_token("00000000-0000-0000-0000-000000000001")
    payload = decode_access_token_payload(token)
    assert payload
    assert payload["sub"] == "00000000-0000-0000-0000-000000000001"
    assert len(payload["jti"]) == 32


def test_revoked_access_tokens_are_rejected(monkeypatch):
    from app.config import get_settings

    settings = get_settings()
    monkeypatch.setattr(settings, "auth_secret_key", "test-secret-key-with-at-least-32-characters")
    user_id = uuid.uuid4()
    token, _ = create_access_token(str(user_id))
    user = SimpleNamespace(id=user_id, is_active=True)

    class RevokedDb:
        def scalar(self, statement):
            return user

        def get(self, model, token_id):
            return object()

    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    with pytest.raises(HTTPException) as error:
        get_current_user(credentials, RevokedDb())
    assert error.value.status_code == 401
    assert "revoked" in error.value.detail


def test_postgres_import_batches_include_tenant_keys_and_asset_conflict_update():
    organization_id = uuid.uuid4()
    import_id = uuid.uuid4()
    statements = []
    bound_values = []

    class CaptureDb:
        def execute(self, statement, params=None):
            if params is not None:
                statement = statement.values(params)
            compiled = statement.compile(dialect=postgresql.dialect())
            statements.append(str(compiled))
            bound_values.extend(compiled.params.values())

    _insert_batch(
        CaptureDb(),
        [{
            "asset_id": "host-01",
            "asset_name": "Application",
            "asset_type": "server",
            "hostname": "app-01",
            "ip_address": None,
            "operating_system": "Linux",
            "business_criticality": "high",
            "internet_exposed": True,
            "software_name": "Example Product",
            "installed_version": "1.2.3",
            "cve_id": "CVE-2024-1234",
            "vulnerability_name": None,
            "severity": "high",
            "cvss_score": 8.0,
            "known_exploited": None,
            "remediation_status": None,
            "first_detected": None,
            "applicability_status": None,
            "match_evidence": None,
        }],
        organization_id,
        import_id,
    )
    assert len(statements) == 2
    assert "ON CONFLICT" in statements[0]
    assert "enterprise_assets" in statements[0]
    assert "enterprise_exposures" in statements[1]
    assert organization_id in bound_values


def test_invitation_supports_all_server_enforced_roles():
    for role in ("admin", "analyst", "viewer"):
        assert InvitationRequest(email="person@example.com", role=role).role == role


def test_preview_validates_upload_and_reports_duplicates_and_invalid_rows():
    organization_id = uuid.uuid4()
    app.dependency_overrides[get_current_membership] = lambda: SimpleNamespace(
        organization_id=organization_id, role="analyst"
    )
    data = (
        "asset_id,software_name,cve_id,severity,cvss_score\n"
        "host-01,OpenSSL,CVE-2024-1234,High,8.1\n"
        "host-01,OpenSSL,CVE-2024-1234,High,8.1\n"
        "host-02,Other,not-a-cve,Urgent,12\n"
    )
    try:
        response = TestClient(app).post(
            "/api/v1/enterprise/imports/preview",
            files={"upload": ("findings.csv", data, "text/csv")},
            data={"mapping_json": "{}"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    result = response.json()
    assert result["validation"] == {
        "rows_total": 3,
        "rows_valid": 1,
        "rows_invalid": 1,
        "rows_duplicate": 1,
    }
    assert {error["field"] for error in result["validation_errors"]} == {
        "record", "cve_id", "severity", "cvss_score",
    }


@pytest.mark.parametrize(
    ("filename", "content_type"),
    [
        ("enterprise_sample.csv", "text/csv"),
        ("enterprise_sample.json", "application/json"),
    ],
)
def test_synthetic_company_demo_files_pass_preview_validation(filename, content_type):
    sample_path = Path(__file__).parents[1] / "examples" / filename
    app.dependency_overrides[get_current_membership] = lambda: SimpleNamespace(
        organization_id=uuid.uuid4(), role="analyst"
    )
    try:
        response = TestClient(app).post(
            "/api/v1/enterprise/imports/preview",
            files={"upload": (filename, sample_path.read_bytes(), content_type)},
            data={"mapping_json": "{}"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200, response.text
    result = response.json()
    assert result["validation"] == {
        "rows_total": 12,
        "rows_valid": 12,
        "rows_invalid": 0,
        "rows_duplicate": 0,
    }
    assert result["mapping_errors"] == []


def test_import_endpoint_persists_only_valid_unique_rows_in_tenant_batches():
    organization_id = uuid.uuid4()
    user_id = uuid.uuid4()
    statements = []
    bound_values = []
    added = []

    class ImportDb:
        def scalar(self, statement):
            return None

        def add(self, item):
            if hasattr(item, "id") and item.id is None:
                item.id = uuid.uuid4()
            added.append(item)

        def execute(self, statement, params=None):
            if params is not None:
                statement = statement.values(params)
            compiled = statement.compile(dialect=postgresql.dialect())
            statements.append(str(compiled))
            bound_values.extend(compiled.params.values())

        def get(self, model, item_id):
            return next((item for item in added if isinstance(item, model) and item.id == item_id), None)

        def commit(self):
            return None

        def rollback(self):
            return None

    db = ImportDb()

    def override_db():
        yield db

    app.dependency_overrides[get_current_membership] = lambda: SimpleNamespace(
        organization_id=organization_id, role="analyst"
    )
    app.dependency_overrides[get_current_user] = lambda: SimpleNamespace(id=user_id)
    app.dependency_overrides[get_db] = override_db
    data = (
        "asset_id,software_name,cve_id,cvss_score,severity,applicability_status,match_evidence\n"
        "host-01,Example Product,CVE-2024-1234,8.0,High,confirmed_match,scanner supplied match\n"
        "host-01,Example Product,CVE-2024-1234,8.0,High,confirmed_match,scanner supplied match\n"
        "host-02,Other Product,,9.0,Urgent,,\n"
        "host-03,Unknown Product,,9.0,High,unsupported_matching,no adapter\n"
    )
    try:
        response = TestClient(app).post(
            "/api/v1/enterprise/imports",
            files={"upload": ("findings.csv", data, "text/csv")},
            data={"mapping_json": "{}"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201, response.text
    result = response.json()
    assert result["validation"] == {
        "rows_total": 4,
        "rows_valid": 2,
        "rows_invalid": 1,
        "rows_duplicate": 1,
    }
    assert result["records_imported"] == 2
    assert result["status"] == "completed"
    assert len(statements) == 2
    assert organization_id in bound_values
    import_record = next(item for item in added if item.__class__.__name__ == "EnterpriseImport")
    assert import_record.validation_errors_truncated is False
    assert {error["field"] for error in import_record.validation_errors} == {"record", "severity"}


def test_viewer_cannot_preview_or_import_company_data():
    app.dependency_overrides[get_current_membership] = lambda: SimpleNamespace(
        organization_id=uuid.uuid4(), role="viewer"
    )
    try:
        response = TestClient(app).post(
            "/api/v1/enterprise/imports/preview",
            files={"upload": ("inventory.csv", "asset_id\nhost-01\n", "text/csv")},
            data={"mapping_json": "{}"},
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 403


def test_enterprise_summary_query_is_scoped_to_selected_organization():
    organization_id = uuid.uuid4()
    captured = {}

    class ReadOnlyDb:
        def scalar(self, statement):
            captured["statement"] = statement
            return None

    def override_db():
        yield ReadOnlyDb()

    app.dependency_overrides[get_current_membership] = lambda: SimpleNamespace(
        organization_id=organization_id, role="viewer"
    )
    app.dependency_overrides[get_db] = override_db
    try:
        response = TestClient(app).get("/api/v1/enterprise/summary")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["total_assets"] == 0
    statement = captured["statement"].compile(dialect=postgresql.dialect())
    assert "enterprise_imports.organization_id" in str(statement)
    assert organization_id in statement.params.values()


def test_prioritization_summary_queries_compile_for_latest_tenant_import():
    organization_id = uuid.uuid4()
    import_id = uuid.uuid4()
    captured_queries = []

    class Result:
        def one(self):
            return (0, 0, 0, 0, 0, 0, 0)

        def all(self):
            return []

        def mappings(self):
            return self

    class ReadOnlyDb:
        scalar_calls = 0

        def scalar(self, statement):
            self.scalar_calls += 1
            return import_id if self.scalar_calls == 1 else 0

        def execute(self, statement):
            compiled = statement.compile(dialect=postgresql.dialect())
            captured_queries.append((str(compiled), compiled.params))
            return Result()

    def override_db():
        yield ReadOnlyDb()

    app.dependency_overrides[get_current_membership] = lambda: SimpleNamespace(
        organization_id=organization_id, role="viewer"
    )
    app.dependency_overrides[get_db] = override_db
    try:
        response = TestClient(app).get("/api/v1/enterprise/summary")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    result = response.json()
    assert result["latest_import_id"] == str(import_id)
    assert result["prioritized_remediation"] == []
    assert result["known_exploited_cves"] == []
    assert result["multi_critical_high_assets"] == 0
    assert captured_queries
    assert all(
        "enterprise_exposures.organization_id" in query
        and "enterprise_exposures.import_id" in query
        for query, _ in captured_queries
        if "enterprise_exposures" in query
    )


def test_importation_does_not_replace_synthetic_dashboard_routes():
    client = TestClient(app)
    paths = app.openapi()["paths"]
    assert "/api/v1/dashboard/summary" in paths
    assert "/api/v1/exposures/confirmed" in paths
    assert "/api/v1/enterprise/imports/preview" in paths
    assert "/api/v1/enterprise/summary" in paths
