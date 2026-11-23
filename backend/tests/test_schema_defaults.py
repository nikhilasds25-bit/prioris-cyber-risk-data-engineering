from app.models import EnterpriseExposure, EnterpriseImport, Organization, OrganizationMembership, User


def test_model_server_defaults_match_migration_defined_defaults():
    expected_defaults = {
        (Organization, "is_active"): "true",
        (User, "is_active"): "true",
        (OrganizationMembership, "role"): "viewer",
        (OrganizationMembership, "is_active"): "true",
        (EnterpriseImport, "rows_total"): "0",
        (EnterpriseImport, "rows_valid"): "0",
        (EnterpriseImport, "rows_invalid"): "0",
        (EnterpriseImport, "rows_duplicate"): "0",
        (EnterpriseImport, "records_imported"): "0",
        (EnterpriseImport, "detected_columns"): "[]",
        (EnterpriseImport, "column_mapping"): "{}",
        (EnterpriseImport, "validation_errors"): "[]",
        (EnterpriseImport, "validation_errors_truncated"): "false",
        (EnterpriseExposure, "risk_factors"): "{}",
        (EnterpriseExposure, "missing_evidence"): "[]",
        (EnterpriseExposure, "source_evidence"): "{}",
    }

    for (model, field), expected in expected_defaults.items():
        column = model.__table__.c[field]
        assert column.server_default is not None, f"{model.__name__}.{field} lacks a server default"
        assert str(column.server_default.arg).strip("'") == expected


def test_audit_details_remains_required_for_non_orm_inserts():
    from app.models import AuditLog

    column = AuditLog.__table__.c.details
    assert column.default is not None
    assert column.server_default is None
    assert not column.nullable
