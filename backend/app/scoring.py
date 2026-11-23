"""Canonical PRIORIS risk-scoring configuration and component calculation."""
from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class RiskScoringConfig:
    kev_bonus: float = 2.0
    criticality_step: float = 1.0
    internet_facing_bonus: float = 2.0
    internal_bonus: float = 1.0
    medium_threshold: float = 6.0
    high_threshold: float = 10.0
    critical_threshold: float = 14.0

    def validate(self) -> None:
        values = asdict(self)
        for name, value in values.items():
            if not math.isfinite(value):
                raise ValueError(f"{name} must be a finite number")
            if value < 0:
                raise ValueError(f"{name} must not be negative")
        if not (
            self.medium_threshold
            <= self.high_threshold
            <= self.critical_threshold
        ):
            raise ValueError(
                "Risk thresholds must satisfy medium <= high <= critical"
            )
        if self.critical_threshold > self.maximum_score:
            raise ValueError("Critical threshold must not exceed the maximum possible score")

    @property
    def maximum_score(self) -> float:
        return (
            10.0
            + self.kev_bonus
            + 3.0 * self.criticality_step
            + max(self.internet_facing_bonus, self.internal_bonus)
        )


def risk_tier(score: float, config: RiskScoringConfig) -> str:
    if not math.isfinite(score) or score < 0 or score > config.maximum_score:
        raise ValueError(f"Risk score must be between 0 and {config.maximum_score}")
    if score >= config.critical_threshold:
        return "critical"
    if score >= config.high_threshold:
        return "high"
    if score >= config.medium_threshold:
        return "medium"
    return "low"


def score_components(
    cvss_score: Any,
    in_kev: Any,
    criticality: Any,
    exposure: Any,
    config: RiskScoringConfig = RiskScoringConfig(),
) -> dict[str, Any]:
    config.validate()
    missing: list[str] = []
    try:
        severity = float(cvss_score)
    except (TypeError, ValueError):
        severity = math.nan
    if not math.isfinite(severity) or not 0.0 <= severity <= 10.0:
        missing.append("valid_cvss_score_0_to_10")

    if in_kev is True or in_kev == "True":
        kev_member = True
    elif in_kev is False or in_kev == "False":
        kev_member = False
    else:
        kev_member = None
        missing.append("explicit_cisa_kev_membership")

    criticality_levels = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    criticality_value = (
        str(criticality).strip().casefold()
        if isinstance(criticality, str)
        else ""
    )
    if criticality_value not in criticality_levels:
        missing.append("recognized_asset_criticality")

    exposure_value = (
        str(exposure).strip().casefold()
        if isinstance(exposure, str)
        else ""
    )
    if exposure_value not in {"internet-facing", "internal", "restricted"}:
        missing.append("recognized_asset_exposure")

    if missing:
        return {
            "score": None,
            "tier": None,
            "missing_evidence": missing,
        }

    severity_component = severity
    kev_component = config.kev_bonus if kev_member else 0.0
    criticality_component = (
        criticality_levels[criticality_value] * config.criticality_step
    )
    exposure_component = {
        "internet-facing": config.internet_facing_bonus,
        "internal": config.internal_bonus,
        "restricted": 0.0,
    }[exposure_value]
    score = round(
        severity_component
        + kev_component
        + criticality_component
        + exposure_component,
        4,
    )
    return {
        "score": score,
        "tier": risk_tier(score, config),
        "missing_evidence": [],
        "components": {
            "severity": round(severity_component, 4),
            "kev": round(kev_component, 4),
            "criticality": round(criticality_component, 4),
            "exposure": round(exposure_component, 4),
        },
    }
