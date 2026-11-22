from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field


class ExposurePage(BaseModel):
    model_config = ConfigDict(extra="forbid")
    view: Literal["confirmed", "review"]
    total: int
    offset: int
    limit: int
    items: list[dict[str, Any]]


class HealthStatus(BaseModel):
    status: str
    service: str
