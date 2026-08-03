from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class Evidence(BaseModel):
    """A single piece of normalized evidence from any provider."""

    provider: str = Field(description="Name of the provider that produced this evidence.")
    type: str = Field(description="Type of evidence, e.g. event, metric, log, resource.")
    resource: str = Field(description="Resource identifier, e.g. Pod/sre-lab/nginx.")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the evidence was collected.",
    )
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score.")
    severity: str | None = Field(default=None, description="Optional severity label.")
    payload: Any = Field(description="Raw structured evidence payload.")

    class Config:
        arbitrary_types_allowed = True
