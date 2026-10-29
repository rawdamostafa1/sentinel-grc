"""Risk register models (W3). Fields follow Project Details section 13.2."""
from datetime import date, datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field

# "accept" and "accepted" are not allowed in create/update. Acceptance must go through
# /accept (it needs an owner, a reason and an expiry date).
SettableTreatment = Literal["mitigate", "transfer", "avoid"]
AnyTreatment = Literal["mitigate", "accept", "transfer", "avoid"]
SettableStatus = Literal["open", "in_treatment", "closed"]
AnyStatus = Literal["open", "in_treatment", "accepted", "closed"]
Band = Literal["Low", "Medium", "High", "Critical"]


class RiskCore(BaseModel):
    title: str = Field(min_length=1)
    description: str = ""
    asset_ids: list[str] = Field(min_length=1, description="Affected assets (the same field W2 reads)")
    threat: str = ""
    vulnerability: str = ""
    owner: str
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    existing_controls: list[str] = []
    residual_likelihood: Optional[int] = Field(default=None, ge=1, le=5)
    residual_impact: Optional[int] = Field(default=None, ge=1, le=5)
    due_date: Optional[date] = None
    review_date: Optional[date] = None
    auto_update: bool = Field(default=True, description="false = W4 never changes likelihood/impact")


class RiskCreate(RiskCore):
    treatment: SettableTreatment = "mitigate"
    status: SettableStatus = "open"


class RiskUpdate(BaseModel):
    """All fields are optional: send only what you want to change."""
    title: Optional[str] = Field(default=None, min_length=1)
    description: Optional[str] = None
    asset_ids: Optional[list[str]] = Field(default=None, min_length=1)
    threat: Optional[str] = None
    vulnerability: Optional[str] = None
    owner: Optional[str] = None
    likelihood: Optional[int] = Field(default=None, ge=1, le=5)
    impact: Optional[int] = Field(default=None, ge=1, le=5)
    existing_controls: Optional[list[str]] = None
    residual_likelihood: Optional[int] = Field(default=None, ge=1, le=5)
    residual_impact: Optional[int] = Field(default=None, ge=1, le=5)
    due_date: Optional[date] = None
    review_date: Optional[date] = None
    treatment: Optional[SettableTreatment] = None
    status: Optional[SettableStatus] = None
    auto_update: Optional[bool] = None


class AcceptanceRequest(BaseModel):
    accepted_by: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    expires_at: datetime


class Acceptance(BaseModel):
    accepted_by: str
    reason: str
    expires_at: datetime
    accepted_at: datetime


class Risk(RiskCore):
    risk_id: str
    treatment: AnyTreatment
    status: AnyStatus
    inherent_score: int
    inherent_band: Band
    residual_score: int
    residual_band: Band
    acceptance: Optional[Acceptance] = None
    acceptance_expired: bool = False
    base_likelihood: Optional[int] = None
    live_factors: Optional[dict] = None
    last_recalculated: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime