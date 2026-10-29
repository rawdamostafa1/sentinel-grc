"""Asset model. This is the "contract" the rest of the team depends on."""
from datetime import datetime, timezone
from typing import Literal, Optional
from pydantic import BaseModel, Field

AssetType = Literal[
    "application", "service", "database", "network",
    "datastore", "third-party", "soar-component",
]
DataClass = Literal["public", "internal", "confidential"]
Exposure = Literal["internet-facing", "internal", "external"]
Environment = Literal["production", "lab"]
Status = Literal["active", "retired"]


class AssetBase(BaseModel):
    name: str = Field(min_length=1)
    type: AssetType
    owner: str
    business_service: str
    criticality: int = Field(ge=1, le=5, description="1 = least important, 5 = most critical")
    data_classification: DataClass
    exposure: Exposure
    environment: Environment = "lab"
    hostnames: list[str] = []      # service names in docker compose
    ip_addresses: list[str] = []   # used for lookup by IP
    description: str = ""
    status: Status = "active"


class AssetCreate(AssetBase):
    asset_id: Optional[str] = None  # if left empty, it is generated automatically


class AssetUpdate(BaseModel):
    """All fields are optional; send only the ones you want to change."""
    name: Optional[str] = None
    type: Optional[AssetType] = None
    owner: Optional[str] = None
    business_service: Optional[str] = None
    criticality: Optional[int] = Field(default=None, ge=1, le=5)
    data_classification: Optional[DataClass] = None
    exposure: Optional[Exposure] = None
    environment: Optional[Environment] = None
    hostnames: Optional[list[str]] = None
    ip_addresses: Optional[list[str]] = None
    description: Optional[str] = None
    status: Optional[Status] = None


class Asset(AssetBase):
    asset_id: str
    last_seen: Optional[datetime] = None


def now_utc() -> datetime:
    return datetime.now(timezone.utc)