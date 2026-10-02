from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class Decision(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"


class Finding(BaseModel):
    detector: str
    attack_type: str
    severity: int = Field(ge=1, le=100)
    confidence: float = Field(ge=0, le=1)
    evidence: str
    explanation: str


class ScanRequest(BaseModel):
    content: str
    source_type: str = "user_message"
    external_content: bool = False
    metadata: dict = {}


class ScanResponse(BaseModel):
    request_id: str
    decision: Decision
    risk_score: int
    findings: List[Finding]
    sanitized_content: Optional[str] = None
    normalized_content: str
    source_type: str
    summary: str
