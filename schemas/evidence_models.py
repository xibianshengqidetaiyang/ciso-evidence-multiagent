from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any


class RawEvidence(BaseModel):
    file_path: str
    file_name: str
    extension: str
    mime_type: Optional[str] = None
    size: int = 0
    sha256: Optional[str] = None
    extracted_text: Optional[str] = None
    is_binary: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    is_valid_evidence: bool
    status: str
    confidence: float
    reject_reason: Optional[str] = None
    risk_flags: List[str] = Field(default_factory=list)
    summary: Optional[str] = None


class RequirementCatalogItem(BaseModel):
    requirement_assessment_id: str
    framework_name: Optional[str] = None
    requirement_id: Optional[str] = None
    title: str
    description: Optional[str] = None


class RequirementMatch(BaseModel):
    framework: str
    requirement_id: str
    requirement_assessment_id: str
    title: Optional[str] = None
    score: float
    reason: Optional[str] = None


class ClassificationResult(BaseModel):
    matches: List[RequirementMatch] = Field(default_factory=list)
    classification_confidence: float = 0.0
    rationale: Optional[str] = None

    @property
    def primary_match(self) -> Optional[RequirementMatch]:
        return self.matches[0] if self.matches else None


class ImportResult(BaseModel):
    success: bool
    evidence_id: Optional[str] = None
    reused_existing: bool = False
    linked_requirement_ids: List[str] = Field(default_factory=list)
    linked_requirement_assessment_ids: List[str] = Field(default_factory=list)
    message: Optional[str] = None
    raw_response: Optional[Dict[str, Any]] = None


class ScoreEstimate(BaseModel):
    min: int
    max: int


class MissingEvidenceItem(BaseModel):
    category: str
    missing_item: str
    importance: str  # high / medium / low


class RecommendedFileItem(BaseModel):
    file_name: str
    purpose: str


class ScoreGainEstimateItem(BaseModel):
    after_files: List[str] = Field(default_factory=list)
    estimated_score_min: int
    estimated_score_max: int


class GapReport(BaseModel):
    current_score_estimate: ScoreEstimate
    missing_evidence: List[MissingEvidenceItem] = Field(default_factory=list)
    recommended_files: List[RecommendedFileItem] = Field(default_factory=list)
    score_gain_estimate: List[ScoreGainEstimateItem] = Field(default_factory=list)
    priority_actions: List[str] = Field(default_factory=list)


class PreAuditResult(BaseModel):
    result: str
    confidence: float
    findings: List[str] = Field(default_factory=list)
    suggestions: List[str] = Field(default_factory=list)
    manual_review_required: bool = False
    gap_report: Optional[GapReport] = None


class FlowResult(BaseModel):
    ok: bool
    step: str
    raw_evidence: Optional[RawEvidence] = None
    validation: Optional[ValidationResult] = None
    classification: Optional[ClassificationResult] = None
    import_result: Optional[ImportResult] = None
    pre_audit: Optional[PreAuditResult] = None
    message: Optional[str] = None