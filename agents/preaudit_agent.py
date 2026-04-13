from __future__ import annotations
from typing import List, Dict, Any
import json

from schemas.evidence_models import (
    RawEvidence,
    ClassificationResult,
    ImportResult,
    PreAuditResult,
    GapReport,
    ScoreEstimate,
    MissingEvidenceItem,
    RecommendedFileItem,
    ScoreGainEstimateItem,
)
from tools.llm_client import OllamaClient, LlmError


class PreAuditAgent:
    """
    作用：
    1. 给出初审结论
    2. 给出 findings / suggestions
    3. 给出 gap_report：缺什么、补什么、预计提分区间
    """

    def __init__(self) -> None:
        self.llm = OllamaClient()

    def run(
        self,
        raw: RawEvidence,
        classification: ClassificationResult,
        import_result: ImportResult,
    ) -> PreAuditResult:
        if not classification.matches:
            return PreAuditResult(
                result="suspicious",
                confidence=0.0,
                findings=["未命中任何 requirement，无法执行初审"],
                suggestions=["请先确认分类结果是否正确，再执行初审"],
                manual_review_required=True,
            )

        evidence_payload = self._build_evidence_payload(raw)
        requirement_payload = self._build_requirement_payload(classification)

        try:
            data = self.llm.chat_json(
                self._system_prompt(),
                self._user_prompt(evidence_payload, requirement_payload),
            )
            return self._normalize_result(data)
        except LlmError as e:
            return PreAuditResult(
                result="suspicious",
                confidence=0.0,
                findings=[f"AI 初审失败：{e}"],
                suggestions=["请检查 Ollama 是否正常运行，或对该证据人工复核"],
                manual_review_required=True,
            )

    def _build_evidence_payload(self, raw: RawEvidence) -> Dict[str, Any]:
        return {
            "file_name": raw.file_name,
            "extension": raw.extension,
            "mime_type": raw.mime_type,
            "size": raw.size,
            "metadata": raw.metadata,
            "text_preview": raw.extracted_text[:7000] if raw.extracted_text else None,
        }

    def _build_requirement_payload(self, classification: ClassificationResult) -> List[Dict[str, Any]]:
        return [
            {
                "framework": m.framework,
                "requirement_id": m.requirement_id,
                "title": m.title,
                "score": m.score,
                "reason": m.reason,
                "requirement_assessment_id": m.requirement_assessment_id,
            }
            for m in classification.matches
        ]

    def _system_prompt(self) -> str:
        return """
你是一个审计证据 AI 初审与整改建议助手。
你的任务：
1. 根据证据内容和已匹配 requirement，判断该证据是 compliant / partial / non_compliant / suspicious 中哪一种。
2. 给出 2-5 条 findings。
3. 给出 2-5 条 suggestions。
4. 生成一个 gap_report，明确：
   - 当前估分区间
   - 缺失证据
   - 建议补充的文件
   - 补充后预计提分区间
   - 优先行动项
5. 如果证据明显不足，manual_review_required 必须为 true。
6. 分数使用区间，不要使用单点分数。
7. 只输出 JSON，不要输出解释。

输出格式：
{
  "result": "compliant | partial | non_compliant | suspicious",
  "confidence": 0.78,
  "findings": ["...", "..."],
  "suggestions": ["...", "..."],
  "manual_review_required": true,
  "gap_report": {
    "current_score_estimate": {
      "min": 60,
      "max": 70
    },
    "missing_evidence": [
      {
        "category": "xxx",
        "missing_item": "xxx",
        "importance": "high"
      }
    ],
    "recommended_files": [
      {
        "file_name": "xxx.docx",
        "purpose": "xxx"
      }
    ],
    "score_gain_estimate": [
      {
        "after_files": ["xxx.docx", "yyy.pdf"],
        "estimated_score_min": 75,
        "estimated_score_max": 85
      }
    ],
    "priority_actions": [
      "xxx",
      "xxx"
    ]
  }
}
""".strip()

    def _user_prompt(self, evidence_payload: Dict[str, Any], requirement_payload: List[Dict[str, Any]]) -> str:
        return f"""
当前证据：
{json.dumps(evidence_payload, ensure_ascii=False, indent=2)}

当前已匹配 requirements：
{json.dumps(requirement_payload, ensure_ascii=False, indent=2)}

请输出初审结论和整改提分建议。
""".strip()

    def _normalize_result(self, data: Dict[str, Any]) -> PreAuditResult:
        result = str(data.get("result", "suspicious")).strip().lower()
        if result not in {"compliant", "partial", "non_compliant", "suspicious"}:
            result = "suspicious"

        try:
            confidence = float(data.get("confidence", 0.0))
        except Exception:
            confidence = 0.0

        findings = data.get("findings") or []
        suggestions = data.get("suggestions") or []

        if not isinstance(findings, list):
            findings = [str(findings)]
        if not isinstance(suggestions, list):
            suggestions = [str(suggestions)]

        manual_review_required = bool(data.get("manual_review_required", False))

        gap_report = None
        gap_data = data.get("gap_report")
        if isinstance(gap_data, dict):
            try:
                current_score = gap_data.get("current_score_estimate") or {}
                gap_report = GapReport(
                    current_score_estimate=ScoreEstimate(
                        min=int(current_score.get("min", 0)),
                        max=int(current_score.get("max", 0)),
                    ),
                    missing_evidence=[
                        MissingEvidenceItem(
                            category=str(x.get("category", "")),
                            missing_item=str(x.get("missing_item", "")),
                            importance=str(x.get("importance", "medium")),
                        )
                        for x in gap_data.get("missing_evidence", [])
                        if isinstance(x, dict)
                    ],
                    recommended_files=[
                        RecommendedFileItem(
                            file_name=str(x.get("file_name", "")),
                            purpose=str(x.get("purpose", "")),
                        )
                        for x in gap_data.get("recommended_files", [])
                        if isinstance(x, dict)
                    ],
                    score_gain_estimate=[
                        ScoreGainEstimateItem(
                            after_files=[str(v) for v in x.get("after_files", [])],
                            estimated_score_min=int(x.get("estimated_score_min", 0)),
                            estimated_score_max=int(x.get("estimated_score_max", 0)),
                        )
                        for x in gap_data.get("score_gain_estimate", [])
                        if isinstance(x, dict)
                    ],
                    priority_actions=[str(x) for x in gap_data.get("priority_actions", [])],
                )
            except Exception:
                gap_report = None

        return PreAuditResult(
            result=result,
            confidence=confidence,
            findings=[str(x) for x in findings],
            suggestions=[str(x) for x in suggestions],
            manual_review_required=manual_review_required,
            gap_report=gap_report,
        )