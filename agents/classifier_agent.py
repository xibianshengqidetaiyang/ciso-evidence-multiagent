from __future__ import annotations
from typing import List, Dict, Any
from pathlib import Path
import json

from schemas.evidence_models import RawEvidence, ClassificationResult, RequirementMatch, RequirementCatalogItem
from tools.llm_client import OllamaClient, LlmError


class ClassifierAgent:
    def __init__(self) -> None:
        self.llm = OllamaClient()

    def run(self, raw: RawEvidence, catalog: List[RequirementCatalogItem]) -> ClassificationResult:
        if not catalog:
            return ClassificationResult(matches=[], classification_confidence=0.0, rationale="当前 assessment 下没有 requirement catalog")

        reduced_catalog = self._reduce_catalog(raw, catalog, top_k=60)
        payload = self._build_prompts(raw, reduced_catalog)

        try:
            data = self.llm.chat_json(payload["system"], payload["user"])
            return self._normalize_result(data, reduced_catalog)
        except LlmError as e:
            return ClassificationResult(matches=[], classification_confidence=0.0, rationale=f"Ollama 分类失败: {e}")

    def _evidence_summary(self, raw: RawEvidence) -> Dict[str, Any]:
        text_preview = raw.extracted_text[:5000] if raw.extracted_text else None
        return {
            "file_name": raw.file_name,
            "file_stem": Path(raw.file_name).stem,
            "extension": raw.extension,
            "mime_type": raw.mime_type,
            "size": raw.size,
            "metadata": raw.metadata,
            "text_preview": text_preview,
        }

    def _reduce_catalog(self, raw: RawEvidence, catalog: List[RequirementCatalogItem], top_k: int = 60) -> List[RequirementCatalogItem]:
        text = " ".join([
            raw.file_name.lower(),
            (raw.extracted_text or "").lower(),
            " ".join(str(v).lower() for v in raw.metadata.values() if isinstance(v, str)),
        ])

        scored = []
        for item in catalog:
            hay = f"{item.requirement_id} {item.title} {item.description or ''}".lower()
            score = 0
            for token in set(text.replace("\n", " ").split()):
                if token and len(token) >= 2 and token in hay:
                    score += 1
            scored.append((score, item))

        scored.sort(key=lambda x: x[0], reverse=True)
        reduced = [item for _, item in scored[:top_k]]
        return reduced or catalog[:top_k]

    def _build_prompts(self, raw: RawEvidence, catalog: List[RequirementCatalogItem]) -> Dict[str, str]:
        evidence = self._evidence_summary(raw)
        catalog_json = [
            {
                "requirement_assessment_id": item.requirement_assessment_id,
                "framework_name": item.framework_name,
                "requirement_id": item.requirement_id,
                "title": item.title,
                "description": item.description,
            }
            for item in catalog
        ]

        system_prompt = """
你是一个审计证据分类助手。
你的唯一任务是：根据证据内容，把当前证据映射到当前目标审计下最相关的 requirement assessments。
要求：
1. 只能从提供的 catalog 中选择，禁止虚构 requirement_id 或 requirement_assessment_id。
2. 支持多对多映射，一个证据可对应多个 requirement。
3. 若证据信息不足，可以返回空 matches。
4. 输出必须是 JSON。
5. score 取值 0~1。
6. 只输出 JSON，不要解释。
JSON 格式：
{
  "matches": [
    {
      "requirement_assessment_id": "...",
      "framework": "...",
      "requirement_id": "...",
      "title": "...",
      "score": 0.88,
      "reason": "..."
    }
  ],
  "classification_confidence": 0.88,
  "rationale": "..."
}
""".strip()

        user_prompt = f"""
当前证据：
{json.dumps(evidence, ensure_ascii=False, indent=2)}

当前目标审计的候选 requirement catalog：
{json.dumps(catalog_json, ensure_ascii=False, indent=2)}

请完成分类。
""".strip()

        return {"system": system_prompt, "user": user_prompt}

    def _normalize_result(self, data: Dict[str, Any], catalog: List[RequirementCatalogItem]) -> ClassificationResult:
        valid_ids = {x.requirement_assessment_id: x for x in catalog}
        matches = []

        for item in data.get("matches", []):
            ra_id = str(item.get("requirement_assessment_id", "")).strip()
            if not ra_id or ra_id not in valid_ids:
                continue
            ref = valid_ids[ra_id]
            matches.append(
                RequirementMatch(
                    framework=str(item.get("framework") or ref.framework_name or ""),
                    requirement_id=str(item.get("requirement_id") or ref.requirement_id or ""),
                    requirement_assessment_id=ra_id,
                    title=str(item.get("title") or ref.title or ""),
                    score=float(item.get("score", 0.0)),
                    reason=item.get("reason"),
                )
            )

        matches.sort(key=lambda x: x.score, reverse=True)
        confidence = max([m.score for m in matches], default=0.0)

        return ClassificationResult(
            matches=matches,
            classification_confidence=float(data.get("classification_confidence", confidence)),
            rationale=data.get("rationale") or "Ollama 分类结果",
        )
