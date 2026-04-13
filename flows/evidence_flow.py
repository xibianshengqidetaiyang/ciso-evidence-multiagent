from __future__ import annotations
from typing import Optional

from schemas.evidence_models import FlowResult
from tools.document_parser import parse_document, ParseError
from tools.audit_logger import log_event, enqueue_manual_review
from tools.ciso_api import CisoApiClient, import_evidence_with_optional_reuse, CisoApiError
from agents.validator_agent import ValidatorAgent
from agents.classifier_agent import ClassifierAgent
from agents.preaudit_agent import PreAuditAgent


class EvidenceFlow:
    def __init__(self) -> None:
        self.validator = ValidatorAgent()
        self.classifier = ClassifierAgent()
        self.preaudit = PreAuditAgent()
        self.ciso = CisoApiClient()

    def _format_preaudit_note(self, pre_audit) -> str:
        lines = [
            "【AI初审结果】",
            f"结论：{pre_audit.result}",
            f"置信度：{pre_audit.confidence}",
            "",
            "【发现】",
        ]
        for item in pre_audit.findings:
            lines.append(f"- {item}")

        lines.append("")
        lines.append("【改进建议】")
        for item in pre_audit.suggestions:
            lines.append(f"- {item}")

        lines.append("")
        lines.append(f"需人工复核：{pre_audit.manual_review_required}")
        return "\n".join(lines)

    def run(
        self,
        file_path: str,
        assessment_id: Optional[str] = None,
        assessment_name: Optional[str] = None,
        assessment_framework: Optional[str] = None,
        assessment_version: Optional[str] = None,
        try_ocr: bool = False,
        reuse_existing_evidence: bool = True,
    ) -> FlowResult:
        try:
            raw = parse_document(file_path, try_ocr=try_ocr)
            log_event("parsed", raw.model_dump())
        except ParseError as e:
            log_event("parse_failed", {"file_path": file_path, "reason": str(e)})
            return FlowResult(ok=False, step="parse", message=str(e))

        validation = self.validator.run(raw)
        log_event("validated", validation.model_dump())

        if validation.status == "reject":
            enqueue_manual_review(
                {"file_name": raw.file_name, "step": "validator", "reason": validation.reject_reason}
            )
            return FlowResult(
                ok=False,
                step="validator",
                raw_evidence=raw,
                validation=validation,
                message=validation.reject_reason,
            )

        classification = None
        import_result = None
        pre_audit = None

        if assessment_id or assessment_name:
            try:
                assessment = self.ciso.resolve_assessment(
                    assessment_id=assessment_id,
                    assessment_name=assessment_name,
                    assessment_framework=assessment_framework,
                    assessment_version=assessment_version,
                )
                log_event("assessment_resolved", assessment)

                catalog = self.ciso.build_requirement_catalog(assessment)
                log_event("requirement_catalog_loaded", {"count": len(catalog)})

                classification = self.classifier.run(raw, catalog)
                log_event("classified", classification.model_dump())

                if not classification.matches:
                    enqueue_manual_review(
                        {
                            "file_name": raw.file_name,
                            "step": "classifier",
                            "reason": f"AI 未命中任何 requirement（assessment={assessment.get('name')}）",
                        }
                    )
                    return FlowResult(
                        ok=False,
                        step="classifier",
                        raw_evidence=raw,
                        validation=validation,
                        classification=classification,
                        message="AI 未命中任何 requirement",
                    )

                import_result = import_evidence_with_optional_reuse(
                    self.ciso,
                    raw,
                    classification,
                    reuse_existing=reuse_existing_evidence,
                )
                log_event("imported", import_result.model_dump())

                # === AI 初审 ===
                pre_audit = self.preaudit.run(raw, classification, import_result)
                log_event("preaudit", pre_audit.model_dump())

                # === 回写 AI 初审备注到 requirement assessment ===
                note = self._format_preaudit_note(pre_audit)
                for ra_id in import_result.linked_requirement_assessment_ids:
                    try:
                        self.ciso.add_review_note(ra_id, note)
                    except Exception as e:
                        log_event(
                            "preaudit_note_write_failed",
                            {
                                "file_name": raw.file_name,
                                "requirement_assessment_id": ra_id,
                                "error": str(e),
                            },
                        )

            except CisoApiError as e:
                enqueue_manual_review(
                    {"file_name": raw.file_name, "step": "ciso_api", "reason": str(e)}
                )
                return FlowResult(
                    ok=False,
                    step="ciso_api",
                    raw_evidence=raw,
                    validation=validation,
                    message=str(e),
                )
            except Exception as e:
                enqueue_manual_review(
                    {"file_name": raw.file_name, "step": "flow", "reason": str(e)}
                )
                return FlowResult(
                    ok=False,
                    step="flow",
                    raw_evidence=raw,
                    validation=validation,
                    message=str(e),
                )
        else:
            return FlowResult(
                ok=True,
                step="validated_only",
                raw_evidence=raw,
                validation=validation,
                message="未指定 assessment，仅完成解析与最小筛选",
            )

        return FlowResult(
            ok=True,
            step="done",
            raw_evidence=raw,
            validation=validation,
            classification=classification,
            import_result=import_result,
            pre_audit=pre_audit,
            message="流程执行完成",
        )