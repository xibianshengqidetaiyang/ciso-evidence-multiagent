from __future__ import annotations

from schemas.evidence_models import RawEvidence, ValidationResult
from tools.document_parser import is_empty_evidence, is_noise_evidence


class ValidatorAgent:
    def run(self, raw: RawEvidence) -> ValidationResult:
        if is_empty_evidence(raw):
            return ValidationResult(
                is_valid_evidence=False,
                status="reject",
                confidence=0.98,
                reject_reason="文件为空或无可用内容",
                summary="文件为空",
            )

        if is_noise_evidence(raw):
            return ValidationResult(
                is_valid_evidence=False,
                status="reject",
                confidence=0.90,
                reject_reason="文件内容疑似纯噪声",
                summary="检测到乱码/低信号文本",
            )

        return ValidationResult(
            is_valid_evidence=True,
            status="pass",
            confidence=0.85,
            summary="通过最小证据筛选",
        )
