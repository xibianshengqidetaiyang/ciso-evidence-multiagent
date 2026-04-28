from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from schemas.evidence_models import (
    ClassificationResult,
    RawEvidence,
    RequirementCatalogItem,
    RequirementMatch,
)


@dataclass
class ScoredCandidate:
    item: RequirementCatalogItem
    score: float
    primary_family: Optional[str]
    family_align: float
    anchor_strength: float
    lexical_overlap: float
    filename_overlap: float
    action_match: float
    doc_type_fit: float
    title_bias: float
    generic_penalty: float
    conflict_penalty: float
    reason: str


class ClassifierAgent:
    """
    通用证据分类器：
    1. 不写死 tisax requirement id
    2. 只依赖当前 assessment 的 requirement catalog
    3. 用“证据主题家族 + 控制项主题家族 + 文档形态 + 文本重叠”做排序
    4. 默认纯规则，不依赖 LLM，也不为了 demo 写死样本
    """

    STOPWORDS = {
        "the", "and", "for", "with", "that", "this", "from", "into", "are", "was",
        "were", "is", "be", "been", "being", "of", "to", "in", "on", "at", "as",
        "by", "or", "an", "a", "it", "its", "their", "there", "such", "than",
        "which", "what", "how", "extent", "regarding", "related", "relevant",
        "must", "should", "may", "can", "will", "using", "used", "use",
        "information", "security", "management", "control", "controls",
        "requirement", "requirements", "organization", "organisations", "organization’s",
        "purpose", "scope", "policy", "procedure", "standard", "further",
        "introduction", "considered", "handled", "ensured", "activities",
        "以及", "或者", "相关", "要求", "管理", "信息", "安全", "控制", "措施", "组织",
        "目的", "范围", "职责", "权限", "规定", "程序", "制度", "管理制度",
    }

    GENERIC_TITLE_PATTERNS = [
        re.compile(r"^\s*introduction[:：]?\s*$", re.I),
        re.compile(r"^\s*further information\s*$", re.I),
        re.compile(r"^\s*\(?must\)?\s*$", re.I),
        re.compile(r"^\s*\(?should\)?\s*$", re.I),
        re.compile(r"^\s*\(?for .+\)?\s*$", re.I),
        re.compile(r"^\s*说明[:：]?\s*$", re.I),
        re.compile(r"^\s*引言[:：]?\s*$", re.I),
    ]

    FAMILY_RULES: Dict[str, Dict[str, List[str]]] = {
        "asset_inventory": {
            "positive": [
                "asset inventory", "inventory", "register", "registered", "identified",
                "recorded", "asset list", "information asset", "asset owner",
                "资产清单", "资产台账", "识别", "登记", "记录", "信息资产", "资产所有者",
            ],
            "strong": [
                "asset inventory", "asset list", "information asset",
                "资产清单", "资产台账", "信息资产",
            ],
            "actions": [
                "identify", "record", "register", "maintain", "review",
                "识别", "记录", "登记", "维护", "核查",
            ],
        },
        "asset_classification": {
            "positive": [
                "classification", "classified", "labeling", "labelling",
                "protection needs", "classification level", "confidentiality",
                "integrity", "availability",
                "分类", "分级", "标识", "标签", "保护需求", "保密性", "完整性", "可用性",
            ],
            "strong": [
                "protection needs", "classification level",
                "分类", "分级", "保护需求", "标识",
            ],
            "actions": [
                "classify", "label", "determine", "review",
                "分类", "分级", "标识", "确定", "核查",
            ],
        },
        "awareness_training": {
            "positive": [
                "awareness", "training", "trained", "staff", "employee", "employees",
                "qualification", "confidentiality", "policy compliance", "handbook",
                "培训", "宣贯", "意识", "员工", "人员", "保密", "教育", "资格", "手册", "规章制度",
            ],
            "strong": [
                "awareness", "training", "staff", "employee handbook",
                "培训", "宣贯", "员工手册", "保密",
            ],
            "actions": [
                "train", "educate", "communicate", "comply",
                "培训", "教育", "宣贯", "遵守",
            ],
        },
        "malware_protection": {
            "positive": [
                "malware", "anti-virus", "antivirus", "virus", "virus protection",
                "virus database", "malicious code", "mobile code",
                "恶意软件", "病毒", "防病毒", "杀毒", "病毒库", "恶意代码", "可移动代码", "查杀",
            ],
            "strong": [
                "malware", "anti-virus", "antivirus", "virus protection",
                "malicious code", "virus database",
                "恶意软件", "病毒", "防病毒", "杀毒", "病毒库", "恶意代码", "查杀",
            ],
            "actions": [
                "install", "update", "detect", "remove", "monitor", "protect",
                "安装", "更新", "检测", "清除", "监测", "防护", "查杀",
            ],
        },
        "vulnerability_management": {
            "positive": [
                "vulnerability", "weakness", "patch", "remediation", "security flaw",
                "hardening", "cve", "rdp", "nla", "remoteregistry",
                "man in the middle", "remote desktop",
                "漏洞", "弱点", "补丁", "整改", "修复", "加固", "远程桌面",
                "中间人", "网络级身份验证", "remote registry",
            ],
            "strong": [
                "vulnerability", "weakness", "patch", "remediation", "hardening",
                "rdp", "nla", "remoteregistry", "man in the middle",
                "漏洞", "弱点", "补丁", "整改", "修复", "加固", "远程桌面",
                "中间人", "网络级身份验证",
            ],
            "actions": [
                "discover", "remediate", "fix", "disable", "harden", "patch",
                "发现", "整改", "修复", "禁用", "加固", "处置",
            ],
        },
        "logging_monitoring": {
            "positive": [
                "log", "logs", "logging", "event log", "audit trail", "review", "analyse",
                "analyze", "failed login", "successful login", "account lockout",
                "日志", "日志检查", "评审记录", "审计记录", "事件日志", "登录失败",
                "登录成功", "账户被锁定", "上网行为日志", "邮件发送日志",
            ],
            "strong": [
                "event log", "logging", "audit trail", "failed login",
                "日志检查", "评审记录", "事件日志", "登录失败", "上网行为日志",
            ],
            "actions": [
                "record", "review", "analyse", "analyze", "monitor", "inspect",
                "记录", "检查", "评审", "分析", "监控",
            ],
        },
        "incident_management": {
            "positive": [
                "incident", "event reporting", "escalation", "response",
                "security event", "reportable event",
                "事件", "上报", "升级", "响应", "报告", "处置流程",
            ],
            "strong": [
                "incident", "event reporting", "escalation",
                "事件", "上报", "升级", "响应",
            ],
            "actions": [
                "report", "escalate", "respond", "handle",
                "上报", "升级", "响应", "处置",
            ],
        },
        "access_control": {
            "positive": [
                "access control", "authorization", "authorisation", "user account",
                "least privilege", "authentication", "password", "privilege",
                "访问控制", "权限", "授权", "账号", "账户", "认证", "密码", "最小权限",
            ],
            "strong": [
                "access control", "authorization", "least privilege", "user account",
                "访问控制", "授权", "最小权限", "账号", "账户",
            ],
            "actions": [
                "authorize", "grant", "revoke", "disable", "control",
                "授权", "分配", "删除", "禁用", "控制",
            ],
        },
        "third_party_supplier": {
            "positive": [
                "supplier", "service provider", "third party", "external service",
                "contractor", "outsourcing",
                "供应商", "服务商", "第三方", "外部服务", "承包商", "外包",
            ],
            "strong": [
                "supplier", "third party", "external service",
                "供应商", "第三方", "外部服务",
            ],
            "actions": [
                "evaluate", "approve", "manage",
                "评估", "批准", "管理",
            ],
        },
        "privacy_encryption": {
            "positive": [
                "encryption", "encrypted", "cryptographic", "data protection",
                "personal data", "privacy",
                "加密", "密码", "数据保护", "个人信息", "隐私",
            ],
            "strong": [
                "encryption", "cryptographic", "personal data",
                "加密", "密码", "个人信息",
            ],
            "actions": [
                "encrypt", "protect", "process",
                "加密", "保护", "处理",
            ],
        },
        "physical_security": {
            "positive": [
                "physical", "zone", "perimeter", "entry", "badge", "visitor",
                "物理", "区域", "门禁", "访客", "边界",
            ],
            "strong": [
                "physical", "zone", "perimeter",
                "物理", "区域", "门禁",
            ],
            "actions": [
                "protect", "restrict", "control",
                "保护", "限制", "控制",
            ],
        },
    }

    CONFLICT_MATRIX: Dict[str, Dict[str, float]] = {
        "malware_protection": {
            "awareness_training": 0.28,
            "asset_inventory": 0.16,
            "asset_classification": 0.16,
            "physical_security": 0.18,
            "third_party_supplier": 0.16,
            "privacy_encryption": 0.12,
        },
        "vulnerability_management": {
            "awareness_training": 0.26,
            "asset_inventory": 0.14,
            "asset_classification": 0.14,
            "physical_security": 0.18,
            "privacy_encryption": 0.10,
        },
        "logging_monitoring": {
            "awareness_training": 0.18,
            "asset_classification": 0.10,
            "physical_security": 0.12,
        },
        "asset_classification": {
            "awareness_training": 0.14,
            "malware_protection": 0.20,
            "vulnerability_management": 0.18,
        },
        "awareness_training": {
            "malware_protection": 0.20,
            "vulnerability_management": 0.18,
            "logging_monitoring": 0.12,
            "asset_classification": 0.12,
        },
    }

    def __init__(self) -> None:
        self.preview_chars = int(os.getenv("CLASSIFIER_TEXT_PREVIEW_CHARS", "4500"))
        self.reduce_top_k = int(os.getenv("CLASSIFIER_REDUCE_TOP_K", "120"))
        self.final_top_k = int(os.getenv("CLASSIFIER_FINAL_TOP_K", "10"))

    def run(self, raw: RawEvidence, catalog: List[RequirementCatalogItem]) -> ClassificationResult:
        return self.classify(raw=raw, requirement_catalog=catalog)

    def classify(
        self,
        raw: RawEvidence,
        requirement_catalog: List[RequirementCatalogItem],
        **_: Any,
    ) -> ClassificationResult:
        if not requirement_catalog:
            return ClassificationResult(
                matches=[],
                classification_confidence=0.0,
                rationale="当前 assessment 下没有 requirement catalog",
            )

        reduced_catalog = self._reduce_catalog(raw, requirement_catalog, top_k=self.reduce_top_k)
        scored = self._score_candidates(raw, reduced_catalog)
        matches = self._finalize_matches(scored)

        confidence = max((m.score for m in matches), default=0.0)
        rationale = f"规则排序结果；catalog已裁剪为{len(reduced_catalog)}/{len(requirement_catalog)}"

        return ClassificationResult(
            matches=matches,
            classification_confidence=round(confidence, 4),
            rationale=rationale,
        )

    # =========================================================
    # 基础工具
    # =========================================================

    def _normalize_space(self, s: str) -> str:
        s = s or ""
        s = s.replace("\xa0", " ").replace("\u3000", " ")
        return re.sub(r"\s+", " ", s).strip()

    def _normalize_text(self, s: str) -> str:
        return self._normalize_space(s).lower()

    def _safe_text(self, raw: RawEvidence) -> str:
        parts = [
            raw.file_name or "",
            raw.extracted_text or "",
            " ".join(
                str(v) for v in (raw.metadata or {}).values()
                if isinstance(v, (str, int, float))
            ),
        ]
        return self._normalize_text("\n".join(p for p in parts if p))

    def _tokenize(self, text: str) -> List[str]:
        text = self._normalize_text(text)
        tokens: List[str] = []

        for m in re.finditer(r"[a-z0-9][a-z0-9._/\-]{1,}|[\u4e00-\u9fff]{2,}", text):
            tok = m.group(0).strip("._/-")
            if len(tok) < 2:
                continue
            if tok in self.STOPWORDS:
                continue
            tokens.append(tok)

        for m in re.finditer(r"\b\d+(?:\.\d+){1,4}\b", text):
            tokens.append(m.group(0))

        return tokens

    def _token_set(self, text: str) -> Set[str]:
        return set(self._tokenize(text))

    def _evidence_summary(self, raw: RawEvidence) -> Dict[str, Any]:
        return {
            "file_name": raw.file_name,
            "file_stem": Path(raw.file_name).stem if raw.file_name else "",
            "extension": raw.extension,
            "mime_type": raw.mime_type,
            "size": raw.size,
            "metadata": raw.metadata or {},
            "text_preview": (raw.extracted_text or "")[: self.preview_chars],
        }

    def _item_text(self, item: RequirementCatalogItem) -> str:
        return self._normalize_text(
            f"{item.requirement_id or ''} {item.title or ''} {item.description or ''}"
        )

    # =========================================================
    # 文档形态判断
    # =========================================================

    def _guess_document_form(self, raw: RawEvidence) -> str:
        txt = self._safe_text(raw)

        if any(k in txt for k in ["日志检查", "评审记录", "审计记录", "event log", "logging", "failed login"]):
            return "log_record"
        if any(k in txt for k in ["弱点报告", "漏洞", "弱点", "vulnerability", "weakness", "patch"]):
            return "report"
        if any(k in txt for k in ["员工手册", "staff manual", "manual", "handbook"]):
            return "manual"
        if any(k in txt for k in ["管理程序", "制度", "规定", "policy", "procedure", "standard"]):
            return "procedure"
        return "other"

    # =========================================================
    # family 计算
    # =========================================================

    def _keyword_hits(self, text: str, keywords: List[str]) -> Tuple[int, List[str]]:
        hits: List[str] = []
        norm = self._normalize_text(text)
        for kw in keywords:
            nkw = self._normalize_text(kw)
            if nkw and nkw in norm:
                hits.append(kw)
        return len(hits), hits

    def _family_profile(self, text: str) -> Dict[str, float]:
        profile: Dict[str, float] = {}
        for family, rule in self.FAMILY_RULES.items():
            pos_hits, _ = self._keyword_hits(text, rule["positive"])
            strong_hits, _ = self._keyword_hits(text, rule["strong"])
            action_hits, _ = self._keyword_hits(text, rule["actions"])

            raw_score = pos_hits * 1.0 + strong_hits * 1.8 + action_hits * 0.6
            if raw_score <= 0:
                continue

            profile[family] = min(1.0, raw_score / 5.0)
        return profile

    def _dominant_family(self, profile: Dict[str, float]) -> Optional[str]:
        if not profile:
            return None
        ordered = sorted(profile.items(), key=lambda x: x[1], reverse=True)
        best_family, best_score = ordered[0]
        second_score = ordered[1][1] if len(ordered) > 1 else 0.0

        if best_score >= 0.48 and best_score >= second_score + 0.12:
            return best_family
        return None

    def _family_similarity(
        self,
        doc_profile: Dict[str, float],
        item_profile: Dict[str, float],
    ) -> Tuple[float, Optional[str]]:
        common = set(doc_profile.keys()) & set(item_profile.keys())
        if not common:
            return 0.0, None

        best_family = None
        best_score = 0.0
        for family in common:
            ds = doc_profile.get(family, 0.0)
            is_ = item_profile.get(family, 0.0)
            score = math.sqrt(ds * is_)
            if score > best_score:
                best_score = score
                best_family = family
        return best_score, best_family

    def _shared_family_strong_hits(self, doc_text: str, item_text: str, family: Optional[str]) -> int:
        if not family or family not in self.FAMILY_RULES:
            return 0
        count = 0
        for kw in self.FAMILY_RULES[family]["strong"]:
            nkw = self._normalize_text(kw)
            if nkw and nkw in doc_text and nkw in item_text:
                count += 1
        return count

    def _anchor_strength(
        self,
        doc_text: str,
        item_text: str,
        family: Optional[str],
        doc_profile: Dict[str, float],
        item_profile: Dict[str, float],
    ) -> float:
        if not family:
            return 0.0

        shared = self._shared_family_strong_hits(doc_text, item_text, family)
        if shared >= 2:
            return 1.0
        if shared == 1:
            return 0.65

        ds = doc_profile.get(family, 0.0)
        is_ = item_profile.get(family, 0.0)

        if ds >= 0.75 and is_ >= 0.75:
            return 0.45
        if ds >= 0.55 and is_ >= 0.55:
            return 0.30
        return 0.0

    def _action_match_score(self, doc_text: str, family: Optional[str]) -> float:
        if not family or family not in self.FAMILY_RULES:
            return 0.0
        hit_count, _ = self._keyword_hits(doc_text, self.FAMILY_RULES[family]["actions"])
        if hit_count <= 0:
            return 0.0
        return min(1.0, hit_count / 3.0)

    # =========================================================
    # requirement 判断
    # =========================================================

    def _extract_clause_code(self, item: RequirementCatalogItem) -> str:
        rid = str(item.requirement_id or "")
        title = str(item.title or "")

        tail = rid.split(":")[-1].strip()
        if re.fullmatch(r"[A-Za-z]?\d+(?:\.\d+){1,4}", tail):
            return tail

        m = re.match(r"^\s*([A-Za-z]?\d+(?:\.\d+){1,4})\b", title)
        if m:
            return m.group(1)

        return ""

    def _is_question_like_title(self, item: RequirementCatalogItem) -> bool:
        title = self._normalize_text(item.title or "")
        clause = self._extract_clause_code(item)

        if "to what extent" in title:
            return True
        if title.startswith("是否") or title.startswith("什么程度"):
            return True
        if clause and ":node" not in (item.requirement_id or "").lower():
            return True

        return False

    def _is_generic_candidate(self, item: RequirementCatalogItem) -> bool:
        title = self._normalize_text(item.title or "")
        rid = (item.requirement_id or "").lower()

        for p in self.GENERIC_TITLE_PATTERNS:
            if p.match(title):
                return True

        if ":node" in rid and not self._is_question_like_title(item):
            return True
        if title.endswith("introduction:") or title == "introduction":
            return True
        if "further information" in title:
            return True

        return False

    def _title_bias(self, item: RequirementCatalogItem) -> float:
        bias = 0.0
        clause = self._extract_clause_code(item)

        if self._is_question_like_title(item):
            bias += 0.72
        elif clause:
            bias += 0.28

        if not self._is_generic_candidate(item):
            bias += 0.28

        if clause and ":node" not in (item.requirement_id or "").lower():
            bias += 0.08

        return min(1.0, bias)

    # =========================================================
    # 评分
    # =========================================================

    def _lexical_overlap(self, doc_tokens: Set[str], item_tokens: Set[str]) -> float:
        if not doc_tokens or not item_tokens:
            return 0.0
        shared = doc_tokens & item_tokens
        if not shared:
            return 0.0
        return min(1.0, len(shared) / max(2.0, len(item_tokens) ** 0.5))

    def _filename_overlap(self, file_tokens: Set[str], item_tokens: Set[str]) -> float:
        if not file_tokens or not item_tokens:
            return 0.0
        shared = file_tokens & item_tokens
        if not shared:
            return 0.0
        return min(1.0, len(shared) / max(1.0, len(file_tokens)))

    def _doc_type_fit(self, doc_form: str, family: Optional[str]) -> float:
        if not family:
            return 0.30

        if doc_form == "manual":
            if family == "awareness_training":
                return 0.95
            if family in {"access_control", "privacy_encryption"}:
                return 0.65
            return 0.45

        if doc_form == "procedure":
            if family in {
                "asset_inventory",
                "asset_classification",
                "malware_protection",
                "vulnerability_management",
                "access_control",
                "incident_management",
                "third_party_supplier",
                "privacy_encryption",
            }:
                return 0.95
            if family == "awareness_training":
                return 0.50
            return 0.55

        if doc_form == "report":
            if family in {"vulnerability_management", "incident_management", "logging_monitoring"}:
                return 0.95
            if family == "malware_protection":
                return 0.60
            return 0.45

        if doc_form == "log_record":
            if family == "logging_monitoring":
                return 0.95
            if family in {"incident_management", "access_control"}:
                return 0.70
            return 0.45

        return 0.35

    def _conflict_penalty(self, dominant_family: Optional[str], primary_family: Optional[str]) -> float:
        if not dominant_family or not primary_family:
            return 0.0
        if dominant_family == primary_family:
            return 0.0
        return self.CONFLICT_MATRIX.get(dominant_family, {}).get(primary_family, 0.0)

    def _cheap_score(
        self,
        raw: RawEvidence,
        item: RequirementCatalogItem,
        doc_tokens: Set[str],
        file_tokens: Set[str],
        doc_profile: Dict[str, float],
        doc_form: str,
    ) -> float:
        item_text = self._item_text(item)
        item_tokens = self._token_set(item_text)
        item_profile = self._family_profile(item_text)
        doc_text = self._safe_text(raw)

        family_align, primary_family = self._family_similarity(doc_profile, item_profile)
        anchor = self._anchor_strength(doc_text, item_text, primary_family, doc_profile, item_profile)
        lexical = self._lexical_overlap(doc_tokens, item_tokens)
        filename_hit = self._filename_overlap(file_tokens, item_tokens)
        action = self._action_match_score(doc_text, primary_family)
        doc_fit = self._doc_type_fit(doc_form, primary_family)
        title_bias = self._title_bias(item)

        generic_penalty = 0.16 if self._is_generic_candidate(item) else (0.05 if ":node" in (item.requirement_id or "").lower() else 0.0)
        conflict_penalty = self._conflict_penalty(self._dominant_family(doc_profile), primary_family)

        score = (
            family_align * 0.26
            + anchor * 0.25
            + lexical * 0.14
            + filename_hit * 0.03
            + action * 0.08
            + doc_fit * 0.08
            + title_bias * 0.16
            - generic_penalty
            - conflict_penalty
        )
        return score

    def _reduce_catalog(
        self,
        raw: RawEvidence,
        catalog: List[RequirementCatalogItem],
        top_k: int = 120,
    ) -> List[RequirementCatalogItem]:
        if len(catalog) <= top_k:
            return catalog

        doc_text = self._safe_text(raw)
        doc_tokens = self._token_set(doc_text)
        file_tokens = self._token_set(Path(raw.file_name).stem if raw.file_name else "")
        doc_profile = self._family_profile(doc_text)
        doc_form = self._guess_document_form(raw)

        scored: List[Tuple[float, RequirementCatalogItem]] = []
        for item in catalog:
            s = self._cheap_score(raw, item, doc_tokens, file_tokens, doc_profile, doc_form)
            scored.append((s, item))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [item for _, item in scored[:top_k]]

    def _score_candidates(self, raw: RawEvidence, catalog: List[RequirementCatalogItem]) -> List[ScoredCandidate]:
        doc_text = self._safe_text(raw)
        doc_tokens = self._token_set(doc_text)
        file_tokens = self._token_set(Path(raw.file_name).stem if raw.file_name else "")
        doc_profile = self._family_profile(doc_text)
        doc_form = self._guess_document_form(raw)
        dominant_family = self._dominant_family(doc_profile)

        scored: List[ScoredCandidate] = []

        for item in catalog:
            item_text = self._item_text(item)
            item_tokens = self._token_set(item_text)
            item_profile = self._family_profile(item_text)

            family_align, primary_family = self._family_similarity(doc_profile, item_profile)
            anchor = self._anchor_strength(doc_text, item_text, primary_family, doc_profile, item_profile)
            lexical = self._lexical_overlap(doc_tokens, item_tokens)
            filename_hit = self._filename_overlap(file_tokens, item_tokens)
            action_match = self._action_match_score(doc_text, primary_family)
            doc_type_fit = self._doc_type_fit(doc_form, primary_family)
            title_bias = self._title_bias(item)

            generic_penalty = 0.16 if self._is_generic_candidate(item) else (0.05 if ":node" in (item.requirement_id or "").lower() else 0.0)
            conflict_penalty = self._conflict_penalty(dominant_family, primary_family)

            score = (
                family_align * 0.26
                + anchor * 0.25
                + lexical * 0.14
                + filename_hit * 0.03
                + action_match * 0.08
                + doc_type_fit * 0.08
                + title_bias * 0.16
                - generic_penalty
                - conflict_penalty
            )

            if dominant_family and primary_family == dominant_family:
                score += 0.03

            score = max(0.0, min(0.99, score))

            reason = (
                f"family对齐={family_align:.2f}；"
                f"强锚点={anchor:.2f}；"
                f"文本重叠={lexical:.2f}；"
                f"文件名命中={filename_hit:.2f}；"
                f"动作命中={action_match:.2f}；"
                f"文档形态={doc_type_fit:.2f}；"
                f"title加权={title_bias:.2f}"
            )
            if generic_penalty > 0:
                reason += f"；generic降权={generic_penalty:.2f}"
            if conflict_penalty > 0:
                reason += f"；冲突降权={conflict_penalty:.2f}"
            if dominant_family:
                reason += f"；主导家族={dominant_family}"

            scored.append(
                ScoredCandidate(
                    item=item,
                    score=round(score, 4),
                    primary_family=primary_family,
                    family_align=family_align,
                    anchor_strength=anchor,
                    lexical_overlap=lexical,
                    filename_overlap=filename_hit,
                    action_match=action_match,
                    doc_type_fit=doc_type_fit,
                    title_bias=title_bias,
                    generic_penalty=generic_penalty,
                    conflict_penalty=conflict_penalty,
                    reason=reason,
                )
            )

        scored.sort(key=lambda x: x.score, reverse=True)
        return scored

    # =========================================================
    # 结果收束
    # =========================================================

    def _finalize_matches(self, scored: List[ScoredCandidate]) -> List[RequirementMatch]:
        if not scored:
            return []

        best_score = scored[0].score
        best_explicit_by_family: Dict[str, float] = {}

        for cand in scored:
            fam = cand.primary_family
            if fam and self._is_question_like_title(cand.item):
                best_explicit_by_family[fam] = max(best_explicit_by_family.get(fam, 0.0), cand.score)

        selected: List[ScoredCandidate] = []
        seen_ids: Set[str] = set()

        for cand in scored:
            ra_id = str(cand.item.requirement_assessment_id or "")
            if not ra_id or ra_id in seen_ids:
                continue

            fam = cand.primary_family or ""
            is_generic = self._is_generic_candidate(cand.item)

            if is_generic and fam in best_explicit_by_family:
                if cand.score <= best_explicit_by_family[fam] - 0.03:
                    continue

            threshold = 0.34 if not is_generic else 0.42
            if cand.score < threshold:
                continue

            if cand.score < best_score - 0.18:
                continue

            selected.append(cand)
            seen_ids.add(ra_id)

            if len(selected) >= self.final_top_k:
                break

        if not selected:
            for cand in scored[:3]:
                if cand.score >= 0.28:
                    ra_id = str(cand.item.requirement_assessment_id or "")
                    if not ra_id or ra_id in seen_ids:
                        continue
                    selected.append(cand)
                    seen_ids.add(ra_id)

        matches: List[RequirementMatch] = []
        for cand in selected[: self.final_top_k]:
            ref = cand.item
            matches.append(
                RequirementMatch(
                    framework=str(ref.framework_name or ""),
                    requirement_id=str(ref.requirement_id or ""),
                    requirement_assessment_id=str(ref.requirement_assessment_id or ""),
                    title=str(ref.title or ""),
                    score=round(float(cand.score), 4),
                    reason=cand.reason,
                )
            )

        return matches