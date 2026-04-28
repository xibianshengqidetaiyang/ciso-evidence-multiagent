from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple


def _to_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _normalize_text(text: str) -> str:
    text = _to_str(text)
    text = text.replace("\xa0", " ").replace("\u3000", " ")
    text = re.sub(r"\s+", " ", text)
    return text.strip().lower()


def _contains_any(text: str, keywords: List[str]) -> bool:
    text = _normalize_text(text)
    return any(k.lower() in text for k in keywords)


def _dedup_keep_order(items: List[str]) -> List[str]:
    out: List[str] = []
    seen = set()

    for item in items:
        item = _to_str(item).strip()
        if not item or item in seen:
            continue

        seen.add(item)
        out.append(item)

    return out


class AdviceAgent:
    """
    规则型 AI 初审建议 Agent。

    重点：
    - 不固定 TISAX，仍然是通用版。
    - 识别控制项类型、证据类型、覆盖维度、缺口方向。
    - 有明确缺口时输出“建议补证清单”。
    - 没有明确缺口时只输出“可选增强证据（非必补）”，避免误导成全部都要补。
    """

    SUMMARY_START = "[AI挂接摘要-开始]"
    SUMMARY_END = "[AI挂接摘要-结束]"

    FAMILY_LABELS = {
        "contract_policy_commitment": "合同约束/保密承诺/政策遵守",
        "awareness_training": "培训与意识",
        "asset_classification": "资产识别与分类分级",
        "malware_protection": "恶意软件防护",
        "event_logs": "日志记录与分析",
        "incident_handling": "事件与应急管理",
        "weakness_vulnerability": "弱点/漏洞管理",
        "access_control": "访问控制",
        "backup_recovery": "备份与恢复",
        "supplier_management": "供应商/外部服务管理",
        "physical_security": "物理与环境安全",
        "policy_governance": "制度治理",
        "privacy_data_protection": "隐私与数据保护",
        "cryptography": "密码与加密管理",
        "business_continuity": "业务连续性",
        "change_management": "变更管理",
        "generic": "通用控制项",
        "unknown": "未知类型",
    }

    FAMILY_REQUIRED_DIMS = {
        "contract_policy_commitment": ["制度/要求", "签署/承诺记录", "范围/对象"],
        "awareness_training": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "asset_classification": ["制度/要求", "资产清单", "分类分级标准", "责任/审批", "复核/闭环"],
        "malware_protection": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "event_logs": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "incident_handling": ["制度/要求", "执行记录", "责任/审批", "复核/闭环"],
        "weakness_vulnerability": ["制度/要求", "执行记录", "责任/审批", "复核/闭环"],
        "access_control": ["制度/要求", "执行记录", "责任/审批", "复核/闭环"],
        "backup_recovery": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "supplier_management": ["制度/要求", "责任/审批", "执行记录", "复核/闭环"],
        "physical_security": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "policy_governance": ["制度/要求", "责任/审批", "发布/宣贯", "复核/闭环"],
        "privacy_data_protection": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "cryptography": ["制度/要求", "执行记录", "责任/审批", "复核/闭环"],
        "business_continuity": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "change_management": ["制度/要求", "执行记录", "责任/审批", "复核/闭环"],
        "generic": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
        "unknown": ["制度/要求", "执行记录", "范围/对象", "复核/闭环"],
    }

    FAMILY_KEYWORDS = {
        "contract_policy_commitment": [
            "contractually bound",
            "contract",
            "employment contract",
            "confidentiality",
            "non-disclosure",
            "nda",
            "comply with policies",
            "security policies",
            "obliged",
            "commitment",
            "agreement",
            "合同",
            "劳动合同",
            "保密协议",
            "保密承诺",
            "承诺书",
            "信息安全承诺",
            "员工承诺",
            "政策遵守",
            "遵守信息安全",
            "遵守安全政策",
            "签署",
            "签字",
            "入职签署",
        ],
        "awareness_training": [
            "training",
            "awareness",
            "trained",
            "sensitized",
            "培训",
            "意识",
            "宣贯",
            "员工手册",
            "员工",
            "考试",
            "测验",
            "签到",
            "参训",
            "教育",
            "课程",
        ],
        "asset_classification": [
            "asset",
            "assets",
            "classification",
            "classified",
            "protection needs",
            "信息资产",
            "资产",
            "分类",
            "分级",
            "资产清单",
            "资产台账",
            "保护需求",
        ],
        "malware_protection": [
            "malware",
            "virus",
            "anti-virus",
            "antivirus",
            "endpoint",
            "恶意软件",
            "病毒",
            "防病毒",
            "杀毒",
            "木马",
            "终端安全",
            "病毒库",
        ],
        "event_logs": [
            "log",
            "logs",
            "logging",
            "event",
            "monitoring",
            "日志",
            "审计日志",
            "事件日志",
            "日志检查",
            "日志评审",
            "监控",
            "告警",
            "分析",
        ],
        "incident_handling": [
            "incident",
            "crisis",
            "emergency",
            "response",
            "事件",
            "应急",
            "安全事件",
            "响应",
            "处置",
            "上报",
            "危机",
        ],
        "weakness_vulnerability": [
            "weakness",
            "vulnerability",
            "vulnerabilities",
            "patch",
            "漏洞",
            "弱点",
            "风险",
            "缺陷",
            "整改",
            "扫描",
            "复测",
        ],
        "access_control": [
            "access",
            "account",
            "identity",
            "password",
            "privilege",
            "权限",
            "账号",
            "账户",
            "访问控制",
            "口令",
            "密码",
            "授权",
            "登录",
        ],
        "backup_recovery": [
            "backup",
            "restore",
            "recovery",
            "备份",
            "恢复",
            "还原",
            "容灾",
        ],
        "supplier_management": [
            "supplier",
            "external",
            "third party",
            "outsourcing",
            "vendor",
            "供应商",
            "外包",
            "第三方",
            "外部服务",
            "服务商",
        ],
        "physical_security": [
            "physical",
            "facility",
            "entry",
            "visitor",
            "security zone",
            "物理",
            "门禁",
            "访客",
            "机房",
            "区域",
            "安防",
            "进入",
        ],
        "policy_governance": [
            "policy",
            "policies",
            "governance",
            "organization",
            "management system",
            "制度",
            "方针",
            "治理",
            "组织",
            "职责",
            "管理体系",
            "管理规定",
        ],
        "privacy_data_protection": [
            "privacy",
            "personal data",
            "data protection",
            "gdpr",
            "pipl",
            "隐私",
            "个人信息",
            "个人数据",
            "数据保护",
            "个人信息保护",
        ],
        "cryptography": [
            "cryptographic",
            "cryptography",
            "encryption",
            "key management",
            "加密",
            "密码",
            "密钥",
            "证书",
            "算法",
        ],
        "business_continuity": [
            "continuity",
            "bcp",
            "drp",
            "disaster recovery",
            "业务连续性",
            "连续性",
            "灾备",
            "应急演练",
            "恢复演练",
        ],
        "change_management": [
            "change",
            "release",
            "变更",
            "发布",
            "上线",
            "回退",
            "审批变更",
        ],
    }

    DIMENSION_KEYWORDS = {
        "制度/要求": [
            "制度",
            "规定",
            "程序",
            "流程",
            "办法",
            "规范",
            "手册",
            "policy",
            "procedure",
            "rule",
            "requirement",
            "shall",
            "should",
            "must",
        ],
        "签署/承诺记录": [
            "签署",
            "签字",
            "签收",
            "承诺书",
            "保密协议",
            "劳动合同",
            "合同",
            "nda",
            "non-disclosure",
            "confidentiality agreement",
            "employment contract",
            "signed",
            "signature",
            "acknowledgement",
            "commitment",
        ],
        "执行记录": [
            "记录",
            "台账",
            "签到",
            "考试",
            "测验",
            "检查",
            "评审",
            "审核",
            "报告",
            "工单",
            "处置",
            "扫描",
            "导出",
            "截图",
            "日志",
            "清单",
            "record",
            "report",
            "ticket",
            "review",
            "check",
            "assessment",
        ],
        "范围/对象": [
            "范围",
            "适用",
            "对象",
            "部门",
            "岗位",
            "人员",
            "员工",
            "系统",
            "资产",
            "设备",
            "业务",
            "数据",
            "project",
            "employee",
            "staff",
            "system",
            "asset",
            "scope",
        ],
        "责任/审批": [
            "责任",
            "负责人",
            "责任人",
            "审批",
            "批准",
            "审核人",
            "复核人",
            "申请人",
            "执行人",
            "owner",
            "approver",
            "approval",
            "responsible",
        ],
        "复核/闭环": [
            "复核",
            "复查",
            "复测",
            "验证",
            "整改",
            "关闭",
            "闭环",
            "跟踪",
            "确认",
            "纠正",
            "改进",
            "close",
            "closed",
            "closure",
            "verify",
            "verification",
            "remediation",
            "corrective",
        ],
        "资产清单": [
            "资产清单",
            "资产台账",
            "信息资产台账",
            "资产编号",
            "资产名称",
            "asset inventory",
            "asset list",
            "inventory",
        ],
        "分类分级标准": [
            "分类分级",
            "分类标准",
            "分级标准",
            "保护等级",
            "保护需求",
            "classification criteria",
            "protection needs",
        ],
        "发布/宣贯": [
            "发布",
            "宣贯",
            "通知",
            "邮件",
            "培训",
            "公告",
            "知悉",
            "publication",
            "announcement",
            "notification",
        ],
    }

    def analyze(
        self,
        file_name: str,
        evidence_text: str,
        target_title: str,
        target_description: str,
        score: float,
    ) -> Dict[str, Any]:
        file_name = _to_str(file_name)
        evidence_text = _to_str(evidence_text)
        target_title = _to_str(target_title)
        target_description = _to_str(target_description)
        score_f = _safe_float(score)

        target_text = f"{target_title}\n{target_description}"
        evidence_full_text = f"{file_name}\n{evidence_text}"

        target_family = self._detect_family(target_text, default="generic")
        evidence_family = self._detect_family(evidence_full_text, default="generic")

        present_dims = self._detect_present_dims(evidence_full_text)

        required_dims = self.FAMILY_REQUIRED_DIMS.get(
            target_family,
            self.FAMILY_REQUIRED_DIMS["generic"],
        )

        missing_dims = [x for x in required_dims if x not in present_dims]
        partial_dims: List[str] = []

        role = self._decide_role(
            target_family=target_family,
            evidence_family=evidence_family,
            score=score_f,
            present_dims=present_dims,
            missing_dims=missing_dims,
        )

        recommendations = self._build_recommendations(
            family=target_family,
            missing_dims=missing_dims,
            partial_dims=partial_dims,
        )

        uplift_low, uplift_high = self._estimate_uplift(
            role=role,
            score=score_f,
            missing_dims=missing_dims,
            partial_dims=partial_dims,
        )

        verdict = self._build_verdict(
            role=role,
            score=score_f,
            missing_dims=missing_dims,
            target_family=target_family,
            evidence_family=evidence_family,
        )

        return {
            "role": role,
            "target_family": target_family,
            "target_family_cn": self.FAMILY_LABELS.get(target_family, target_family),
            "evidence_family": evidence_family,
            "evidence_family_cn": self.FAMILY_LABELS.get(evidence_family, evidence_family),
            "verdict": verdict,
            "present_dims": present_dims,
            "partial_dims": partial_dims,
            "missing_dims": missing_dims,
            "recommendations": recommendations,
            "uplift_low": uplift_low,
            "uplift_high": uplift_high,
        }

    def summarize_for_observation(
        self,
        target_label: str,
        records: List[Dict[str, Any]],
        high_threshold: float = 0.70,
        medium_threshold: float = 0.40,
    ) -> str:
        target_label = _to_str(target_label).strip()
        records = list(records or [])

        ordered = sorted(records, key=lambda x: _safe_float(x.get("score")), reverse=True)

        primary_items = [x for x in ordered if _to_str(x.get("role")) == "primary"]
        supporting_items = [x for x in ordered if _to_str(x.get("role")) == "supporting"]
        mismatch_items = [x for x in ordered if _to_str(x.get("role")) == "mismatch"]

        primary_gaps = self._collect_all_gaps(primary_items)
        has_required_gaps = bool(primary_gaps)

        lines: List[str] = []

        lines.append(self.SUMMARY_START)
        lines.append("[AI挂接摘要]")
        lines.append(f"当前控制项：{target_label}")
        lines.append(f"关联证据数量：{len(ordered)}")
        lines.append("")

        if primary_items:
            lines.append("主证据建议：")

            for idx, item in enumerate(primary_items, start=1):
                file_name = _to_str(item.get("file_name"))
                score = _safe_float(item.get("score"))
                confidence = self._confidence_label(score, high_threshold, medium_threshold)
                verdict = _to_str(item.get("verdict")) or "可作为初步主支撑证据，建议人工确认。"

                present = item.get("present_dims") or []
                missing = item.get("missing_dims") or []
                partial = item.get("partial_dims") or []
                pending = _dedup_keep_order(partial + missing)

                lines.append(f"{idx}. {file_name}（主证据，{confidence}，score={score:.4f}）")
                lines.append(f"   - 结论：{verdict}")

                if present:
                    lines.append(f"   - 已覆盖：{'、'.join(present)}")
                else:
                    lines.append("   - 已覆盖：暂无明显覆盖点")

                if pending:
                    lines.append(f"   - 待补方向：{'、'.join(pending)}")
                else:
                    lines.append("   - 待补方向：暂无明确必补缺口")

            lines.append("")

        if supporting_items:
            lines.append("辅助证据：")

            for idx, item in enumerate(supporting_items, start=1):
                file_name = _to_str(item.get("file_name"))
                score = _safe_float(item.get("score"))
                lines.append(
                    f"{idx}. {file_name}（score={score:.4f}）：可作为辅助支撑，建议结合主证据人工确认。"
                )

            lines.append("")

        if mismatch_items:
            lines.append("待人工确认：")

            for idx, item in enumerate(mismatch_items, start=1):
                file_name = _to_str(item.get("file_name"))
                score = _safe_float(item.get("score"))
                target_family_cn = _to_str(item.get("target_family_cn"))
                evidence_family_cn = _to_str(item.get("evidence_family_cn"))

                lines.append(
                    f"{idx}. {file_name}（score={score:.4f}）：相关性偏弱或可能跨控制项，建议人工确认是否保留。"
                )

                if target_family_cn or evidence_family_cn:
                    lines.append(
                        f"   - 识别类型：目标控制项偏向“{target_family_cn or '未知'}”，证据内容偏向“{evidence_family_cn or '未知'}”。"
                    )

            lines.append("")

        lines.append("总体建议：")
        lines.extend(self._build_overall_summary(primary_items, supporting_items, mismatch_items))
        lines.append("")

        supplement_steps = self._build_overall_supplement_steps(
            primary_items,
            supporting_items,
            mismatch_items,
        )

        if supplement_steps:
            if has_required_gaps:
                lines.append("建议补证清单：")
                lines.append("说明：以下为针对当前缺口的补证建议，不代表所有材料都必须同时补齐。")
            else:
                lines.append("可选增强证据（非必补）：")
                lines.append("说明：当前未识别到明确必补缺口，以下材料用于增强证明力，可按审计要求择一或抽样补充。")

            for idx, step in enumerate(supplement_steps, start=1):
                lines.append(f"{idx}. {step}")

            lines.append("")

        priority = self._build_priority_direction(primary_items, supporting_items, mismatch_items)

        if priority:
            if has_required_gaps:
                lines.append("优先补证方向：")
                for item in priority:
                    lines.append(f"- {item}")
                lines.append("")
            else:
                lines.append("优先增强方向：")
                for item in priority:
                    lines.append(f"- {item}")
                lines.append("")

        lines.append("说明：以上为规则型 AI 初审建议，仅用于证据整理、补证优先级和人工复核参考，不等同于最终审计结论。")
        lines.append(self.SUMMARY_END)

        return "\n".join(lines)

    def replace_summary_section(self, existing_observation: str, new_summary: str) -> str:
        existing = _to_str(existing_observation).strip()
        new_summary = _to_str(new_summary).strip()

        if not existing:
            return new_summary

        pattern = re.compile(
            re.escape(self.SUMMARY_START) + r".*?" + re.escape(self.SUMMARY_END),
            flags=re.DOTALL,
        )

        if pattern.search(existing):
            return pattern.sub(new_summary, existing).strip()

        return f"{existing}\n\n{new_summary}".strip()

    def _detect_family(self, text: str, default: str = "generic") -> str:
        text_norm = _normalize_text(text)

        best_family = default
        best_score = 0

        for family, keywords in self.FAMILY_KEYWORDS.items():
            hit = 0

            for keyword in keywords:
                if keyword.lower() in text_norm:
                    hit += 1

            if hit > best_score:
                best_score = hit
                best_family = family

        return best_family if best_score > 0 else default

    def _detect_present_dims(self, evidence_text: str) -> List[str]:
        text = _normalize_text(evidence_text)

        out: List[str] = []

        for dim, keywords in self.DIMENSION_KEYWORDS.items():
            if any(keyword.lower() in text for keyword in keywords):
                out.append(dim)

        if "范围/对象" not in out and _contains_any(
            text,
            ["员工", "人员", "岗位", "部门", "项目成员", "管理员", "staff", "employee", "personnel"],
        ):
            out.append("范围/对象")

        return _dedup_keep_order(out)

    def _families_compatible(self, target_family: str, evidence_family: str) -> bool:
        if target_family == evidence_family:
            return True

        if target_family in ("generic", "unknown") or evidence_family in ("generic", "unknown"):
            return True

        compatible_groups = [
            {"contract_policy_commitment", "awareness_training", "policy_governance", "privacy_data_protection"},
            {"event_logs", "incident_handling", "weakness_vulnerability"},
            {"malware_protection", "incident_handling", "weakness_vulnerability"},
            {"asset_classification", "supplier_management", "access_control"},
            {"access_control", "physical_security"},
            {"backup_recovery", "business_continuity"},
            {"cryptography", "access_control", "privacy_data_protection"},
            {"change_management", "access_control", "event_logs"},
        ]

        for group in compatible_groups:
            if target_family in group and evidence_family in group:
                return True

        return False

    def _decide_role(
        self,
        target_family: str,
        evidence_family: str,
        score: float,
        present_dims: List[str],
        missing_dims: List[str],
    ) -> str:
        compatible = self._families_compatible(target_family, evidence_family)
        has_core_content = bool(present_dims)
        missing_count = len(missing_dims)

        if compatible and score >= 0.70:
            return "primary"

        if compatible and score >= 0.60 and has_core_content:
            return "primary"

        if compatible and score >= 0.50 and has_core_content and missing_count <= 2:
            return "primary"

        if compatible and score >= 0.40:
            return "supporting"

        if score >= 0.50:
            return "mismatch"

        return "supporting"

    def _build_verdict(
        self,
        role: str,
        score: float,
        missing_dims: List[str],
        target_family: str,
        evidence_family: str,
    ) -> str:
        if role == "mismatch":
            return "相关性偏弱或可能跨控制项，建议人工确认是否保留，不建议直接据此判定合规。"

        if role == "supporting":
            return "可作为辅助证据，但单独支撑力度不足，建议结合主证据人工复核。"

        if missing_dims:
            return "可作为初步主支撑证据，但证据包仍不完整，建议补证后再确认。"

        if score >= 0.75:
            return "可作为较强主支撑证据，建议人工抽查确认。"

        return "可作为初步主支撑证据，建议人工确认。"

    def _build_recommendations(
        self,
        family: str,
        missing_dims: List[str],
        partial_dims: List[str],
    ) -> List[Dict[str, Any]]:
        gaps = _dedup_keep_order(partial_dims + missing_dims)

        recommendations: List[Dict[str, Any]] = []

        for gap in gaps:
            landing_steps = self._build_landing_steps_for_gap(family, gap)
            uplift_low, uplift_high = self._gap_uplift(gap)

            recommendations.append(
                {
                    "gap": gap,
                    "text": self._gap_text(gap),
                    "landing_steps": landing_steps,
                    "uplift_low": uplift_low,
                    "uplift_high": uplift_high,
                }
            )

        return recommendations

    def _gap_text(self, gap: str) -> str:
        mapping = {
            "制度/要求": "补充正式制度、流程、标准或管理要求。",
            "签署/承诺记录": "补充员工已签署合同条款、保密协议或信息安全承诺书的记录。",
            "执行记录": "补充当前审核周期内的实际执行记录。",
            "范围/对象": "补充控制项覆盖范围、对象清单或适用说明。",
            "责任/审批": "补充责任分工、审批记录或授权确认材料。",
            "复核/闭环": "补充复核记录、整改跟踪和关闭确认材料。",
            "资产清单": "补充资产台账或信息资产清单。",
            "分类分级标准": "补充分类分级标准和实际应用样例。",
            "发布/宣贯": "补充制度发布、宣贯或通知证明。",
        }

        return mapping.get(gap, f"补充“{gap}”相关支撑证据。")

    def _gap_uplift(self, gap: str) -> Tuple[float, float]:
        mapping = {
            "制度/要求": (0.05, 0.08),
            "签署/承诺记录": (0.08, 0.12),
            "执行记录": (0.08, 0.12),
            "范围/对象": (0.04, 0.07),
            "责任/审批": (0.04, 0.08),
            "复核/闭环": (0.03, 0.06),
            "资产清单": (0.06, 0.10),
            "分类分级标准": (0.06, 0.10),
            "发布/宣贯": (0.03, 0.06),
        }

        return mapping.get(gap, (0.03, 0.05))

    def _estimate_uplift(
        self,
        role: str,
        score: float,
        missing_dims: List[str],
        partial_dims: List[str],
    ) -> Tuple[float, float]:
        gaps = _dedup_keep_order(partial_dims + missing_dims)

        if not gaps:
            return (0.00, 0.02)

        lows = []
        highs = []

        for gap in gaps:
            low, high = self._gap_uplift(gap)
            lows.append(low)
            highs.append(high)

        low_total = min(0.20, sum(lows))
        high_total = min(0.30, sum(highs))

        if role == "mismatch":
            low_total = min(low_total, 0.05)
            high_total = min(high_total, 0.08)

        return (round(low_total, 2), round(high_total, 2))

    def _confidence_label(self, score: float, high_threshold: float, medium_threshold: float) -> str:
        if score >= high_threshold:
            return "高置信度"

        if score >= medium_threshold:
            return "中置信度"

        return "低置信度"

    def _build_overall_summary(
        self,
        primary_items: List[Dict[str, Any]],
        supporting_items: List[Dict[str, Any]],
        mismatch_items: List[Dict[str, Any]],
    ) -> List[str]:
        lines: List[str] = []

        if primary_items:
            lines.append(f"- 主证据 {len(primary_items)} 份：可作为当前控制项的主要支撑。")
        else:
            lines.append("- 主证据 0 份：当前尚未识别到足够直接的主支撑证据。")

        if supporting_items:
            lines.append(f"- 辅助证据 {len(supporting_items)} 份：建议作为补充材料，不建议单独作为合规判断依据。")

        if mismatch_items:
            lines.append(f"- 待人工确认 {len(mismatch_items)} 份：可能存在跨控制项关联，建议人工确认是否保留挂接。")

        all_gaps = self._collect_all_gaps(primary_items)

        if all_gaps:
            lines.append(f"- 当前主要待补方向：{'、'.join(all_gaps)}。")
        else:
            lines.append("- 当前未发现明确必补缺口，建议人工抽查证据真实性、时间范围和适用范围。")

        return lines

    def _collect_all_gaps(self, records: List[Dict[str, Any]]) -> List[str]:
        gaps: List[str] = []

        for item in records:
            for dim in item.get("partial_dims") or []:
                gaps.append(_to_str(dim))

            for dim in item.get("missing_dims") or []:
                gaps.append(_to_str(dim))

        return _dedup_keep_order(gaps)

    def _collect_family_for_overall(self, records: List[Dict[str, Any]]) -> str:
        for item in records:
            family = _to_str(item.get("target_family")).strip()

            if family and family not in ("unknown", "generic"):
                return family

        return "generic"

    def _build_overall_supplement_steps(
        self,
        primary_items: List[Dict[str, Any]],
        supporting_items: List[Dict[str, Any]],
        mismatch_items: List[Dict[str, Any]],
    ) -> List[str]:
        source_items = primary_items or supporting_items or mismatch_items

        if not source_items:
            return [
                "补充当前审核周期内能够直接证明控制项已执行的证据，例如执行记录、审批记录、系统截图、台账导出或复核记录。",
                "证据中建议包含：执行时间、责任人、适用范围、执行结果、复核人和关闭结论。",
            ]

        family = self._collect_family_for_overall(source_items)
        all_gaps = self._collect_all_gaps(primary_items)

        if not all_gaps:
            return self._build_no_gap_but_strengthen_steps(family)

        steps: List[str] = []

        for gap in all_gaps:
            steps.extend(self._build_landing_steps_for_gap(family, gap))

        return _dedup_keep_order(steps)[:6]

    def _build_no_gap_but_strengthen_steps(self, family: str) -> List[str]:
        """
        没有明确缺口时，只输出“可选增强证据”。
        这里不是要求全部补齐，只是给审计员一个抽查/增强方向。
        """

        if family == "contract_policy_commitment":
            return [
                "可抽样补充员工签署台账，字段建议包含：员工姓名、部门、岗位、入职日期、签署文件名称、签署日期、签署状态。",
                "可抽样补充劳动合同、保密协议、信息安全承诺书或员工手册签收确认记录，用于证明员工已被合同或承诺约束。",
                "如审计要求更高，可补充覆盖率统计，说明应签署人数、已签署人数、未签署人数和补签计划。",
            ]

        if family == "awareness_training":
            return [
                "可抽样补充培训签到表、考试/测验结果或学习平台导出记录，用于证明培训不是仅停留在制度层面。",
                "如审计要求更高，可补充培训覆盖率统计，说明应参训人数、实际参训人数、未参训人员和补训安排。",
            ]

        if family == "asset_classification":
            return [
                "可抽样补充资产台账记录，证明分类分级标准已应用到具体资产。",
                "如审计要求更高，可补充资产清单复核记录，说明复核时间、复核人、变更项和确认结论。",
            ]

        if family == "event_logs":
            return [
                "可抽样补充日志平台截图或日志检查记录，证明日志已采集、已分析、异常已处理。",
                "如审计要求更高，可补充异常日志处置闭环记录，说明告警、处置、复核和关闭过程。",
            ]

        if family == "weakness_vulnerability":
            return [
                "可抽样补充弱点/漏洞清单，字段建议包含：问题名称、风险等级、影响资产、发现时间、整改责任人和当前状态。",
                "如审计要求更高，可补充整改复测记录或关闭确认材料。",
            ]

        if family == "access_control":
            return [
                "可抽样补充账号开通、变更、删除记录，证明权限申请、审批、执行过程可追溯。",
                "如审计要求更高，可补充权限定期复核记录或异常权限整改记录。",
            ]

        return [
            "可抽样补充当前审核周期内的执行记录、复核记录或审批确认材料，用于增强证据证明力。",
            "证据中建议包含：执行时间、责任人、适用范围、执行结果、复核人和关闭结论。",
        ]

    def _build_priority_direction(
        self,
        primary_items: List[Dict[str, Any]],
        supporting_items: List[Dict[str, Any]],
        mismatch_items: List[Dict[str, Any]],
    ) -> List[str]:
        source_items = primary_items or supporting_items or mismatch_items
        gaps = self._collect_all_gaps(primary_items)

        if not gaps:
            family = self._collect_family_for_overall(source_items)

            if family == "contract_policy_commitment":
                return ["签署台账抽样", "签署文件抽样", "覆盖率统计"]

            if family == "awareness_training":
                return ["培训签到/考试记录抽样", "培训覆盖率统计"]

            return ["执行记录抽样", "复核记录抽样"]

        priority_order = [
            "签署/承诺记录",
            "执行记录",
            "复核/闭环",
            "范围/对象",
            "责任/审批",
            "资产清单",
            "分类分级标准",
            "制度/要求",
            "发布/宣贯",
        ]

        result = []

        for p in priority_order:
            if p in gaps:
                result.append(p)

        for gap in gaps:
            if gap not in result:
                result.append(gap)

        return result[:5]

    def _build_landing_steps_for_gap(self, family: str, gap_name: str) -> List[str]:
        family_specific_steps = {
            "contract_policy_commitment": {
                "签署/承诺记录": [
                    "补充员工签署台账，字段至少包含：员工姓名、部门、岗位、入职日期、签署文件名称、签署日期、签署状态。",
                    "补充劳动合同、保密协议或信息安全承诺书的抽样扫描件，证明员工已被合同或承诺书约束。",
                    "补充员工手册签收确认记录或制度知悉确认记录，证明员工已知悉并承诺遵守信息安全政策。",
                ],
                "范围/对象": [
                    "补充签署对象清单，至少覆盖正式员工、外包人员、实习生、关键岗位人员和系统管理员。",
                    "说明哪些人员不适用签署要求，并给出不适用原因。",
                ],
                "责任/审批": [
                    "补充入职签署流程或 HR 审批流程截图，明确由谁收集、谁复核、谁归档。",
                    "补充合同/保密协议模板审批记录，证明模板内容经过法务、人事或信息安全负责人确认。",
                ],
                "复核/闭环": [
                    "补充签署完整性复核记录，字段至少包含：复核日期、复核人、抽查范围、缺失人员、整改责任人、关闭结论。",
                    "对未签署或缺失扫描件的人员，补充补签记录和最终归档证明。",
                ],
                "制度/要求": [
                    "补充员工信息安全义务条款，明确员工需遵守信息安全政策、保密要求、违规责任和离职后的保密义务。",
                    "补充劳动合同、保密协议或员工手册中的信息安全条款截图或摘录。",
                ],
            },
            "awareness_training": {
                "执行记录": [
                    "补充培训签到表，字段至少包含：姓名、部门、岗位、培训日期、培训主题、签到方式。",
                    "补充培训考试或测验结果，字段至少包含：人员名单、分数、合格线、未通过人员补训记录。",
                    "补充培训课件、培训通知或培训照片，证明培训内容覆盖该控制项要求。",
                ],
                "范围/对象": [
                    "补充培训覆盖范围清单，区分新员工、普通员工、关键岗位、项目成员、系统管理员等对象。",
                    "补充应参训人数、实际参训人数、未参训人员名单和补训安排。",
                ],
                "复核/闭环": [
                    "补充培训效果复核记录，例如考试通过率统计、问卷结果、抽查访谈记录。",
                    "对未参加或未通过人员补充补训记录和最终通过证明。",
                ],
                "责任/审批": [
                    "补充年度培训计划审批记录，明确培训负责人、审批人、培训周期和覆盖对象。",
                ],
                "发布/宣贯": [
                    "补充培训通知、制度宣贯邮件、学习平台发布截图或会议通知。",
                ],
            },
            "event_logs": {
                "执行记录": [
                    "补充日志检查记录，字段至少包含：检查日期、检查人、系统名称、日志类型、异常数量、处理结论。",
                    "补充日志平台截图或导出报表，证明关键系统日志确实被采集和分析。",
                ],
                "范围/对象": [
                    "补充日志接入范围清单，字段至少包含：系统名称、设备类型、日志类型、责任人、是否接入、未接入原因。",
                ],
                "复核/闭环": [
                    "补充异常日志处置闭环记录，字段至少包含：异常时间、异常类型、影响系统、处置人、处置动作、关闭时间。",
                    "如有告警，补充告警工单、升级记录、复核确认或关闭截图。",
                ],
            },
            "incident_handling": {
                "执行记录": [
                    "补充安全事件处置单，字段至少包含：事件编号、发现时间、上报时间、影响范围、处置过程、恢复时间、责任人。",
                    "补充事件分级记录，说明事件严重级别、判断依据和响应时限。",
                ],
                "复核/闭环": [
                    "补充事件复盘报告，内容至少包含：根因分析、影响评估、整改措施、责任人、计划完成时间。",
                    "补充整改关闭证明，例如复测记录、关闭审批、管理层确认或跟踪台账。",
                ],
            },
            "weakness_vulnerability": {
                "执行记录": [
                    "补充弱点/漏洞清单，字段至少包含：问题名称、风险等级、影响资产、发现时间、发现来源、整改责任人。",
                    "补充原始扫描报告或人工核查记录，证明弱点来源可追溯。",
                ],
                "复核/闭环": [
                    "补充整改跟踪表，字段至少包含：整改措施、整改责任人、计划完成时间、实际完成时间、当前状态。",
                    "补充复测报告，证明弱点已修复或已形成风险接受记录。",
                ],
            },
            "malware_protection": {
                "执行记录": [
                    "补充终端安全平台查杀记录，字段至少包含：主机名、IP、检测时间、病毒名称、处理动作、处理结果。",
                    "补充病毒库更新记录，证明防病毒能力保持更新。",
                ],
                "复核/闭环": [
                    "补充病毒告警处置单，说明告警是否确认、是否隔离、是否清除、是否复查。",
                    "补充月度防病毒检查报告或异常处置汇总表。",
                ],
            },
            "access_control": {
                "执行记录": [
                    "补充账号开通、变更、删除记录，字段至少包含：申请人、账号、权限内容、审批人、执行人、执行时间。",
                    "补充离职人员账号回收记录，证明权限及时撤销。",
                ],
                "责任/审批": [
                    "补充权限审批单或审批流截图，证明权限授予经过授权。",
                    "补充权限申请理由、审批意见和审批时间。",
                ],
                "复核/闭环": [
                    "补充权限定期复核记录，字段至少包含：复核范围、复核人、异常权限、整改动作、关闭结论。",
                ],
            },
            "asset_classification": {
                "资产清单": [
                    "补充信息资产台账导出文件，字段至少包含：资产名称、资产类型、所属部门、责任人、分类、分级、更新时间。",
                    "补充资产台账维护记录，说明新增、变更、下线资产如何更新。",
                ],
                "分类分级标准": [
                    "补充资产分类分级标准，明确分类维度、分级规则、保护要求和审批流程。",
                    "补充资产分类分级样例，证明标准已落到具体资产。",
                ],
                "复核/闭环": [
                    "补充年度或季度资产清单复核记录，说明复核人、复核范围、变更项和确认结论。",
                ],
            },
            "supplier_management": {
                "执行记录": [
                    "补充供应商评估记录，字段至少包含：供应商名称、服务内容、评估日期、评估人、风险等级、处理结论。",
                ],
                "责任/审批": [
                    "补充供应商准入审批记录或合同审批记录，证明外部服务经过授权和评估。",
                ],
                "复核/闭环": [
                    "补充供应商年度复评记录、整改跟踪表或风险接受审批记录。",
                ],
            },
            "privacy_data_protection": {
                "执行记录": [
                    "补充个人信息处理活动记录，字段至少包含：处理目的、数据类型、数据主体、系统名称、责任部门、保存期限。",
                    "补充个人信息访问、导出、删除或授权审批记录。",
                ],
                "范围/对象": [
                    "补充个人信息清单，说明涉及哪些数据类型、业务场景、系统和责任部门。",
                ],
                "复核/闭环": [
                    "补充个人信息保护检查记录、问题整改跟踪表或合规复核确认记录。",
                ],
            },
            "cryptography": {
                "执行记录": [
                    "补充加密策略执行记录，例如系统加密配置截图、证书配置截图、密钥轮换记录。",
                ],
                "责任/审批": [
                    "补充密钥申请、变更、吊销或审批记录，明确申请人、审批人和执行人。",
                ],
                "复核/闭环": [
                    "补充密钥或证书定期复核记录，说明过期、弱算法或异常配置是否已处理。",
                ],
            },
        }

        if family in family_specific_steps and gap_name in family_specific_steps[family]:
            return family_specific_steps[family][gap_name]

        return self._generic_steps_for_gap(gap_name)

    def _generic_steps_for_gap(self, gap_name: str) -> List[str]:
        if gap_name == "制度/要求":
            return [
                "补充正式发布的制度/流程文件，文件中需包含版本号、发布日期、适用范围、责任部门和审批记录。",
                "补充制度发布或宣贯证明，例如发布邮件、制度平台截图、培训通知或会议纪要。",
            ]

        if gap_name == "签署/承诺记录":
            return [
                "补充签署台账，字段至少包含：人员姓名、部门、岗位、签署文件、签署日期、签署状态。",
                "补充已签署文件的抽样扫描件，例如保密协议、承诺书、合同条款签署页或制度知悉确认记录。",
            ]

        if gap_name == "执行记录":
            return [
                "补充当前审核周期内的实际执行记录，不能只提交制度文件。",
                "执行记录至少包含：执行时间、执行人、执行对象、执行内容、执行结果、异常情况和处理结论。",
                "可补充系统导出记录、检查表、工单截图、签到表、扫描报告、评审记录或处理台账。",
            ]

        if gap_name == "范围/对象":
            return [
                "补充覆盖范围清单，说明该控制项覆盖哪些部门、系统、人员、资产、业务流程或数据类型。",
                "清单中建议包含：对象名称、所属部门、责任人、是否纳入控制范围、未纳入原因。",
            ]

        if gap_name == "责任/审批":
            return [
                "补充责任分工或审批记录，明确申请人、执行人、审批人、复核人和最终责任部门。",
                "可补充审批流截图、邮件审批记录、签字版审批单或会议确认记录。",
            ]

        if gap_name == "复核/闭环":
            return [
                "补充复核记录，说明该控制项执行后是否经过二次确认。",
                "复核记录至少包含：复核时间、复核人、复核对象、发现问题、整改要求、整改责任人、完成时间和关闭结论。",
                "如发现问题，需补充整改闭环证明，例如整改跟踪表、复测记录、关闭确认单或管理层确认记录。",
            ]

        if gap_name == "资产清单":
            return [
                "补充信息资产台账导出文件，至少包含资产名称、资产类型、所属部门、责任人、分类分级、更新时间。",
                "补充资产清单复核记录，证明资产台账不是一次性文件，而是按周期维护。",
            ]

        if gap_name == "分类分级标准":
            return [
                "补充分类分级标准文件，明确分类维度、分级规则、保护要求和审批流程。",
                "补充至少 3 条资产分类分级样例，证明分类分级规则已实际应用到资产台账。",
            ]

        if gap_name == "发布/宣贯":
            return [
                "补充制度发布或宣贯记录，例如通知邮件、会议纪要、培训记录或平台发布截图。",
                "记录中建议包含发布时间、发布对象、发布内容、确认方式和负责人。",
            ]

        return [
            "补充能直接证明该控制项已执行的记录类证据，例如审批单、执行记录、系统截图、台账导出或复核记录。",
            "证据中建议包含：责任部门、责任人、执行时间、适用范围、执行结果、审批/复核人。",
        ]