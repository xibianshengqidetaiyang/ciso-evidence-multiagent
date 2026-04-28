from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agents.classifier_agent import ClassifierAgent
from agents.advice_agent import AdviceAgent
from tools.ciso_api import CisoApiClient
from tools.document_parser import parse_document, is_empty_evidence, is_noise_evidence


# ============================================================
# 基础配置
# ============================================================

INPUT_DIR = Path(os.getenv("EVIDENCE_INPUT_DIR", r"D:\evidence_demo\input"))

OUTPUT_MANIFEST = Path(os.getenv("IMPORT_REVIEW_OUTPUT", "import_review_manifest.json"))
REVIEW_DECISION_OUTPUT = Path(os.getenv("REVIEW_DECISION_OUTPUT", "review_decision_manifest.json"))

ASSESSMENT_ID = os.getenv("ASSESSMENT_ID", "").strip()
if not ASSESSMENT_ID:
    raise RuntimeError("缺少 ASSESSMENT_ID，请先设置环境变量 ASSESSMENT_ID")

APPLY_IMPORT = os.getenv("APPLY_IMPORT", "1") == "1"
REUSE_EXISTING_EVIDENCE = os.getenv("REUSE_EXISTING_EVIDENCE", "1") == "1"

DEBUG_MODE = os.getenv("DEBUG_MODE", "0") == "1"

AUTO_APPLY_REVIEW_DECISION = os.getenv("AUTO_APPLY_REVIEW_DECISION", "0") == "1"
CISO_SCORE_WRITE_MODE = os.getenv("CISO_SCORE_WRITE_MODE", "none").strip().lower()

DEBUG_ONLY_FILES_ENV = os.getenv("DEBUG_ONLY_FILES", "").strip()
DEBUG_ONLY_FILES = {
    x.strip()
    for x in re.split(r"[;,|]", DEBUG_ONLY_FILES_ENV)
    if x.strip()
}


# ============================================================
# 分类 / 挂接阈值
# ============================================================

HIGH_CONFIDENCE_THRESHOLD = float(os.getenv("HIGH_CONFIDENCE_THRESHOLD", "0.70"))
MEDIUM_CONFIDENCE_THRESHOLD = float(os.getenv("MEDIUM_CONFIDENCE_THRESHOLD", "0.40"))

# 已经写死为 0.40，低于 0.40 不挂
ATTACH_MIN_SCORE = float(os.getenv("ATTACH_MIN_SCORE", "0.40"))

# 通用版核心限制：
# 每一份证据最多自动挂接相关度最高的 N 个控制项
# 注意：这不限制“一个控制项可以有多少份证据”
FINAL_TARGET_TOP_K = int(os.getenv("FINAL_TARGET_TOP_K", "10"))

PRINT_TOP_K = int(os.getenv("PRINT_TOP_K", "20"))


# ============================================================
# 子项展开加权
# ============================================================

CHILD_DELTA_MUST = float(os.getenv("CHILD_DELTA_MUST", "0.03"))
CHILD_DELTA_SHOULD = float(os.getenv("CHILD_DELTA_SHOULD", "0.00"))
CHILD_DELTA_HIGH = float(os.getenv("CHILD_DELTA_HIGH", "-0.03"))
CHILD_DELTA_VERY_HIGH = float(os.getenv("CHILD_DELTA_VERY_HIGH", "-0.06"))
CHILD_DELTA_VEHICLE = float(os.getenv("CHILD_DELTA_VEHICLE", "-0.08"))
CHILD_DELTA_SGA = float(os.getenv("CHILD_DELTA_SGA", "-0.05"))

CHILD_TEXT_BONUS_STRONG = float(os.getenv("CHILD_TEXT_BONUS_STRONG", "0.05"))
CHILD_TEXT_BONUS_MEDIUM = float(os.getenv("CHILD_TEXT_BONUS_MEDIUM", "0.03"))
CHILD_TEXT_BONUS_LIGHT = float(os.getenv("CHILD_TEXT_BONUS_LIGHT", "0.01"))


# ============================================================
# AI 初审状态 / 结果
# ============================================================

AUTO_APPLY_MIN_SCORE = int(os.getenv("AUTO_APPLY_MIN_SCORE", "50"))
AUTO_COMPLIANT_MIN_SCORE = int(os.getenv("AUTO_COMPLIANT_MIN_SCORE", "80"))

STATUS_TODO = os.getenv("REVIEW_STATUS_TODO", "待办")
STATUS_REVIEWING = os.getenv("REVIEW_STATUS_REVIEWING", "审核中")

RESULT_UNEVALUATED = os.getenv("REVIEW_RESULT_UNEVALUATED", "未评估")
RESULT_PARTIAL = os.getenv("REVIEW_RESULT_PARTIAL", "部分合规")
RESULT_COMPLIANT = os.getenv("REVIEW_RESULT_COMPLIANT", "合规")
RESULT_LOW = os.getenv("REVIEW_RESULT_LOW", "未评估")


# ============================================================
# 分数收紧配置
# ============================================================

SINGLE_PRIMARY_CAP = int(os.getenv("SINGLE_PRIMARY_CAP", "68"))
SINGLE_PRIMARY_NO_SUPPORT_CAP = int(os.getenv("SINGLE_PRIMARY_NO_SUPPORT_CAP", "68"))
NORMAL_GAP_CAP = int(os.getenv("NORMAL_GAP_CAP", "75"))
KEY_GAP_CAP = int(os.getenv("KEY_GAP_CAP", "68"))
NO_EXECUTION_CAP = int(os.getenv("NO_EXECUTION_CAP", "65"))

KEY_GAP_MAP: Dict[str, set[str]] = {
    "contract_policy_commitment": {"签署/承诺记录", "范围/对象"},
    "awareness_training": {"执行记录", "范围/对象"},
    "asset_classification": {"资产清单", "分类分级标准"},
    "malware_protection": {"执行记录", "复核/闭环"},
    "event_logs": {"执行记录", "复核/闭环"},
    "incident_handling": {"执行记录", "复核/闭环"},
    "weakness_vulnerability": {"执行记录", "复核/闭环"},
    "access_control": {"执行记录", "责任/审批", "复核/闭环"},
    "backup_recovery": {"执行记录", "复核/闭环"},
    "supplier_management": {"责任/审批", "复核/闭环"},
    "physical_security": {"执行记录", "范围/对象"},
    "policy_governance": {"制度/要求", "责任/审批"},
    "privacy_data_protection": {"制度/要求", "执行记录", "范围/对象"},
    "generic": {"执行记录"},
    "unknown": {"执行记录"},
}


# ============================================================
# 通用工具函数
# ============================================================

def _to_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value)


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(round(float(value)))
    except Exception:
        return default


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _clamp_int(value: float, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, int(round(value))))


def _ai_score_to_ciso_maturity(score_100: Any) -> int:
    s = _safe_int(score_100, 0)

    if s < 40:
        return 1
    if s < 60:
        return 2
    if s < 80:
        return 3
    if s < 90:
        return 4
    return 5


def _first_non_empty(*values: Any) -> Any:
    for value in values:
        if value not in (None, "", [], {}):
            return value
    return None


def _normalize_text(text: str) -> str:
    s = _to_str(text).replace("\xa0", " ").replace("\u3000", " ")
    s = re.sub(r"\s+", " ", s).strip().lower()
    return s


def _short_requirement_id(requirement_id: Any) -> str:
    s = _to_str(requirement_id).strip()
    if not s:
        return ""
    if ":" in s:
        s = s.split(":")[-1]
    return s.strip()


def _is_internal_node(value: Any) -> bool:
    s = _to_str(value).strip()
    return bool(re.fullmatch(r"node\d+", s, flags=re.IGNORECASE))


def _looks_like_version_context(full_text: str, start: int, end: int) -> bool:
    before = full_text[max(0, start - 16):start].lower()
    after = full_text[end:min(len(full_text), end + 8)].lower()

    if re.search(r"(?:^|[^a-z0-9])v\s*$", before):
        return True

    if "version" in before or "版本" in before:
        return True

    if after.startswith(":") and re.search(r"v\s*$", before):
        return True

    return False


def _extract_requirement_code(value: Any) -> str:
    s = _to_str(value).strip()
    if not s:
        return ""

    candidates: List[str] = []

    if ":" in s:
        parts = [p.strip() for p in s.split(":") if p.strip()]
        candidates.extend(reversed(parts))

    candidates.append(s)

    patterns = [
        r"第\s*\d+\s*条",
        r"Article\s+\d+[A-Za-z]?",
        r"[A-Z]{1,8}(?:[.-][A-Z0-9]{1,12}){1,8}",
        r"[A-Z]{1,8}\d+(?:\.\d+){1,8}",
        r"\d+(?:\.\d+){1,8}",
    ]

    for item in candidates:
        item = _to_str(item).strip()
        if not item:
            continue

        if _is_internal_node(item):
            continue

        for pattern in patterns:
            for m in re.finditer(pattern, item, flags=re.IGNORECASE):
                code = m.group(0).strip()

                if not code:
                    continue

                if _is_internal_node(code):
                    continue

                if _looks_like_version_context(item, m.start(), m.end()):
                    continue

                if re.fullmatch(r"v?\d+(?:\.\d+){1,8}", code, flags=re.IGNORECASE):
                    if re.search(r"[a-z]-v" + re.escape(code), item, flags=re.IGNORECASE):
                        continue
                    if re.search(r"version\s*" + re.escape(code), item, flags=re.IGNORECASE):
                        continue

                return code

    return ""


def _extract_keywords(text: str) -> List[str]:
    text = _normalize_text(text)
    if not text:
        return []

    zh = re.findall(r"[\u4e00-\u9fff]{2,10}", text)
    en = re.findall(r"[a-z][a-z0-9_\-]{2,}", text)

    stop = {
        "what", "extent", "with", "from", "that", "this", "those", "these",
        "which", "when", "where", "into", "used", "using", "their", "there",
        "information", "security", "requirements", "requirement", "managed",
        "management", "control", "controls", "organization", "relevant",
        "handling", "considered", "processed", "ensured", "process",
        "shall", "should", "must", "need", "needs", "the", "and", "for",
    }

    out: List[str] = []
    seen = set()

    for token in zh + en:
        token = token.strip().lower()
        if not token or token in stop or token in seen:
            continue
        seen.add(token)
        out.append(token)

    return out[:60]


def _keyword_overlap_score(evidence_text: str, target_text: str) -> float:
    e_set = set(_extract_keywords(evidence_text))
    t_set = set(_extract_keywords(target_text))

    if not e_set or not t_set:
        return 0.0

    shared = e_set & t_set

    if not shared:
        return 0.0

    return len(shared) / max(1.0, len(t_set))


def _normalize_impl_groups(value: Any) -> List[str]:
    if value is None:
        return []

    if isinstance(value, str):
        s = value.strip()
        return [s] if s else []

    if isinstance(value, (list, tuple, set)):
        out = []
        for x in value:
            sx = _to_str(x).strip()
            if sx:
                out.append(sx)
        return out

    return []


def _display_impl_groups(groups: List[str]) -> str:
    if not groups:
        return ""

    return "/".join([g.replace("_", " ").strip() for g in groups if _to_str(g).strip()])


def _normalize_existing_evidence_ids(evidences: Any) -> List[str]:
    out: List[str] = []

    if isinstance(evidences, list):
        for ev in evidences:
            if isinstance(ev, dict):
                ev_id = ev.get("id") or ev.get("evidence_id") or ev.get("uuid")
                if ev_id:
                    out.append(str(ev_id))
            elif ev:
                out.append(str(ev))

    elif isinstance(evidences, dict):
        ev_id = evidences.get("id") or evidences.get("evidence_id") or evidences.get("uuid")
        if ev_id:
            out.append(str(ev_id))

    return list(dict.fromkeys(out))


def _desc_first_line(text: str) -> str:
    for line in _to_str(text).splitlines():
        s = line.strip().lstrip("-").lstrip("*").strip()
        if s:
            return s[:120]
    return ""


def _evidence_full_text(raw: Any) -> str:
    return f"{_to_str(getattr(raw, 'file_name', ''))}\n{_to_str(getattr(raw, 'extracted_text', ''))}".lower()


# ============================================================
# Requirement 树处理
# ============================================================

def _normalize_requirement_row(item: dict) -> Dict[str, Any]:
    req = item.get("requirement") if isinstance(item.get("requirement"), dict) else {}
    req_node = item.get("requirement_node") if isinstance(item.get("requirement_node"), dict) else {}
    parent_req = req.get("parent_requirement") if isinstance(req.get("parent_requirement"), dict) else {}

    requirement_id = _first_non_empty(
        item.get("requirement_id"),
        item.get("ref_id"),
        req.get("urn"),
        req.get("ref_id"),
        req.get("id"),
        req_node.get("urn"),
        req_node.get("ref_id"),
        req_node.get("id"),
    )
    requirement_id = _to_str(requirement_id).strip()

    ref_id = _first_non_empty(
        req.get("ref_id"),
        req_node.get("ref_id"),
        _short_requirement_id(requirement_id),
    )
    ref_id = _to_str(ref_id).strip()

    title = _first_non_empty(
        item.get("name"),
        item.get("title"),
        req.get("name"),
        req.get("title"),
        req_node.get("name"),
        req_node.get("title"),
        requirement_id,
    )
    title = _to_str(title).strip()

    description = _first_non_empty(
        item.get("description"),
        req.get("description"),
        req_node.get("description"),
        "",
    )
    description = _to_str(description).strip()

    parent_requirement_id = _to_str(
        _first_non_empty(
            parent_req.get("urn"),
            parent_req.get("id"),
            parent_req.get("ref_id"),
        )
    ).strip()

    parent_ref_id = _to_str(parent_req.get("ref_id")).strip()

    parent_title = _to_str(
        _first_non_empty(
            parent_req.get("name"),
            parent_req.get("title"),
            parent_req.get("ref_id"),
            parent_requirement_id,
        )
    ).strip()

    parent_key = _short_requirement_id(parent_ref_id or parent_requirement_id)
    implementation_groups = _normalize_impl_groups(req.get("implementation_groups"))

    own_code = (
        _extract_requirement_code(requirement_id)
        or _extract_requirement_code(ref_id)
        or _extract_requirement_code(title)
    )

    parent_code = (
        _extract_requirement_code(parent_requirement_id)
        or _extract_requirement_code(parent_ref_id)
        or _extract_requirement_code(parent_title)
    )

    display_code = own_code or parent_code

    return {
        "ra_id": _to_str(item.get("id")).strip(),
        "requirement_id": requirement_id,
        "short_requirement_id": _short_requirement_id(requirement_id),
        "ref_id": ref_id,
        "node_key": _short_requirement_id(ref_id or requirement_id),
        "title": title,
        "description": description,
        "desc_first_line": _desc_first_line(description),
        "assessable": bool(item.get("assessable")),
        "implementation_groups": implementation_groups,
        "impl_display": _display_impl_groups(implementation_groups),
        "parent_requirement_id": parent_requirement_id,
        "parent_ref_id": parent_ref_id,
        "parent_key": parent_key,
        "parent_title": parent_title,
        "own_code": own_code,
        "parent_code": parent_code,
        "display_code": display_code,
        "observation": _to_str(item.get("observation")),
        "evidences": item.get("evidences") or [],
        "raw_item": item,
    }


def _build_requirement_index(requirement_rows: List[dict]) -> Dict[str, Any]:
    rows = [_normalize_requirement_row(x) for x in requirement_rows if x.get("id")]

    by_ra_id: Dict[str, Dict[str, Any]] = {}
    by_match_key: Dict[str, List[Dict[str, Any]]] = {}
    children_by_parent_key: Dict[str, List[Dict[str, Any]]] = {}

    for row in rows:
        by_ra_id[row["ra_id"]] = row

        for key in [
            row["ra_id"],
            row["requirement_id"],
            row["short_requirement_id"],
            row["ref_id"],
            row["node_key"],
        ]:
            key = _short_requirement_id(key)
            if key:
                by_match_key.setdefault(key, []).append(row)

        if row["parent_key"] and row["assessable"]:
            children_by_parent_key.setdefault(row["parent_key"], []).append(row)

    for row in rows:
        if row.get("display_code"):
            continue

        parent_key = _short_requirement_id(row.get("parent_key"))
        parent_candidates = by_match_key.get(parent_key, [])

        for parent in parent_candidates:
            code = parent.get("display_code") or parent.get("own_code") or parent.get("parent_code")
            if code:
                row["display_code"] = code
                break

    return {
        "rows": rows,
        "by_ra_id": by_ra_id,
        "by_match_key": by_match_key,
        "children_by_parent_key": children_by_parent_key,
    }


# ============================================================
# Classifier 调用
# ============================================================

def _call_classifier(classifier: Any, raw: Any, requirement_catalog: List[Any]) -> Any:
    if hasattr(classifier, "run"):
        return classifier.run(raw, requirement_catalog)

    if hasattr(classifier, "classify"):
        try:
            return classifier.classify(evidence=raw, requirement_catalog=requirement_catalog)
        except TypeError:
            pass

        try:
            return classifier.classify(raw, requirement_catalog)
        except TypeError:
            pass

        return classifier.classify(raw)

    raise RuntimeError("ClassifierAgent 没有可用的 run/classify 方法")


def _result_to_dict(result: Any) -> Dict[str, Any]:
    if result is None:
        return {"matches": [], "classification_confidence": 0.0, "rationale": "空结果"}

    if hasattr(result, "model_dump"):
        data = result.model_dump()
    elif isinstance(result, dict):
        data = result
    else:
        data = {"raw_result": str(result)}

    matches = data.get("matches", []) or []
    top_score = max([_safe_float(x.get("score")) for x in matches if isinstance(x, dict)] or [0.0])

    return {
        "matches": matches,
        "classification_confidence": _safe_float(data.get("classification_confidence"), top_score),
        "rationale": _to_str(data.get("rationale") or data.get("raw_result") or ""),
        "raw_result": data,
    }


# ============================================================
# 父项展开到子项
# ============================================================

def _resolve_base_rows(match: Dict[str, Any], idx: Dict[str, Any]) -> List[Dict[str, Any]]:
    by_ra_id = idx["by_ra_id"]
    by_match_key = idx["by_match_key"]

    results: List[Dict[str, Any]] = []
    seen = set()

    ra_id = _to_str(match.get("requirement_assessment_id")).strip()
    if ra_id and ra_id in by_ra_id:
        results.append(by_ra_id[ra_id])
        seen.add(ra_id)

    req_id = _to_str(match.get("requirement_id")).strip()
    req_key = _short_requirement_id(req_id)

    for key in [req_id, req_key]:
        key = _short_requirement_id(key)
        if not key:
            continue

        for row in by_match_key.get(key, []):
            if row["ra_id"] in seen:
                continue
            results.append(row)
            seen.add(row["ra_id"])

    return results


def _collect_leaf_descendants(row: Dict[str, Any], idx: Dict[str, Any]) -> List[Dict[str, Any]]:
    children_by_parent_key = idx["children_by_parent_key"]

    start_key = row["node_key"]
    if not start_key:
        return []

    first_children = children_by_parent_key.get(start_key, [])
    if not first_children:
        return []

    leaves: List[Dict[str, Any]] = []
    queue = list(first_children)

    while queue:
        node = queue.pop(0)
        sub_key = node["node_key"]
        sub_children = children_by_parent_key.get(sub_key, [])

        if sub_children:
            queue.extend(sub_children)
        else:
            leaves.append(node)

    return leaves


def _child_specific_delta(leaf_row: Dict[str, Any], raw: Any) -> float:
    evidence_text = _evidence_full_text(raw)
    impls = [x.lower() for x in (leaf_row.get("implementation_groups") or [])]
    impl = impls[0] if impls else ""

    delta = 0.0

    if impl == "must":
        delta += CHILD_DELTA_MUST
    elif impl == "should":
        delta += CHILD_DELTA_SHOULD
    elif impl == "high":
        delta += CHILD_DELTA_HIGH
    elif impl == "very_high":
        delta += CHILD_DELTA_VERY_HIGH
    elif impl == "vehicle":
        delta += CHILD_DELTA_VEHICLE
    elif impl == "sga":
        delta += CHILD_DELTA_SGA

    child_text = "\n".join(
        [
            _to_str(leaf_row.get("display_code")),
            _to_str(leaf_row.get("title")),
            _to_str(leaf_row.get("description")),
            _to_str(leaf_row.get("desc_first_line")),
            _to_str(leaf_row.get("impl_display")),
        ]
    )

    overlap = _keyword_overlap_score(evidence_text, child_text)

    if overlap >= 0.20:
        delta += CHILD_TEXT_BONUS_STRONG
    elif overlap >= 0.10:
        delta += CHILD_TEXT_BONUS_MEDIUM
    elif overlap >= 0.05:
        delta += CHILD_TEXT_BONUS_LIGHT

    return delta


def _target_label(row: Dict[str, Any]) -> str:
    code = _to_str(
        row.get("display_code")
        or row.get("source_code")
        or row.get("own_code")
        or row.get("parent_code")
    ).strip()

    if not code:
        code = (
            _extract_requirement_code(row.get("requirement_id"))
            or _extract_requirement_code(row.get("ref_id"))
            or _extract_requirement_code(row.get("title"))
            or _to_str(row.get("short_requirement_id") or row.get("ref_id") or row.get("requirement_id"))
        )

    impl = _to_str(row.get("impl_display")).strip()

    if impl:
        return f"{code}（{impl}）"

    return code


def _source_code_from_match(match: Dict[str, Any], base_row: Optional[Dict[str, Any]] = None) -> str:
    code = (
        _extract_requirement_code(match.get("requirement_id"))
        or _extract_requirement_code(match.get("title"))
    )

    if code:
        return code

    if base_row:
        code = (
            _to_str(base_row.get("display_code"))
            or _to_str(base_row.get("own_code"))
            or _to_str(base_row.get("parent_code"))
        ).strip()

    return code


def _expand_match_to_targets(match: Dict[str, Any], idx: Dict[str, Any], raw: Any) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    base_rows = _resolve_base_rows(match, idx)
    base_score = _safe_float(match.get("score"), 0.0)

    for base_row in base_rows:
        source_code = _source_code_from_match(match, base_row)
        leaf_children = _collect_leaf_descendants(base_row, idx)

        if leaf_children:
            for leaf in leaf_children:
                if source_code:
                    leaf["source_code"] = source_code
                    leaf["display_code"] = source_code
                elif not leaf.get("display_code"):
                    inherited = (
                        base_row.get("display_code")
                        or base_row.get("own_code")
                        or base_row.get("parent_code")
                    )
                    if inherited:
                        leaf["display_code"] = inherited

                delta = _child_specific_delta(leaf, raw)
                final_score = round(_clamp(base_score + delta), 4)

                if final_score < ATTACH_MIN_SCORE:
                    continue

                label = _target_label(leaf)

                results.append(
                    {
                        "ra_id": leaf["ra_id"],
                        "framework": _to_str(match.get("framework")),
                        "requirement_id": leaf["requirement_id"],
                        "title": label,
                        "score": final_score,
                        "base_score": round(base_score, 4),
                        "reason": (
                            f"base_score={base_score:.4f}"
                            f"；child_delta={delta:.2f}"
                            f"；子项展开={label}"
                            f"；base_reason={_to_str(match.get('reason')) or '分类命中'}"
                        ),
                        "target_label": label,
                        "implementation_groups": leaf["implementation_groups"],
                    }
                )

            continue

        if base_row["assessable"] and base_score >= ATTACH_MIN_SCORE:
            if source_code:
                base_row["source_code"] = source_code
                base_row["display_code"] = source_code

            label = _target_label(base_row)

            results.append(
                {
                    "ra_id": base_row["ra_id"],
                    "framework": _to_str(match.get("framework")),
                    "requirement_id": base_row["requirement_id"],
                    "title": label,
                    "score": round(_clamp(base_score), 4),
                    "base_score": round(base_score, 4),
                    "reason": f"base_score={base_score:.4f}；直接挂接当前项；base_reason={_to_str(match.get('reason')) or '分类命中'}",
                    "target_label": label,
                    "implementation_groups": base_row["implementation_groups"],
                }
            )

    dedup: Dict[str, Dict[str, Any]] = {}

    for row in results:
        old = dedup.get(row["ra_id"])
        if old is None or _safe_float(row["score"]) > _safe_float(old["score"]):
            dedup[row["ra_id"]] = row

    ordered = list(dedup.values())
    ordered.sort(key=lambda x: _safe_float(x["score"]), reverse=True)

    return ordered


def _select_final_targets(matches: List[dict], idx: Dict[str, Any], raw: Any) -> List[Dict[str, Any]]:
    """
    通用版最终候选控制项选择逻辑。

    规则：
    1. 先按 ATTACH_MIN_SCORE 做最低相关度过滤。
    2. 同一个 requirement_assessment_id 只保留最高分。
    3. 每份证据最多保留 FINAL_TARGET_TOP_K 个最高相关控制项。
    4. 不写死任何框架、控制项编号、证据名称。
    5. 不限制一个控制项能挂多少份证据。
    """
    bucket: Dict[str, Dict[str, Any]] = {}

    for match in matches:
        if not isinstance(match, dict):
            continue

        for target in _expand_match_to_targets(match, idx, raw):
            old = bucket.get(target["ra_id"])
            if old is None or _safe_float(target.get("score")) > _safe_float(old.get("score")):
                bucket[target["ra_id"]] = target

    selected = [
        x for x in bucket.values()
        if _safe_float(x.get("score")) >= ATTACH_MIN_SCORE
    ]

    selected.sort(key=lambda x: _safe_float(x.get("score")), reverse=True)

    before_count = len(selected)

    if FINAL_TARGET_TOP_K > 0:
        selected = selected[:FINAL_TARGET_TOP_K]

    after_count = len(selected)

    for x in selected:
        old_reason = _to_str(x.get("reason"))
        x["reason"] = (
            f"{old_reason}"
            f"；top_k_filter=保留"
            f"；每份证据最多挂接={FINAL_TARGET_TOP_K}"
            f"；过滤前候选数={before_count}"
            f"；过滤后候选数={after_count}"
        )

    return selected


def _status_from_targets(targets: List[Dict[str, Any]]) -> str:
    if not targets:
        return "needs_review"

    top_score = _safe_float(targets[0]["score"])

    if top_score >= HIGH_CONFIDENCE_THRESHOLD:
        return "auto_import"

    if top_score >= MEDIUM_CONFIDENCE_THRESHOLD:
        return "candidate_review"

    return "low_confidence_attach"


# ============================================================
# Evidence 创建 / 复用 / 挂接
# ============================================================

def _pick_existing_evidence_id(api: CisoApiClient, file_name: str) -> Optional[str]:
    try:
        data = api.search_existing_evidence(file_name)
    except Exception:
        return None

    candidates = []

    if isinstance(data, dict):
        candidates = data.get("results") or data.get("data") or []
    elif isinstance(data, list):
        candidates = data

    for item in candidates:
        if not isinstance(item, dict):
            continue

        if _to_str(item.get("name")).strip() == file_name:
            ev_id = item.get("id")
            if ev_id:
                return str(ev_id)

    return None


def _ensure_evidence(api: CisoApiClient, raw: Any) -> Tuple[str, bool]:
    if REUSE_EXISTING_EVIDENCE:
        existing_id = _pick_existing_evidence_id(api, raw.file_name)
        if existing_id:
            return existing_id, True

    created = api.create_evidence(
        name=raw.file_name,
        description=f"sha256={_to_str(getattr(raw, 'sha256', ''))}",
    )

    evidence_id = _to_str(created.get("id")).strip()

    if not evidence_id:
        raise RuntimeError(f"创建 evidence 成功但未返回 id: {created}")

    api.upload_evidence_file(evidence_id, raw.file_path)

    return evidence_id, False


def _attach_evidence_only(api: CisoApiClient, target_row: Dict[str, Any], evidence_id: str) -> None:
    existing_ids = _normalize_existing_evidence_ids(target_row.get("evidences"))
    merged_ids = list(dict.fromkeys(existing_ids + [evidence_id]))

    api.attach_evidence_to_requirement(target_row["ra_id"], merged_ids)

    target_row["evidences"] = merged_ids


def _preview_text(raw: Any, max_len: int = 300) -> str:
    return _to_str(getattr(raw, "extracted_text", ""))[:max_len]


# ============================================================
# AI 初审评分
# ============================================================

def _unique_records_by_file(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    unique_by_file: Dict[str, Dict[str, Any]] = {}

    for record in records:
        file_name = _to_str(record.get("file_name")).strip()
        if not file_name:
            continue

        old = unique_by_file.get(file_name)
        if old is None or _safe_float(record.get("score")) > _safe_float(old.get("score")):
            unique_by_file[file_name] = record

    ordered = list(unique_by_file.values())
    ordered.sort(key=lambda x: (_safe_float(x.get("score")), _to_str(x.get("file_name"))), reverse=True)

    return ordered


def _split_key_and_normal_gaps(record: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    family = _to_str(record.get("target_family") or "generic")
    key_defs = KEY_GAP_MAP.get(family, KEY_GAP_MAP.get("generic", set()))

    partial_dims = record.get("partial_dims") or []
    missing_dims = record.get("missing_dims") or []

    all_gaps = list(dict.fromkeys([_to_str(x) for x in partial_dims + missing_dims if _to_str(x).strip()]))

    key_gaps = [gap for gap in all_gaps if gap in key_defs]
    normal_gaps = [gap for gap in all_gaps if gap not in key_defs]

    return key_gaps, normal_gaps


def _has_present_dim(records: List[Dict[str, Any]], keywords: List[str]) -> bool:
    for record in records:
        dims = record.get("present_dims") or []
        for dim in dims:
            ds = _to_str(dim)
            if any(keyword in ds for keyword in keywords):
                return True

    return False


def _collect_present_dims(records: List[Dict[str, Any]]) -> List[str]:
    out: List[str] = []
    seen = set()

    for record in records:
        for dim in record.get("present_dims") or []:
            dim_s = _to_str(dim).strip()
            if dim_s and dim_s not in seen:
                seen.add(dim_s)
                out.append(dim_s)

    return out


def _score_by_evidence_completeness(
    primary_items: List[Dict[str, Any]],
    supporting_items: List[Dict[str, Any]],
    mismatch_items: List[Dict[str, Any]],
    key_gaps_final: List[str],
    normal_gaps_final: List[str],
) -> Tuple[int, List[str]]:
    reasons: List[str] = []

    if not primary_items:
        max_support = max([_safe_float(x.get("score")) for x in supporting_items + mismatch_items] or [0.0])
        score = _clamp_int(max_support * 55, 0, 42)
        reasons.append("未发现主证据，按辅助/弱相关证据保守估算。")
        return score, reasons

    max_primary_score = max([_safe_float(x.get("score")) for x in primary_items] or [0.0])
    present_dims = _collect_present_dims(primary_items)

    score = 45
    reasons.append("存在主证据，基础分 45。")

    if max_primary_score >= 0.85:
        score += 7
        reasons.append("最高主证据置信度 >= 0.85，加 7 分。")
    elif max_primary_score >= 0.75:
        score += 5
        reasons.append("最高主证据置信度 >= 0.75，加 5 分。")
    elif max_primary_score >= 0.65:
        score += 3
        reasons.append("最高主证据置信度 >= 0.65，加 3 分。")
    elif max_primary_score >= 0.50:
        score += 1
        reasons.append("最高主证据置信度 >= 0.50，加 1 分。")

    if len(primary_items) >= 2:
        add = min(14, (len(primary_items) - 1) * 5)
        score += add
        reasons.append(f"存在多份主证据，共 {len(primary_items)} 份，加 {add} 分。")

    if supporting_items:
        add = min(4, len(supporting_items) * 2)
        score += add
        reasons.append(f"存在辅助证据 {len(supporting_items)} 份，加 {add} 分。")

    dim_weights = {
        "制度/要求": 4,
        "签署/承诺记录": 5,
        "执行记录": 6,
        "范围/对象": 4,
        "责任/审批": 3,
        "复核/闭环": 5,
        "资产清单": 6,
        "分类分级标准": 6,
        "发布/宣贯": 3,
        "补充抽查/复核证明": 3,
    }

    for dim in present_dims:
        add = dim_weights.get(dim, 2)
        score += add
        reasons.append(f"已覆盖维度“{dim}”，加 {add} 分。")

    if key_gaps_final:
        deduction = len(key_gaps_final) * 14
        score -= deduction
        reasons.append(f"存在关键缺口 {len(key_gaps_final)} 项，扣 {deduction} 分。")

    if normal_gaps_final:
        deduction = len(normal_gaps_final) * 8
        score -= deduction
        reasons.append(f"存在一般缺口 {len(normal_gaps_final)} 项，扣 {deduction} 分。")

    has_execution_present = _has_present_dim(
        primary_items,
        ["执行", "记录", "签到", "签署", "承诺", "检测", "查杀", "评审", "处置", "复测", "闭环", "台账"],
    )

    if not has_execution_present:
        score -= 8
        reasons.append("未发现明显执行类/记录类支撑，扣 8 分。")

    cap = 92

    if key_gaps_final:
        cap = min(cap, KEY_GAP_CAP)
        reasons.append(f"存在关键缺口，分数封顶 {KEY_GAP_CAP}。")

    if normal_gaps_final:
        cap = min(cap, NORMAL_GAP_CAP)
        reasons.append(f"存在一般缺口，分数封顶 {NORMAL_GAP_CAP}。")

    if len(primary_items) == 1:
        cap = min(cap, SINGLE_PRIMARY_CAP)
        reasons.append(f"只有 1 份主证据，分数封顶 {SINGLE_PRIMARY_CAP}。")

    if len(primary_items) == 1 and not supporting_items:
        cap = min(cap, SINGLE_PRIMARY_NO_SUPPORT_CAP)
        reasons.append(f"只有 1 份主证据且无辅助证据，分数封顶 {SINGLE_PRIMARY_NO_SUPPORT_CAP}。")

    if mismatch_items:
        cap = min(cap, 78)
        reasons.append("存在待人工确认证据，分数封顶 78。")

    if not has_execution_present:
        cap = min(cap, NO_EXECUTION_CAP)
        reasons.append(f"缺少执行类/记录类支撑，分数封顶 {NO_EXECUTION_CAP}。")

    if not key_gaps_final and not normal_gaps_final and len(primary_items) == 1:
        cap = min(cap, SINGLE_PRIMARY_CAP)
        reasons.append("未发现明确缺口，但证据数量不足，仍按单主证据封顶处理。")

    score = min(score, cap)
    score = _clamp_int(score, 0, 95)

    return score, reasons


def _compute_review_decision(target_label: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    ordered = _unique_records_by_file(records)

    primary_items = [x for x in ordered if _to_str(x.get("role")) == "primary"]
    supporting_items = [x for x in ordered if _to_str(x.get("role")) == "supporting"]
    mismatch_items = [x for x in ordered if _to_str(x.get("role")) == "mismatch"]

    all_scores = [_safe_float(x.get("score")) for x in ordered]
    max_any_score = max(all_scores or [0.0])

    if not primary_items:
        suggested_score = _clamp_int(max_any_score * 55, 0, 42)

        return {
            "target_label": target_label,
            "primary_count": 0,
            "supporting_count": len(supporting_items),
            "mismatch_count": len(mismatch_items),
            "max_primary_score": 0.0,
            "suggested_status": STATUS_REVIEWING if ordered else STATUS_TODO,
            "suggested_result": RESULT_LOW if ordered else RESULT_UNEVALUATED,
            "suggested_score": suggested_score,
            "ciso_maturity_score": _ai_score_to_ciso_maturity(suggested_score),
            "key_gaps": [],
            "normal_gaps": [],
            "score_reasons": ["未发现主证据，AI 初审认为当前证据支撑不足。"],
            "decision_reason": "未发现主证据，建议人工复核。",
            "auto_apply_allowed": bool(ordered),
        }

    max_primary_score = max([_safe_float(x.get("score")) for x in primary_items] or [0.0])

    key_gap_counter: Dict[str, int] = {}
    normal_gap_counter: Dict[str, int] = {}

    for item in primary_items:
        key_gaps, normal_gaps = _split_key_and_normal_gaps(item)

        for gap in key_gaps:
            key_gap_counter[gap] = key_gap_counter.get(gap, 0) + 1

        for gap in normal_gaps:
            normal_gap_counter[gap] = normal_gap_counter.get(gap, 0) + 1

    key_gaps_final = sorted(key_gap_counter.keys())
    normal_gaps_final = sorted(normal_gap_counter.keys())

    suggested_score, score_reasons = _score_by_evidence_completeness(
        primary_items=primary_items,
        supporting_items=supporting_items,
        mismatch_items=mismatch_items,
        key_gaps_final=key_gaps_final,
        normal_gaps_final=normal_gaps_final,
    )

    if suggested_score < AUTO_APPLY_MIN_SCORE:
        suggested_status = STATUS_REVIEWING
        suggested_result = RESULT_LOW
        auto_apply_allowed = True
        decision_reason = "存在证据但证据完整度偏低，建议人工复核。"

    elif (
        suggested_score >= AUTO_COMPLIANT_MIN_SCORE
        and len(primary_items) >= 2
        and not key_gaps_final
        and not normal_gaps_final
        and max_primary_score >= HIGH_CONFIDENCE_THRESHOLD
    ):
        suggested_status = STATUS_REVIEWING
        suggested_result = RESULT_COMPLIANT
        auto_apply_allowed = True
        decision_reason = "存在多份主证据，且暂未发现明显缺口，可建议判定为合规。"

    else:
        suggested_status = STATUS_REVIEWING
        suggested_result = RESULT_PARTIAL
        auto_apply_allowed = True

        if key_gaps_final:
            decision_reason = "存在主证据，但仍有关键缺口，建议判定为部分合规。"
        elif normal_gaps_final:
            decision_reason = "存在主证据，但仍有一般缺口，建议判定为部分合规。"
        elif len(primary_items) == 1:
            decision_reason = "存在主证据，但证据数量较少，建议判定为部分合规，并由人工抽查确认。"
        else:
            decision_reason = "存在主证据，但证据完整度未达到合规阈值，建议判定为部分合规。"

    return {
        "target_label": target_label,
        "primary_count": len(primary_items),
        "supporting_count": len(supporting_items),
        "mismatch_count": len(mismatch_items),
        "max_primary_score": round(max_primary_score, 4),
        "suggested_status": suggested_status,
        "suggested_result": suggested_result,
        "suggested_score": suggested_score,
        "ciso_maturity_score": _ai_score_to_ciso_maturity(suggested_score),
        "key_gaps": key_gaps_final,
        "normal_gaps": normal_gaps_final,
        "score_reasons": score_reasons,
        "decision_reason": decision_reason,
        "auto_apply_allowed": auto_apply_allowed,
    }


def _format_review_decision(decision: Dict[str, Any]) -> str:
    lines: List[str] = []

    lines.append("[AI初审结论]")
    lines.append(f"建议状态：{decision.get('suggested_status')}")
    lines.append(f"建议结果：{decision.get('suggested_result')}")
    lines.append(f"AI建议分数：{decision.get('suggested_score')} / 100")
    lines.append(f"CISO成熟度映射：{decision.get('ciso_maturity_score')} / 5")
    lines.append("")

    primary_count = _safe_int(decision.get("primary_count"))
    supporting_count = _safe_int(decision.get("supporting_count"))
    mismatch_count = _safe_int(decision.get("mismatch_count"))

    lines.append("证据情况：")
    lines.append(f"- 主证据：{primary_count} 份")
    lines.append(f"- 辅助证据：{supporting_count} 份")
    lines.append(f"- 待人工确认证据：{mismatch_count} 份")
    lines.append("")

    key_gaps = decision.get("key_gaps") or []
    normal_gaps = decision.get("normal_gaps") or []

    lines.append("缺口摘要：")
    if key_gaps:
        lines.append(f"- 关键缺口：{'、'.join(key_gaps)}")
    else:
        lines.append("- 关键缺口：暂无明显关键缺口")

    if normal_gaps:
        lines.append(f"- 一般缺口：{'、'.join(normal_gaps)}")
    else:
        lines.append("- 一般缺口：暂无明显一般缺口")

    lines.append("")
    lines.append("初审建议：")
    lines.append(f"- {decision.get('decision_reason')}")

    if CISO_SCORE_WRITE_MODE == "none":
        lines.append("- 当前仅回写状态和结果，不回写前端成熟度分数。")
    else:
        lines.append("- 当前已按 AI 分数映射 CISO 成熟度分。")

    return "\n".join(lines)


def _insert_decision_into_summary(summary: str, decision_text: str) -> str:
    summary = _to_str(summary).strip()
    decision_text = _to_str(decision_text).strip()

    end_tag = "[AI挂接摘要-结束]"

    if end_tag in summary:
        return summary.replace(end_tag, f"{decision_text}\n\n{end_tag}")

    if summary:
        return f"{summary}\n\n{decision_text}"

    return decision_text


def _try_apply_review_decision(api: CisoApiClient, ra_id: str, decision: Dict[str, Any]) -> Tuple[bool, str]:
    status = _to_str(decision.get("suggested_status"))
    result = _to_str(decision.get("suggested_result"))
    ai_score = _safe_int(decision.get("suggested_score"))
    maturity_score = _safe_int(decision.get("ciso_maturity_score"), _ai_score_to_ciso_maturity(ai_score))

    if CISO_SCORE_WRITE_MODE == "none":
        score_payload = None
        score_desc = "未回写分数，只回写状态/结果"
    else:
        score_payload = maturity_score
        score_desc = f"AI分数 {ai_score}/100 已映射为 CISO成熟度 {maturity_score}/5"

    method_names = [
        "update_requirement_assessment_review",
        "update_requirement_assessment_decision",
        "update_requirement_assessment",
    ]

    last_error = ""

    for method_name in method_names:
        method = getattr(api, method_name, None)

        if not callable(method):
            continue

        try:
            if score_payload is None:
                method(ra_id, status=status, result=result)
            else:
                method(ra_id, status=status, result=result, score=score_payload)

            return True, f"已通过 {method_name} 回写；{score_desc}"

        except TypeError:
            try:
                if score_payload is None:
                    method(requirement_assessment_id=ra_id, status=status, result=result)
                else:
                    method(requirement_assessment_id=ra_id, status=status, result=result, score=score_payload)

                return True, f"已通过 {method_name} 回写；{score_desc}"

            except Exception as exc:
                last_error = f"{method_name}: {exc}"

        except Exception as exc:
            last_error = f"{method_name}: {exc}"

    if not last_error:
        last_error = "ciso_api.py 中未找到可用的更新方法"

    return False, last_error


# ============================================================
# 主流程
# ============================================================

def main() -> None:
    if not INPUT_DIR.exists():
        raise RuntimeError(f"输入目录不存在: {INPUT_DIR}")

    api = CisoApiClient()
    classifier = ClassifierAgent()
    advice_agent = AdviceAgent()

    assessment = api.resolve_assessment(assessment_id=ASSESSMENT_ID)
    requirement_catalog = api.build_requirement_catalog(assessment)
    requirement_rows = api.list_requirement_assessments(ASSESSMENT_ID)
    idx = _build_requirement_index(requirement_rows)

    all_files = [p for p in sorted(INPUT_DIR.iterdir()) if p.is_file()]
    actual_names = {p.name for p in all_files}

    print(f"[输入目录] {INPUT_DIR.resolve()}")
    print(f"[目录文件数] {len(all_files)}")
    print(f"[DEBUG_MODE] {DEBUG_MODE}")
    print(f"[DEBUG_ONLY_FILES] {len(DEBUG_ONLY_FILES)}")
    print(f"[ASSESSMENT_ID] {ASSESSMENT_ID}")
    print(f"[APPLY_IMPORT] {APPLY_IMPORT}")
    print(f"[AUTO_APPLY_REVIEW_DECISION] {AUTO_APPLY_REVIEW_DECISION}")
    print(f"[CISO_SCORE_WRITE_MODE] {CISO_SCORE_WRITE_MODE}")
    print(f"[ATTACH_MIN_SCORE] {ATTACH_MIN_SCORE}")
    print(f"[FINAL_TARGET_TOP_K] {FINAL_TARGET_TOP_K}")
    print(f"[SINGLE_PRIMARY_CAP] {SINGLE_PRIMARY_CAP}")

    if DEBUG_MODE and DEBUG_ONLY_FILES:
        print("[DEBUG 白名单文件]")
        for name in sorted(DEBUG_ONLY_FILES):
            print(" -", name)

        missing = DEBUG_ONLY_FILES - actual_names
        if missing:
            print("[警告] 白名单文件未在目录中找到：")
            for name in sorted(missing):
                print(" -", name)

    manifest: List[Dict[str, Any]] = []
    decision_manifest: List[Dict[str, Any]] = []
    target_summary_bucket: Dict[str, List[Dict[str, Any]]] = {}

    for path in all_files:
        if DEBUG_MODE and DEBUG_ONLY_FILES and path.name not in DEBUG_ONLY_FILES:
            print(f"[跳过非 debug 文件] {path.name}")
            continue

        print(f"\n[处理中] {path.name}")

        row: Dict[str, Any] = {
            "file_name": path.name,
            "status": "needs_review",
            "confidence": 0.0,
            "candidate_targets": [],
            "raw_matches": [],
            "classifier_rationale": "",
            "error": None,
            "import_result": {
                "applied": False,
                "mode": "skip",
                "message": "未处理",
            },
        }

        try:
            raw = parse_document(str(path), try_ocr=True)

            if is_empty_evidence(raw) or is_noise_evidence(raw):
                row["status"] = "empty_or_noise"
                row["import_result"] = {
                    "applied": False,
                    "mode": "skip",
                    "message": "证据为空或疑似噪声，不执行导入",
                }
                manifest.append(row)
                continue

            cls_result = _call_classifier(classifier, raw, requirement_catalog)
            cls_data = _result_to_dict(cls_result)

            raw_matches = []
            for match in cls_data["matches"]:
                if not isinstance(match, dict):
                    continue

                raw_matches.append(
                    {
                        "requirement_assessment_id": _to_str(match.get("requirement_assessment_id")),
                        "requirement_id": _to_str(match.get("requirement_id")),
                        "title": _to_str(match.get("title")),
                        "score": round(_safe_float(match.get("score"), 0.0), 4),
                        "reason": _to_str(match.get("reason")),
                    }
                )

            final_targets = _select_final_targets(cls_data["matches"], idx, raw)
            confidence = max([_safe_float(x["score"]) for x in final_targets] or [0.0])
            status = _status_from_targets(final_targets)

            row.update(
                {
                    "file_name": raw.file_name,
                    "status": status,
                    "confidence": round(confidence, 4),
                    "candidate_targets": final_targets,
                    "raw_matches": raw_matches[:PRINT_TOP_K],
                    "classifier_rationale": cls_data.get("rationale", ""),
                    "text_len": len(_to_str(getattr(raw, "extracted_text", ""))),
                    "preview_300": _preview_text(raw, 300),
                }
            )

            if not final_targets:
                row["import_result"] = {
                    "applied": False,
                    "mode": "skip",
                    "message": "没有可挂接的最终控制项（全部低于阈值或被 top-k 收束后无候选）",
                }
                manifest.append(row)
                continue

            if not APPLY_IMPORT:
                row["import_result"] = {
                    "applied": False,
                    "mode": "dry_run",
                    "message": "当前为 dry-run，仅输出计划，不实际导入",
                }
                manifest.append(row)
                continue

            evidence_id, reused = _ensure_evidence(api, raw)

            for target in final_targets:
                target_row = idx["by_ra_id"].get(target["ra_id"])
                if not target_row:
                    continue

                _attach_evidence_only(api, target_row, evidence_id)

                advice = advice_agent.analyze(
                    file_name=raw.file_name,
                    evidence_text=_to_str(getattr(raw, "extracted_text", "")),
                    target_title=_to_str(target.get("target_label")),
                    target_description=_to_str(target_row.get("description")),
                    score=_safe_float(target.get("score")),
                )

                target_summary_bucket.setdefault(target["ra_id"], []).append(
                    {
                        "file_name": raw.file_name,
                        "score": _safe_float(target.get("score")),
                        "base_score": _safe_float(target.get("base_score")),
                        "reason": _to_str(target.get("reason")),
                        "target_label": _to_str(target.get("target_label")),
                        "role": _to_str(advice.get("role")),
                        "target_family": _to_str(advice.get("target_family")),
                        "target_family_cn": _to_str(advice.get("target_family_cn")),
                        "evidence_family": _to_str(advice.get("evidence_family")),
                        "evidence_family_cn": _to_str(advice.get("evidence_family_cn")),
                        "verdict": _to_str(advice.get("verdict")),
                        "present_dims": advice.get("present_dims", []),
                        "partial_dims": advice.get("partial_dims", []),
                        "missing_dims": advice.get("missing_dims", []),
                        "recommendations": advice.get("recommendations", []),
                        "uplift_low": advice.get("uplift_low", 0.0),
                        "uplift_high": advice.get("uplift_high", 0.0),
                    }
                )

            row["import_result"] = {
                "applied": True,
                "mode": "imported_with_multi_attach",
                "message": f"evidence 已导入/复用，并已挂接到最多 {FINAL_TARGET_TOP_K} 个最高相关控制项；Observation 将按控制项汇总写入",
                "evidence_id": evidence_id,
                "reused_existing": reused,
            }

        except Exception as exc:
            row["error"] = _to_str(exc)
            row["import_result"] = {
                "applied": False,
                "mode": "error",
                "message": _to_str(exc),
            }

        manifest.append(row)

    if APPLY_IMPORT:
        for ra_id, records in target_summary_bucket.items():
            target_row = idx["by_ra_id"].get(ra_id)
            if not target_row:
                continue

            target_label = records[0].get("target_label") or _target_label(target_row)

            summary = advice_agent.summarize_for_observation(
                target_label=target_label,
                records=records,
                high_threshold=HIGH_CONFIDENCE_THRESHOLD,
                medium_threshold=MEDIUM_CONFIDENCE_THRESHOLD,
            )

            decision = _compute_review_decision(target_label, records)
            decision_text = _format_review_decision(decision)
            summary_with_decision = _insert_decision_into_summary(summary, decision_text)

            merged_observation = advice_agent.replace_summary_section(
                target_row.get("observation", ""),
                summary_with_decision,
            )

            api.add_review_note(ra_id, merged_observation)
            target_row["observation"] = merged_observation

            decision_row = {
                "requirement_assessment_id": ra_id,
                "target_label": target_label,
                "auto_apply_enabled": AUTO_APPLY_REVIEW_DECISION,
                "auto_apply_allowed": bool(decision.get("auto_apply_allowed")),
                "suggested_status": decision.get("suggested_status"),
                "suggested_result": decision.get("suggested_result"),
                "suggested_score": decision.get("suggested_score"),
                "ciso_maturity_score": decision.get("ciso_maturity_score"),
                "score_write_mode": CISO_SCORE_WRITE_MODE,
                "decision_reason": decision.get("decision_reason"),
                "score_reasons": decision.get("score_reasons"),
                "key_gaps": decision.get("key_gaps"),
                "normal_gaps": decision.get("normal_gaps"),
                "primary_count": decision.get("primary_count"),
                "supporting_count": decision.get("supporting_count"),
                "mismatch_count": decision.get("mismatch_count"),
                "applied": False,
                "apply_message": "",
                "apply_error": "",
            }

            if AUTO_APPLY_REVIEW_DECISION and bool(decision.get("auto_apply_allowed")):
                ok, msg = _try_apply_review_decision(api, ra_id, decision)
                decision_row["applied"] = ok

                if ok:
                    decision_row["apply_message"] = msg
                else:
                    decision_row["apply_error"] = msg

            elif AUTO_APPLY_REVIEW_DECISION and not bool(decision.get("auto_apply_allowed")):
                decision_row["apply_message"] = "未达到自动回写条件，不回写状态/结果/分数"

            else:
                decision_row["apply_message"] = "AUTO_APPLY_REVIEW_DECISION=0，仅生成建议，不回写状态/结果/分数"

            decision_manifest.append(decision_row)

    OUTPUT_MANIFEST.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    REVIEW_DECISION_OUTPUT.write_text(
        json.dumps(decision_manifest, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print("\n" + "=" * 80)
    print("导入前审阅清单")
    print("=" * 80)

    for item in manifest:
        print("\n" + "-" * 80)
        print("文件名:", item.get("file_name"))
        print("状态:", item.get("status"))

        if item.get("error"):
            print("错误:", item["error"])
            continue

        raw_matches = item.get("raw_matches") or []
        if raw_matches:
            print("原始分类前5:")
            for idx_num, target in enumerate(raw_matches[:5], start=1):
                print(f"  [raw {idx_num}] {target.get('title')} | {target.get('score')}")

        targets = item.get("candidate_targets") or []
        print("最终候选数量:", len(targets))

        for idx_num, target in enumerate(targets[:PRINT_TOP_K], start=1):
            print(
                f"  {idx_num}. {target.get('target_label')} | {target.get('score')}"
                f" (base={target.get('base_score')})"
            )

        import_result = item.get("import_result") or {}
        print("导入结果:", f"{import_result.get('mode')} | {import_result.get('message')}")

    print("\n" + "=" * 80)
    print("AI 初审决策清单")
    print("=" * 80)

    for item in decision_manifest:
        print("\n" + "-" * 80)
        print("控制项:", item.get("target_label"))
        print("建议状态:", item.get("suggested_status"))
        print("建议结果:", item.get("suggested_result"))
        print("AI建议分数:", item.get("suggested_score"))
        print("CISO成熟度分数:", item.get("ciso_maturity_score"))
        print("允许自动回写:", item.get("auto_apply_allowed"))
        print("已回写:", item.get("applied"))

        if item.get("apply_error"):
            print("回写错误:", item.get("apply_error"))
        else:
            print("回写说明:", item.get("apply_message"))

    print(f"\n审阅清单已写入: {OUTPUT_MANIFEST.resolve()}")
    print(f"AI 初审决策清单已写入: {REVIEW_DECISION_OUTPUT.resolve()}")


if __name__ == "__main__":
    main()