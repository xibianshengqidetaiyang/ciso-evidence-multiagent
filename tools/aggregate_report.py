from __future__ import annotations
from pathlib import Path
import json
from collections import defaultdict
from typing import Any


def _safe_read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _score_band_to_text(min_score: int, max_score: int) -> str:
    return f"{min_score} ~ {max_score}"


def build_aggregate_report(output_dir: str | Path) -> Path:
    output_dir = Path(output_dir)
    result_files = sorted(output_dir.glob("*.result.json"))

    total_files = 0
    success_files = 0
    failed_files = 0
    classifier_failed = 0
    imported_files = 0

    by_requirement: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "files": [],
            "findings": [],
            "suggestions": [],
            "missing_evidence": [],
            "recommended_files": [],
            "priority_actions": [],
            "score_bands": [],
            "score_gain_bands": [],
            "frameworks": set(),
        }
    )

    failed_items: list[dict[str, Any]] = []

    for fp in result_files:
        total_files += 1
        data = _safe_read_json(fp)
        if not data:
            failed_files += 1
            failed_items.append(
                {"file_name": fp.name, "reason": "result.json 解析失败"}
            )
            continue

        ok = bool(data.get("ok"))
        if ok:
            success_files += 1
        else:
            failed_files += 1

        step = str(data.get("step", ""))
        if step == "classifier":
            classifier_failed += 1

        if data.get("import_result"):
            imported_files += 1

        raw_evidence = data.get("raw_evidence") or {}
        file_name = raw_evidence.get("file_name", fp.name)

        classification = data.get("classification") or {}
        matches = classification.get("matches") or []

        pre_audit = data.get("pre_audit") or {}
        findings = pre_audit.get("findings") or []
        suggestions = pre_audit.get("suggestions") or []
        gap_report = pre_audit.get("gap_report") or {}

        current_score = gap_report.get("current_score_estimate") or {}
        missing_evidence = gap_report.get("missing_evidence") or []
        recommended_files = gap_report.get("recommended_files") or []
        priority_actions = gap_report.get("priority_actions") or []
        score_gain_estimate = gap_report.get("score_gain_estimate") or []

        if not matches:
            if not ok:
                failed_items.append(
                    {
                        "file_name": file_name,
                        "reason": data.get("message", "未命中 requirement"),
                    }
                )
            continue

        for m in matches:
            req_id = str(m.get("requirement_id", "")).strip() or "UNKNOWN"
            title = str(m.get("title", "")).strip()
            framework = str(m.get("framework", "")).strip()

            key = f"{req_id} - {title}" if title else req_id
            item = by_requirement[key]

            item["files"].append(file_name)
            if framework:
                item["frameworks"].add(framework)

            for x in findings:
                if x not in item["findings"]:
                    item["findings"].append(x)

            for x in suggestions:
                if x not in item["suggestions"]:
                    item["suggestions"].append(x)

            for x in missing_evidence:
                if x not in item["missing_evidence"]:
                    item["missing_evidence"].append(x)

            for x in recommended_files:
                if x not in item["recommended_files"]:
                    item["recommended_files"].append(x)

            for x in priority_actions:
                if x not in item["priority_actions"]:
                    item["priority_actions"].append(x)

            if current_score:
                band = (
                    int(current_score.get("min", 0)),
                    int(current_score.get("max", 0)),
                )
                if band not in item["score_bands"]:
                    item["score_bands"].append(band)

            for sg in score_gain_estimate:
                band = (
                    tuple(sg.get("after_files", [])),
                    int(sg.get("estimated_score_min", 0)),
                    int(sg.get("estimated_score_max", 0)),
                )
                if band not in item["score_gain_bands"]:
                    item["score_gain_bands"].append(band)

    report_path = output_dir / "_aggregate_remediation_report.md"

    lines: list[str] = []
    lines.append("# 证据导入与整改建议总报告")
    lines.append("")
    lines.append("## 一、批处理概况")
    lines.append(f"- 文件总数：{total_files}")
    lines.append(f"- 成功完成：{success_files}")
    lines.append(f"- 失败数量：{failed_files}")
    lines.append(f"- 已进入导入流程：{imported_files}")
    lines.append(f"- 分类失败数量：{classifier_failed}")
    lines.append("")

    if failed_items:
        lines.append("## 二、失败/未命中项")
        for item in failed_items:
            lines.append(f"- **{item['file_name']}**：{item['reason']}")
        lines.append("")

    lines.append("## 三、按控制项汇总整改建议")
    if not by_requirement:
        lines.append("- 本次未形成可汇总的控制项建议。")
        lines.append("")
    else:
        for req_key in sorted(by_requirement.keys()):
            item = by_requirement[req_key]
            lines.append(f"### {req_key}")
            lines.append("")

            if item["frameworks"]:
                lines.append(f"- 所属框架：{'；'.join(sorted(item['frameworks']))}")

            lines.append(f"- 涉及证据数：{len(item['files'])}")
            lines.append(f"- 涉及证据：{'、'.join(sorted(set(item['files']))[:8])}")

            if item["score_bands"]:
                score_text = "；".join(
                    [
                        _score_band_to_text(min_s, max_s)
                        for min_s, max_s in item["score_bands"]
                    ]
                )
                lines.append(f"- 当前估分区间：{score_text}")

            lines.append("")
            lines.append("#### 主要问题")
            if item["findings"]:
                for x in item["findings"][:8]:
                    lines.append(f"- {x}")
            else:
                lines.append("- 暂无")

            lines.append("")
            lines.append("#### 建议动作")
            if item["suggestions"]:
                for x in item["suggestions"][:8]:
                    lines.append(f"- {x}")
            else:
                lines.append("- 暂无")

            lines.append("")
            lines.append("#### 缺失证据")
            if item["missing_evidence"]:
                for x in item["missing_evidence"][:8]:
                    category = x.get("category", "")
                    missing_item = x.get("missing_item", "")
                    importance = x.get("importance", "medium")
                    lines.append(f"- [{importance}] {category}：{missing_item}")
            else:
                lines.append("- 暂无")

            lines.append("")
            lines.append("#### 建议补充文件")
            if item["recommended_files"]:
                for x in item["recommended_files"][:8]:
                    lines.append(
                        f"- **{x.get('file_name', '未命名文件')}**：{x.get('purpose', '')}"
                    )
            else:
                lines.append("- 暂无")

            lines.append("")
            lines.append("#### 优先级建议")
            if item["priority_actions"]:
                for x in item["priority_actions"][:8]:
                    lines.append(f"- {x}")
            else:
                lines.append("- 暂无")

            lines.append("")
            lines.append("#### 预计提分")
            if item["score_gain_bands"]:
                for after_files, smin, smax in item["score_gain_bands"][:8]:
                    files_text = "、".join(after_files) if after_files else "关键缺失文件"
                    lines.append(f"- 补充 {files_text} 后，预计可提升到 **{smin} ~ {smax}**")
            else:
                lines.append("- 暂无")
            lines.append("")

    lines.append("## 四、全局优先整改建议")
    lines.append("- 优先补正式制度、记录、报告类文件，而不是只补截图。")
    lines.append("- 优先补可直接证明控制项落实情况的原始材料。")
    lines.append("- 对非符合项，优先补“制度 + 执行记录 + 证明材料”三件套。")
    lines.append("- 对图片类证据，建议补 OCR 或补配套说明文档，否则分类和审核稳定性较差。")
    lines.append("")

    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path