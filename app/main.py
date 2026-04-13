from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.config import DEFAULT_INPUT_DIR, DEFAULT_OUTPUT_DIR
from flows.evidence_flow import EvidenceFlow
from tools.aggregate_report import build_aggregate_report


SUPPORTED_EXTENSIONS = {
    ".pdf",
    ".docx",
    ".doc",
    ".md",
    ".txt",
    ".png",
    ".jpg",
    ".jpeg",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="CISO Assistant 多角色证据导入入口"
    )
    parser.add_argument("--assessment-id", default=None, help="目标 assessment 的 ID")
    parser.add_argument("--assessment-name", default=None, help="目标 assessment 的名称")
    parser.add_argument(
        "--assessment-framework",
        default=None,
        help="目标 assessment 的框架名，用于同名 assessment 消歧",
    )
    parser.add_argument(
        "--assessment-version",
        default=None,
        help="目标 assessment 的版本，用于同名 assessment 消歧",
    )
    parser.add_argument(
        "--input-dir",
        default=str(DEFAULT_INPUT_DIR),
        help="输入目录，默认读取 app.config.DEFAULT_INPUT_DIR",
    )
    parser.add_argument(
        "--output-dir",
        default=str(DEFAULT_OUTPUT_DIR),
        help="输出目录，默认读取 app.config.DEFAULT_OUTPUT_DIR",
    )
    parser.add_argument(
        "--try-ocr",
        action="store_true",
        help="是否对图片类证据尝试 OCR",
    )
    parser.add_argument(
        "--no-reuse-existing",
        action="store_true",
        help="关闭重名证据复用，默认开启复用已有证据",
    )
    return parser.parse_args()


def sanitize_stem(name: str) -> str:
    bad_chars = ['\\', '/', ':', '*', '?', '"', '<', '>', '|']
    for ch in bad_chars:
        name = name.replace(ch, "_")
    return name


def list_input_files(input_dir: Path) -> list[Path]:
    if not input_dir.exists():
        return []

    files: list[Path] = []
    for p in input_dir.iterdir():
        if p.is_file() and p.suffix.lower() in SUPPORTED_EXTENSIONS:
            files.append(p)

    files.sort(key=lambda x: x.name.lower())
    return files


def write_json(path: Path, data) -> None:
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def main() -> None:
    args = parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    files = list_input_files(input_dir)
    if not files:
        print(f"输入目录没有可处理文件：{input_dir}")
        return

    print(f"开始处理，共 {len(files)} 个文件")
    print("------------------------------------------------------------")

    flow = EvidenceFlow()
    summary: list[dict] = []

    for fp in files:
        print(f"[处理中] {fp.name}")
        try:
            result = flow.run(
                file_path=str(fp),
                assessment_id=args.assessment_id,
                assessment_name=args.assessment_name,
                assessment_framework=args.assessment_framework,
                assessment_version=args.assessment_version,
                try_ocr=args.try_ocr,
                reuse_existing_evidence=not args.no_reuse_existing,
            )

            result_path = output_dir / f"{sanitize_stem(fp.stem)}.result.json"
            write_json(result_path, result.model_dump())

            summary_item = {
                "file_name": fp.name,
                "ok": result.ok,
                "step": result.step,
                "message": result.message,
            }
            summary.append(summary_item)

            print(
                f"-> 完成 | ok={result.ok} | step={result.step} | message={result.message}"
            )

        except Exception as e:
            err_item = {
                "file_name": fp.name,
                "ok": False,
                "step": "main",
                "message": str(e),
            }
            summary.append(err_item)

            result_path = output_dir / f"{sanitize_stem(fp.stem)}.result.json"
            write_json(result_path, err_item)

            print(f"-> 完成 | ok=False | step=main | message={e}")

    print("------------------------------------------------------------")

    summary_file = output_dir / "_summary.json"
    write_json(summary_file, summary)

    aggregate_report = build_aggregate_report(output_dir)

    print(f"全部处理完成，结果目录：{output_dir}")
    print(f"汇总文件：{summary_file}")
    print(f"总建议报告：{aggregate_report}")


if __name__ == "__main__":
    main()