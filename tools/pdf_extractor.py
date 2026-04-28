from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import fitz  # pymupdf
from pypdf import PdfReader

from app.config import (
    PDF_ENABLE_OCR,
    PDF_TEXT_MIN_CHARS,
    PDF_MIN_AVG_CHARS_PER_PAGE,
    PDF_RENDER_DPI,
    EXTRACTED_TEXT_DIR,
    PDF_RENDERED_PAGES_DIR,
)


class PdfExtractError(Exception):
    """PDF 提取异常"""
    pass


class PdfExtractor:
    def __init__(self) -> None:
        self._ocr_engine = None

    def extract(self, pdf_path: str) -> Dict[str, Any]:
        """
        统一 PDF 抽取入口：
        1. 先尝试原生文本抽取
        2. 如果文本质量不足，再走 OCR
        """
        pdf_file = Path(pdf_path)
        if not pdf_file.exists():
            raise PdfExtractError(f"PDF 不存在: {pdf_path}")

        native_result = self._extract_native_text(pdf_file)

        if self._is_text_good(native_result["text"], native_result["page_count"]):
            self._write_text_cache(pdf_file, native_result["text"], "text_pdf")
            return {
                "ok": True,
                "method": "text_pdf",
                "text": native_result["text"],
                "page_count": native_result["page_count"],
                "warnings": native_result["warnings"],
            }

        if not PDF_ENABLE_OCR:
            return {
                "ok": False,
                "method": "text_pdf",
                "text": native_result["text"],
                "page_count": native_result["page_count"],
                "warnings": native_result["warnings"]
                + ["原生文本抽取质量不足，且 OCR 未开启"],
            }

        ocr_result = self._extract_ocr_text(pdf_file)
        self._write_text_cache(pdf_file, ocr_result["text"], "ocr_pdf")

        return {
            "ok": bool(ocr_result["text"].strip()),
            "method": "ocr_pdf",
            "text": ocr_result["text"],
            "page_count": ocr_result["page_count"],
            "warnings": native_result["warnings"] + ocr_result["warnings"],
        }

    def _extract_native_text(self, pdf_file: Path) -> Dict[str, Any]:
        warnings: List[str] = []
        try:
            reader = PdfReader(str(pdf_file))
            parts: List[str] = []

            for page in reader.pages:
                try:
                    parts.append(page.extract_text() or "")
                except Exception as e:
                    warnings.append(f"某一页原生文本抽取失败: {e}")
                    parts.append("")

            text = "\n".join(parts).strip()

            return {
                "text": text,
                "page_count": len(reader.pages),
                "warnings": warnings,
            }
        except Exception as e:
            return {
                "text": "",
                "page_count": 0,
                "warnings": [f"原生文本抽取失败: {e}"],
            }

    def _extract_ocr_text(self, pdf_file: Path) -> Dict[str, Any]:
        warnings: List[str] = []
        all_text: List[str] = []

        doc = fitz.open(str(pdf_file))
        render_dir = Path(PDF_RENDERED_PAGES_DIR) / pdf_file.stem
        render_dir.mkdir(parents=True, exist_ok=True)

        zoom = PDF_RENDER_DPI / 72.0
        matrix = fitz.Matrix(zoom, zoom)

        for i, page in enumerate(doc):
            img_path = render_dir / f"page_{i + 1}.png"
            try:
                pix = page.get_pixmap(matrix=matrix, alpha=False)
                pix.save(str(img_path))
            except Exception as e:
                warnings.append(f"第 {i + 1} 页渲染失败: {e}")
                continue

            try:
                page_text = self._ocr_image(img_path)
                if page_text.strip():
                    all_text.append(page_text)
                else:
                    warnings.append(f"第 {i + 1} 页 OCR 结果为空")
            except Exception as e:
                warnings.append(f"第 {i + 1} 页 OCR 失败: {e}")

        return {
            "text": "\n".join(t for t in all_text if t).strip(),
            "page_count": len(doc),
            "warnings": warnings,
        }

    def _ocr_image(self, image_path: Path) -> str:
        """
        仅支持 PaddleOCR 2.x 的稳定调用方式
        """
        engine = self._get_ocr_engine()

        try:
            result = engine.ocr(str(image_path), cls=False)
        except TypeError:
            result = engine.ocr(str(image_path))

        texts = self._collect_texts(result)
        return "\n".join(t.strip() for t in texts if isinstance(t, str) and t.strip())

    def _get_ocr_engine(self):
        """
        延迟加载 OCR。
        明确限制为 PaddleOCR 2.x，避免 3.x 的不稳定行为。
        """
        if self._ocr_engine is not None:
            return self._ocr_engine

        try:
            import paddleocr
            from paddleocr import PaddleOCR
        except ImportError as e:
            raise PdfExtractError(
                "未安装 paddleocr，请先执行 pip install -r requirements.txt"
            ) from e

        version = getattr(paddleocr, "__version__", "")
        if version.startswith("3."):
            raise PdfExtractError(
                f"当前安装的是 PaddleOCR {version}，请改用 PaddleOCR 2.x 固定版本"
            )

        try:
            self._ocr_engine = PaddleOCR(
                use_angle_cls=False,
                lang="ch",
                show_log=False,
            )
            return self._ocr_engine
        except Exception as e:
            raise PdfExtractError(f"PaddleOCR 初始化失败: {e}") from e

    def _collect_texts(self, obj: Any) -> List[str]:
        texts: List[str] = []

        if obj is None:
            return texts

        if isinstance(obj, str):
            return [obj]

        if isinstance(obj, tuple):
            if len(obj) == 2 and isinstance(obj[0], str):
                texts.append(obj[0])
            else:
                for item in obj:
                    texts.extend(self._collect_texts(item))
            return texts

        if isinstance(obj, list):
            for item in obj:
                texts.extend(self._collect_texts(item))
            return texts

        if isinstance(obj, dict):
            for v in obj.values():
                texts.extend(self._collect_texts(v))
            return texts

        return texts

    def _is_text_good(self, text: str, page_count: int) -> bool:
        if not text or not text.strip():
            return False

        total_chars = len(text.strip())
        avg_chars = total_chars / max(page_count, 1)

        return (
            total_chars >= PDF_TEXT_MIN_CHARS
            or avg_chars >= PDF_MIN_AVG_CHARS_PER_PAGE
        )

    def _write_text_cache(self, pdf_file: Path, text: str, method: str) -> None:
        cache_dir = Path(EXTRACTED_TEXT_DIR)
        cache_dir.mkdir(parents=True, exist_ok=True)

        out_file = cache_dir / f"{pdf_file.stem}.{method}.txt"
        out_file.write_text(text, encoding="utf-8", errors="ignore")