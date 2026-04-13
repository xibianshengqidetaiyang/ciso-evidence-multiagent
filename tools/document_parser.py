from __future__ import annotations
from pathlib import Path
from typing import Optional, Dict, Any
import mimetypes
import subprocess
import sys

from schemas.evidence_models import RawEvidence
from tools.file_fingerprint import sha256_file


TEXT_EXTENSIONS = {".txt", ".md", ".csv", ".json", ".yaml", ".yml"}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"}


class ParseError(Exception):
    pass


def _read_text_file(path: Path) -> str:
    encodings = ["utf-8", "utf-8-sig", "gb18030", "latin-1"]
    for enc in encodings:
        try:
            return path.read_text(encoding=enc)
        except UnicodeDecodeError:
            continue
    raise ParseError(f"无法读取文本编码: {path}")


def _read_pdf(path: Path) -> str:
    try:
        from pypdf import PdfReader
    except Exception as e:
        raise ParseError("读取 PDF 需要安装 pypdf") from e

    try:
        reader = PdfReader(str(path))
        parts = []
        for page in reader.pages:
            parts.append(page.extract_text() or "")
        return "\n".join(parts)
    except Exception as e:
        raise ParseError(f"PDF 解析失败: {e}") from e


def _read_docx(path: Path) -> str:
    try:
        from docx import Document
    except Exception as e:
        raise ParseError("读取 DOCX 需要安装 python-docx") from e

    try:
        doc = Document(str(path))
        return "\n".join([p.text for p in doc.paragraphs])
    except Exception as e:
        raise ParseError(f"DOCX 解析失败: {e}") from e


def _read_doc_by_word(path: Path) -> str:
    """
    Windows 下优先使用 Word COM 读取 .doc
    需要：
    - 安装 pywin32
    - 本机安装 Microsoft Word
    """
    if not sys.platform.startswith("win"):
        raise ParseError("当前不是 Windows，无法使用 Word COM 读取 DOC")

    try:
        import win32com.client  # type: ignore
    except Exception as e:
        raise ParseError("读取 DOC 需要安装 pywin32") from e

    word = None
    doc = None
    try:
        word = win32com.client.Dispatch("Word.Application")
        word.Visible = False
        word.DisplayAlerts = 0

        doc = word.Documents.Open(str(path.resolve()))
        text = doc.Content.Text
        return text or ""
    except Exception as e:
        raise ParseError(f"Word COM 解析 DOC 失败: {e}") from e
    finally:
        try:
            if doc is not None:
                doc.Close(False)
        except Exception:
            pass
        try:
            if word is not None:
                word.Quit()
        except Exception:
            pass


def _read_doc_fallback(path: Path) -> str:
    for cmd in (["antiword", str(path)], ["catdoc", str(path)]):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode == 0:
                return result.stdout
        except FileNotFoundError:
            continue
        except Exception:
            continue
    raise ParseError("DOC fallback 解析失败：未找到 antiword/catdoc，或执行失败")


def _read_doc(path: Path) -> str:
    # 优先 Word COM，其次 antiword/catdoc
    try:
        return _read_doc_by_word(path)
    except ParseError:
        return _read_doc_fallback(path)


def _ocr_image(path: Path) -> str:
    try:
        import pytesseract
        from PIL import Image
    except Exception as e:
        raise ParseError("图片 OCR 需要安装 pillow + pytesseract") from e

    try:
        img = Image.open(path)
        return pytesseract.image_to_string(img)
    except Exception as e:
        raise ParseError(f"图片 OCR 失败: {e}") from e


def _looks_like_noise(text: str) -> bool:
    cleaned = text.strip()
    if not cleaned:
        return True
    if len(cleaned) < 6:
        return True

    printable = sum(ch.isprintable() for ch in cleaned)
    ratio_printable = printable / max(len(cleaned), 1)
    alnum_or_cjk = sum(ch.isalnum() or ("\u4e00" <= ch <= "\u9fff") for ch in cleaned)
    ratio_signal = alnum_or_cjk / max(len(cleaned), 1)

    return ratio_printable < 0.7 or ratio_signal < 0.15


def parse_document(file_path: str, try_ocr: bool = False) -> RawEvidence:
    path = Path(file_path)
    if not path.exists():
        raise ParseError(f"文件不存在: {file_path}")
    if not path.is_file():
        raise ParseError(f"不是文件: {file_path}")

    ext = path.suffix.lower()
    mime_type, _ = mimetypes.guess_type(str(path))
    size = path.stat().st_size
    sha256 = sha256_file(path)

    extracted_text: Optional[str] = None
    is_binary = True
    metadata: Dict[str, Any] = {"try_ocr": try_ocr}

    if size == 0:
        return RawEvidence(
            file_path=str(path),
            file_name=path.name,
            extension=ext,
            mime_type=mime_type,
            size=size,
            sha256=sha256,
            extracted_text="",
            is_binary=False,
            metadata=metadata,
        )

    try:
        if ext in TEXT_EXTENSIONS:
            extracted_text = _read_text_file(path)
            is_binary = False
        elif ext == ".pdf":
            extracted_text = _read_pdf(path)
        elif ext == ".docx":
            extracted_text = _read_docx(path)
        elif ext == ".doc":
            try:
                extracted_text = _read_doc(path)
            except ParseError as e:
                extracted_text = None
                metadata["parser_warning"] = str(e)
                metadata["text_extract_failed"] = True
        elif ext in IMAGE_EXTENSIONS:
            if try_ocr:
                try:
                    extracted_text = _ocr_image(path)
                except ParseError as e:
                    extracted_text = None
                    metadata["parser_warning"] = str(e)
                    metadata["text_extract_failed"] = True
            else:
                extracted_text = None
                metadata["ocr_skipped"] = True
        else:
            extracted_text = None
            metadata["unsupported_text_extraction"] = True
    except ParseError:
        raise
    except Exception as e:
        extracted_text = None
        metadata["parser_warning"] = f"未知解析异常: {e}"
        metadata["text_extract_failed"] = True

    return RawEvidence(
        file_path=str(path),
        file_name=path.name,
        extension=ext,
        mime_type=mime_type,
        size=size,
        sha256=sha256,
        extracted_text=extracted_text,
        is_binary=is_binary,
        metadata=metadata,
    )


def is_empty_evidence(raw: RawEvidence) -> bool:
    if raw.size == 0:
        return True
    if raw.extracted_text is None:
        return False
    return len(raw.extracted_text.strip()) == 0


def is_noise_evidence(raw: RawEvidence) -> bool:
    if raw.extracted_text is None:
        return False
    return _looks_like_noise(raw.extracted_text)