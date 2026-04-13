from pathlib import Path
import os
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent

# 自动加载项目根目录下的 .env
load_dotenv(BASE_DIR / ".env")

STORAGE_DIR = BASE_DIR / "storage"

# CISO Assistant
CISO_BASE_URL = os.getenv("CISO_BASE_URL", "https://localhost:8443/api")
CISO_API_TOKEN = os.getenv("CISO_API_TOKEN", "")
VERIFY_SSL = os.getenv("CISO_VERIFY_SSL", "false").lower() == "true"

# Ollama
OLLAMA_BASE_URL = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:7b")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "180"))

# I/O
DEFAULT_INPUT_DIR = Path(os.getenv("EVIDENCE_INPUT_DIR", r"D:\evidence_demo\input"))
DEFAULT_OUTPUT_DIR = Path(os.getenv("EVIDENCE_OUTPUT_DIR", r"D:\evidence_demo\output"))

SUPPORTED_EXTS = {".txt", ".md", ".pdf", ".docx", ".doc", ".png", ".jpg", ".jpeg"}