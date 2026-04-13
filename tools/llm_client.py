from __future__ import annotations
from typing import Any, Dict
import requests
import json

from app.config import OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_TIMEOUT


class LlmError(Exception):
    pass


class OllamaClient:
    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        model: str = OLLAMA_MODEL,
        timeout: int = OLLAMA_TIMEOUT,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self.session = requests.Session()

    def chat_json(self, system_prompt: str, user_prompt: str) -> Dict[str, Any]:
        url = f"{self.base_url}/api/chat"
        payload = {
            "model": self.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        }

        resp = self.session.post(url, json=payload, timeout=self.timeout)
        if resp.status_code >= 400:
            raise LlmError(f"Ollama 调用失败: {resp.status_code} {resp.text}")

        data = resp.json()
        content = (data.get("message", {}).get("content") or data.get("response") or "").strip()
        if not content:
            raise LlmError("Ollama 返回为空")

        cleaned = self._extract_json(content)
        try:
            return json.loads(cleaned)
        except Exception as e:
            raise LlmError(f"Ollama 返回不是合法 JSON: {content[:500]}") from e

    @staticmethod
    def _extract_json(text: str) -> str:
        text = text.strip()
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:].strip()
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start:end + 1]
        return text
