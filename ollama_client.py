"""
ollama_client.py
================
Wrapper giao tiếp với Ollama local API (http://localhost:11434).
Hỗ trợ 2 model:
  - llama3.1:8b  → Architect Agent + Auditor Agent
  - qwen2.5-coder:7b → Attacker Agent

Ollama không hỗ trợ response_format=json_object như OpenAI,
nên module này có JSON extraction riêng từ raw text.
"""

import json
import re
import time
import logging
import os
from typing import Any, Dict, Optional, List

import requests
from dotenv import load_dotenv

load_dotenv()
log = logging.getLogger("ollama_client")

# ── Defaults ──────────────────────────────────────────────────────────────────
OLLAMA_BASE_URL       = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
MODEL_ARCHITECT       = os.getenv("OLLAMA_ARCHITECT_MODEL", "llama3.1:8b")
MODEL_ATTACKER        = os.getenv("OLLAMA_ATTACKER_MODEL",  "qwen2.5-coder:7b")
MODEL_AUDITOR         = os.getenv("OLLAMA_AUDITOR_MODEL",   "llama3.1:8b")
OLLAMA_ENABLED        = os.getenv("OLLAMA_ENABLED", "true").lower() == "true"

# Timeout riêng cho từng loại model
TIMEOUT_FAST   = int(os.getenv("OLLAMA_TIMEOUT_FAST",   "30"))   # short prompt
TIMEOUT_MEDIUM = int(os.getenv("OLLAMA_TIMEOUT_MEDIUM", "60"))   # medium prompt
TIMEOUT_LONG   = int(os.getenv("OLLAMA_TIMEOUT_LONG",   "120"))  # complex reasoning


class OllamaClient:
    """
    Client gọi Ollama REST API.

    Dùng endpoint /api/chat với format messages[].
    Tự động retry tối đa max_retries lần khi gặp timeout hoặc lỗi kết nối.
    """

    def __init__(
        self,
        base_url: str = OLLAMA_BASE_URL,
        max_retries: int = 2,
    ):
        self.base_url    = base_url.rstrip("/")
        self.max_retries = max_retries
        self._session    = requests.Session()
        self._session.headers.update({"Content-Type": "application/json"})

    # ── Public API ────────────────────────────────────────────────────────────

    def ping(self) -> bool:
        """Kiểm tra Ollama có đang chạy không."""
        try:
            r = self._session.get(f"{self.base_url}/api/tags", timeout=5)
            return r.status_code == 200
        except Exception:
            return False

    def list_models(self) -> List[str]:
        """Trả về list model đang có trong Ollama."""
        try:
            r = self._session.get(f"{self.base_url}/api/tags", timeout=5)
            if r.status_code == 200:
                data = r.json()
                return [m["name"] for m in data.get("models", [])]
        except Exception:
            pass
        return []

    def chat(
        self,
        model: str,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        timeout: int = TIMEOUT_MEDIUM,
        expect_json: bool = True,
    ) -> Optional[str]:
        """
        Gọi Ollama /api/chat và trả về raw text response.

        Args:
            model:       Tên model (vd: "llama3.1:8b")
            prompt:      User message
            system:      System message (optional)
            temperature: Sampling temperature
            timeout:     HTTP timeout (seconds)
            expect_json: Nếu True, thêm instruction vào prompt để ép JSON output

        Returns:
            Raw text response từ model, hoặc None nếu lỗi
        """
        messages = []
        if system:
            messages.append({"role": "system", "content": system})

        user_content = prompt
        if expect_json:
            user_content += "\n\nIMPORTANT: Respond ONLY with a valid JSON object. No markdown, no explanation."
        messages.append({"role": "user", "content": user_content})

        payload = {
            "model":   model,
            "messages": messages,
            "stream":  False,
            "options": {
                "temperature": temperature,
                "num_predict": 1024,
            },
        }

        for attempt in range(self.max_retries + 1):
            try:
                log.debug(f"[Ollama] {model} attempt {attempt+1}/{self.max_retries+1}")
                resp = self._session.post(
                    f"{self.base_url}/api/chat",
                    json=payload,
                    timeout=timeout,
                )
                resp.raise_for_status()
                data = resp.json()
                text = data.get("message", {}).get("content", "")
                log.debug(f"[Ollama] {model} → {len(text)} chars")
                return text
            except requests.exceptions.Timeout:
                log.warning(f"[Ollama] Timeout (attempt {attempt+1}) — model={model}")
                if attempt < self.max_retries:
                    time.sleep(2)
            except requests.exceptions.ConnectionError:
                log.error(f"[Ollama] ConnectionError — is Ollama running at {self.base_url}?")
                return None
            except Exception as e:
                log.error(f"[Ollama] Unexpected error: {e}")
                return None
        return None

    def chat_json(
        self,
        model: str,
        prompt: str,
        system: str = "",
        temperature: float = 0.1,
        timeout: int = TIMEOUT_MEDIUM,
    ) -> Optional[Dict[str, Any]]:
        """
        Gọi model và trả về Python dict đã parse từ JSON.
        Tự động extract JSON block từ raw text nếu model bọc trong markdown.
        """
        raw = self.chat(
            model=model,
            prompt=prompt,
            system=system,
            temperature=temperature,
            timeout=timeout,
            expect_json=True,
        )
        if raw is None:
            return None
        return self._extract_json(raw)

    # ── Convenience shortcuts ─────────────────────────────────────────────────

    def architect(self, prompt: str, system: str = "", temperature: float = 0.3) -> Optional[Dict]:
        return self.chat_json(MODEL_ARCHITECT, prompt, system, temperature, TIMEOUT_MEDIUM)

    def attacker(self, prompt: str, system: str = "", temperature: float = 0.5) -> Optional[Dict]:
        return self.chat_json(MODEL_ATTACKER, prompt, system, temperature, TIMEOUT_MEDIUM)

    def auditor(self, prompt: str, system: str = "", temperature: float = 0.1) -> Optional[Dict]:
        return self.chat_json(MODEL_AUDITOR, prompt, system, temperature, TIMEOUT_LONG)

    # ── JSON Extraction ───────────────────────────────────────────────────────

    @staticmethod
    def _extract_json(text: str) -> Optional[Dict[str, Any]]:
        """
        Extract JSON từ raw LLM output. Xử lý các trường hợp:
          1. Pure JSON (ideal)
          2. JSON bọc trong ```json ... ```
          3. JSON bọc trong ``` ... ```
          4. JSON xuất hiện ở đâu đó trong text (tìm bằng regex)
        """
        text = text.strip()

        # Case 1: thử parse trực tiếp
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Case 2 & 3: extract từ markdown code block
        code_block = re.search(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", text, re.DOTALL)
        if code_block:
            try:
                return json.loads(code_block.group(1))
            except json.JSONDecodeError:
                pass

        # Case 4: tìm JSON object đầu tiên trong text
        brace_match = re.search(r"\{.*\}", text, re.DOTALL)
        if brace_match:
            try:
                return json.loads(brace_match.group(0))
            except json.JSONDecodeError:
                pass

        # Case 5: tìm JSON array đầu tiên
        bracket_match = re.search(r"\[.*\]", text, re.DOTALL)
        if bracket_match:
            try:
                return json.loads(bracket_match.group(0))
            except json.JSONDecodeError:
                pass

        log.warning(f"[Ollama] Không extract được JSON từ response: {text[:200]}")
        return None

    def check_models_available(self) -> Dict[str, bool]:
        """Kiểm tra xem các model cần thiết có sẵn trong Ollama không."""
        available = self.list_models()
        # Ollama lưu model dưới dạng "name:tag", normalize để so sánh
        available_set = set(m.split(":")[0] + ":" + m.split(":")[1] if ":" in m else m + ":latest"
                           for m in available)
        available_full = set(available)

        def is_available(model_name: str) -> bool:
            return (model_name in available_full or
                    model_name in available_set or
                    any(model_name in a for a in available_full))

        return {
            "architect": is_available(MODEL_ARCHITECT),
            "attacker":  is_available(MODEL_ATTACKER),
            "auditor":   is_available(MODEL_AUDITOR),
        }


# ── Singleton instance dùng chung toàn project ────────────────────────────────
_default_client: Optional[OllamaClient] = None


def get_ollama_client() -> OllamaClient:
    """Trả về singleton OllamaClient."""
    global _default_client
    if _default_client is None:
        _default_client = OllamaClient()
    return _default_client


# ── Quick self-test ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    client = OllamaClient()

    print(f"Ollama ping: {client.ping()}")
    print(f"Models available: {client.list_models()}")
    print(f"Model check: {client.check_models_available()}")

    if client.ping():
        result = client.architect(
            prompt='Return a JSON object with key "hello" and value "world".',
            system="You are a helpful assistant.",
        )
        print(f"Test response: {result}")
