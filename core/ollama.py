import json
from typing import Any
from urllib import error, request


DEFAULT_OLLAMA_HOST = "http://127.0.0.1:11434"


class OllamaClient:
    """Small client for local Ollama chat requests with graceful fallback."""

    def __init__(self, host: str = DEFAULT_OLLAMA_HOST, timeout: int = 30):
        self.host = host.rstrip("/")
        self.timeout = timeout

    def chat(self, model: str, messages: list[dict[str, str]], format_schema: dict[str, Any] | None = None) -> dict:
        payload: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "stream": False,
        }
        if format_schema:
            payload["format"] = format_schema

        body = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.host}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with request.urlopen(req, timeout=self.timeout) as response:
            return json.loads(response.read().decode("utf-8"))

    def is_available(self) -> bool:
        req = request.Request(f"{self.host}/api/tags", method="GET")
        try:
            with request.urlopen(req, timeout=5) as response:
                return response.status == 200
        except (error.URLError, error.HTTPError, TimeoutError):
            return False
