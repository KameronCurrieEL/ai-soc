"""The one place the project talks to a language model.

The rest of the code depends only on the LLM protocol ("give me text for this prompt"),
so swapping Ollama for another backend means adding one class here. See docs/decisions.md.
"""

from __future__ import annotations

import json
import time
import urllib.request
from dataclasses import dataclass
from typing import Iterator, Protocol

from soc.checks import resolve_ollama_url


class LLM(Protocol):
    name: str

    def complete(self, system: str, user: str, schema: dict | None = None) -> str:
        """Return the model's raw text reply. Callers must validate it."""
        ...


@dataclass
class OllamaLLM:
    """Local model via Ollama's /api/chat. Free, offline, alert data never leaves the machine."""

    url: str
    model: str
    timeout_s: float = 180.0   # a 3B model on a laptop CPU/GPU can take a while
    temperature: float = 0.0   # deterministic as possible: same alert -> same triage
    max_tokens: int = 400      # hard cap: ~4-8 tokens/s on CPU, and small models ramble
    last_duration_s: float = 0.0
    last_stop_reason: str = ""  # "stop" = finished, "length" = cut off by max_tokens

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    def build_request(self, system: str, user: str, schema: dict | None = None) -> dict:
        body: dict = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "stream": False,
            "options": {"temperature": self.temperature, "num_predict": self.max_tokens},
        }
        if schema is not None:
            body["format"] = schema  # structured outputs: constrain the reply to this JSON Schema
        return body

    def complete(self, system: str, user: str, schema: dict | None = None) -> str:
        req = urllib.request.Request(
            f"{self.url}/api/chat",
            data=json.dumps(self.build_request(system, user, schema)).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            payload = json.load(resp)
        self.last_duration_s = time.monotonic() - start
        self.last_stop_reason = payload.get("done_reason", "")
        return payload.get("message", {}).get("content", "")

    def stream(self, messages: list[dict], num_ctx: int = 4096, fmt: dict | None = None) -> Iterator[str]:
        """Chat with streaming: yield text chunks as the model produces them (Ollama sends NDJSON lines).

        Used by the dashboard assistant so the analyst sees the answer forming instead of
        waiting ~30 s on CPU. num_ctx 4096: room for the incident context + a short history.
        `fmt` is an optional JSON Schema (structured output): the responder streams schema-constrained JSON.
        """
        body = {"model": self.model, "messages": messages, "stream": True,
                "options": {"temperature": self.temperature, "num_predict": self.max_tokens, "num_ctx": num_ctx}}
        if fmt is not None:
            body["format"] = fmt
        req = urllib.request.Request(f"{self.url}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        start = time.monotonic()
        with urllib.request.urlopen(req, timeout=self.timeout_s) as resp:
            for line in resp:
                if not line.strip():
                    continue
                part = json.loads(line)
                if part.get("error"):
                    raise RuntimeError(part["error"])
                chunk = part.get("message", {}).get("content", "")
                if chunk:
                    yield chunk
                if part.get("done"):
                    self.last_stop_reason = part.get("done_reason", "")
                    break
        self.last_duration_s = time.monotonic() - start


def llm_from_env(env: dict[str, str]) -> OllamaLLM:
    url = resolve_ollama_url(env)
    if not url:
        raise RuntimeError("no OLLAMA_URL and could not detect the Windows host IP")
    return OllamaLLM(url=url, model=env.get("OLLAMA_MODEL", "qwen2.5:3b"))
