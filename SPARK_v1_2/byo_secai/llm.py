from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import json

import requests
import re


class LLMError(RuntimeError):
    """Raised when an LLM backend call fails."""


@dataclass
class LLMResponse:
    text: str
    model: str
    took_ms: int
    mode: str  # 'ollama' | 'stub'
    meta: Optional[Dict[str, Any]] = None


class BaseLLM:
    """Minimal interface used by the workflow layer."""

    def generate(self, prompt: str, system: Optional[str] = None) -> LLMResponse:  # pragma: no cover
        raise NotImplementedError()

    def generate_stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        on_token: Optional[callable] = None,
    ) -> LLMResponse:
        """Optional streaming generation.

        Default behavior falls back to non-streaming generate().
        """
        return self.generate(prompt=prompt, system=system)


class OllamaLLM(BaseLLM):
    def __init__(
        self,
        host: str = "http://localhost:11434",
        model: str = "llama3.1",
        temperature: float = 0.2,
        timeout_s: int = 120,
    ):
        self.host = host.rstrip("/")
        self.model = model
        self.temperature = float(temperature)
        self.timeout_s = int(timeout_s)

    # --- health / probe -------------------------------------------------

    def probe(self) -> Dict[str, Any]:
        """Returns a structured probe result for UI display."""
        out: Dict[str, Any] = {
            "host": self.host,
            "ok": False,
            "root_ok": False,
            "tags_ok": False,
            "generate_endpoint": None,  # True/False/None
            "chat_endpoint": None,      # True/False/None
            "openai_endpoint": None,    # True/False/None
            "error": None,
        }

        try:
            r = requests.get(f"{self.host}/", timeout=5)
            out["root_ok"] = r.status_code == 200
        except Exception as e:
            out["error"] = f"Root check failed: {e}"
            return out

        try:
            r = requests.get(f"{self.host}/api/tags", timeout=8)
            out["tags_ok"] = r.status_code == 200
        except Exception:
            out["tags_ok"] = False

        # Endpoint existence checks:
        # We avoid HEAD/OPTIONS because some setups don't support them.
        # A 404 means the route isn't implemented by whatever is on that port.
        out["generate_endpoint"] = self._endpoint_exists("/api/generate")
        out["chat_endpoint"] = self._endpoint_exists("/api/chat")
        out["openai_endpoint"] = self._endpoint_exists("/v1/chat/completions")

        out["ok"] = bool(out["root_ok"] and (out["tags_ok"] or out["generate_endpoint"] or out["chat_endpoint"] or out["openai_endpoint"]))
        return out

    def health(self) -> bool:
        """Backward-compatible boolean health used by get_llm()."""
        p = self.probe()
        return bool(p.get("ok"))

    def _endpoint_exists(self, path: str) -> bool:
        try:
            r = requests.post(f"{self.host}{path}", json={}, timeout=4)
            return r.status_code != 404
        except Exception:
            # If the port is open but the call fails, treat as unknown-but-present
            return True

    # --- generation ------------------------------------------------------

    @staticmethod
    def _clean_model_text(text: str) -> str:
        """Remove common model preambles ("Thinking..."), and hidden reasoning blocks.

        Keeps artifacts clean and prevents chatty debug output from leaking into reports.
        """
        if not text:
            return ""
        t = text.strip()

        # Strip <think>...</think> blocks (some models emit these)
        t = re.sub(r"<think>.*?</think>", "", t, flags=re.IGNORECASE | re.DOTALL).strip()

        # Strip Ollama-style: Thinking...  ...done thinking.
        # Remove the whole block if present.
        t = re.sub(
            r"^\s*Thinking\.{3}\s*.*?\.{3}done thinking\.?\s*",
            "",
            t,
            flags=re.IGNORECASE | re.DOTALL,
        ).strip()

        # Some models prepend single-line reasoning labels
        t = re.sub(r"^\s*(assistant|reasoning)\s*:\s*", "", t, flags=re.IGNORECASE).strip()
        return t

    def generate(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        start = time.time()

        # Try classic /api/generate first (works on most Ollama installs)
        try:
            text, meta = self._generate_via_generate(prompt=prompt, system=system)
            text = self._clean_model_text(text)
            return LLMResponse(
                text=text,
                model=meta.get("model", self.model),
                took_ms=int((time.time() - start) * 1000),
                mode="ollama",
                meta=meta,
            )
        except LLMError as e1:
            # If it's an endpoint issue, fall through to other APIs
            e1s = str(e1)

        # Try /api/chat (newer style)
        try:
            text, meta = self._generate_via_chat(prompt=prompt, system=system)
            text = self._clean_model_text(text)
            return LLMResponse(
                text=text,
                model=meta.get("model", self.model),
                took_ms=int((time.time() - start) * 1000),
                mode="ollama",
                meta=meta,
            )
        except LLMError as e2:
            e2s = str(e2)

        # Try OpenAI-compat endpoint /v1/chat/completions (supported by some Ollama builds / proxies)
        try:
            text, meta = self._generate_via_openai(prompt=prompt, system=system)
            text = self._clean_model_text(text)
            return LLMResponse(
                text=text,
                model=meta.get("model", self.model),
                took_ms=int((time.time() - start) * 1000),
                mode="ollama",
                meta=meta,
            )
        except LLMError as e3:
            e3s = str(e3)

        raise LLMError(
            "Ollama generation failed. Tried /api/generate, /api/chat, and /v1/chat/completions. "
            f"Errors: generate=({e1s}) chat=({e2s}) openai=({e3s})"
        )

    def generate_stream(
        self,
        prompt: str,
        system: Optional[str] = None,
        on_token: Optional[callable] = None,
    ) -> LLMResponse:
        """Stream tokens from Ollama when possible.

        Uses /api/chat with stream=true. If streaming fails, falls back to generate().
        """
        start = time.time()

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": True,
            "options": {"temperature": self.temperature},
        }

        try:
            with requests.post(
                f"{self.host}/api/chat",
                json=payload,
                stream=True,
                timeout=(5, self.timeout_s),
            ) as r:
                if r.status_code == 404:
                    return self.generate(prompt=prompt, system=system)

                try:
                    r.raise_for_status()
                except Exception as e:
                    raise LLMError(f"/api/chat stream failed: status={r.status_code} body={r.text[:500]!r} err={e}")

                buf: list[str] = []
                meta: Dict[str, Any] = {"model": self.model}

                for raw_line in r.iter_lines(decode_unicode=True):
                    if not raw_line:
                        continue
                    try:
                        data = json.loads(raw_line)
                    except Exception:
                        # Some proxies send non-JSON keepalives; ignore.
                        continue

                    if isinstance(data, dict):
                        if data.get("done") is True:
                            meta.update(data)
                            break
                        msg = data.get("message") or {}
                        chunk = (msg.get("content") or "")
                        if chunk:
                            buf.append(chunk)
                            if on_token:
                                on_token(chunk)

                text = self._clean_model_text("".join(buf))
                return LLMResponse(
                    text=text,
                    model=meta.get("model", self.model),
                    took_ms=int((time.time() - start) * 1000),
                    mode="ollama",
                    meta=meta,
                )
        except LLMError:
            raise
        except Exception:
            # Any streaming failure should not brick the UX.
            return self.generate(prompt=prompt, system=system)
    def _generate_via_generate(self, prompt: str, system: Optional[str]) -> Tuple[str, Dict[str, Any]]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": self.temperature},
        }
        if system:
            payload["system"] = system

        try:
            r = requests.post(f"{self.host}/api/generate", json=payload, timeout=self.timeout_s)
        except Exception as e:
            raise LLMError(f"/api/generate request failed: {e}")

        if r.status_code == 404:
            raise LLMError("/api/generate returned 404 (route not found).")

        try:
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            raise LLMError(f"/api/generate failed: status={r.status_code} body={r.text[:500]!r} err={e}")

        text = (data.get("response") or "").strip()
        if not text:
            raise LLMError(f"/api/generate returned an empty response for model={self.model}.")
        return text, data

    def _generate_via_chat(self, prompt: str, system: Optional[str]) -> Tuple[str, Dict[str, Any]]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "options": {"temperature": self.temperature},
        }

        try:
            r = requests.post(f"{self.host}/api/chat", json=payload, timeout=self.timeout_s)
        except Exception as e:
            raise LLMError(f"/api/chat request failed: {e}")

        if r.status_code == 404:
            raise LLMError("/api/chat returned 404 (route not found).")

        try:
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            raise LLMError(f"/api/chat failed: status={r.status_code} body={r.text[:500]!r} err={e}")

        msg = (data.get("message") or {})
        text = (msg.get("content") or "").strip()
        if not text:
            raise LLMError("/api/chat returned an empty message.")
        return text, data

    def _generate_via_openai(self, prompt: str, system: Optional[str]) -> Tuple[str, Dict[str, Any]]:
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
        }

        headers = {"Content-Type": "application/json"}

        try:
            r = requests.post(f"{self.host}/v1/chat/completions", json=payload, headers=headers, timeout=self.timeout_s)
        except Exception as e:
            raise LLMError(f"/v1/chat/completions request failed: {e}")

        if r.status_code == 404:
            raise LLMError("/v1/chat/completions returned 404 (route not found).")

        try:
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            raise LLMError(f"/v1/chat/completions failed: status={r.status_code} body={r.text[:500]!r} err={e}")

        choices = data.get("choices") or []
        if not choices:
            raise LLMError("/v1/chat/completions returned no choices.")
        msg = (choices[0].get("message") or {})
        text = (msg.get("content") or "").strip()
        if not text:
            raise LLMError("/v1/chat/completions returned empty content.")
        return text, {"model": data.get("model", self.model)}


class StubLLM(BaseLLM):
    def __init__(self, model: str = "stub"):
        self.model = model

    def generate(self, prompt: str, system: Optional[str] = None) -> LLMResponse:
        start = time.time()
        trimmed = prompt.strip().replace("\n", " ")
        if len(trimmed) > 240:
            trimmed = trimmed[:240] + "..."
        text = (
            "[STUB MODE] I couldn't generate via Ollama, so this is a mocked draft.\n\n"
            f"Requested: {trimmed}\n\n"
            "Next steps: verify Ollama host/model in Settings, then re-generate."
        )
        return LLMResponse(text=text, model=self.model, took_ms=int((time.time() - start) * 1000), mode="stub")