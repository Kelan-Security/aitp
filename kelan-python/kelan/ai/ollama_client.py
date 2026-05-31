"""
Ollama Client — Local LLM inference via HTTP.
Connects to Ollama running locally or on the MacBook (OLLAMA_ENDPOINT).
NO external API calls. NO API keys. NO cloud dependencies.
"""
import asyncio
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
import structlog
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from .prompts import build_evaluation_prompt, VERIFY_PROMPT

log = structlog.get_logger()


class Verdict(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MONITOR = "MONITOR"


@dataclass
class TrustVerdict:
    verdict: Verdict
    confidence: float
    reason: str
    raw_response: str = field(default="", repr=False)

    @property
    def is_decisive(self) -> bool:
        return self.confidence >= 0.5

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 4),
            "reason": self.reason,
        }


class OllamaClient:
    """
    Async HTTP client for local Ollama inference.
    Handles retries, connection pooling, and verdict JSON parsing.
    """

    def __init__(self, endpoint: str, model: str, timeout: int = 60):
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.endpoint,
                timeout=httpx.Timeout(connect=5.0, read=self.timeout, write=10.0, pool=5.0),
                limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
            )
        return self._client

    async def health_check(self) -> bool:
        """Returns True if Ollama is reachable."""
        try:
            client = await self._get_client()
            resp = await client.get("/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    async def list_models(self) -> list[str]:
        """Return list of available model names."""
        try:
            client = await self._get_client()
            resp = await client.get("/api/tags", timeout=10)
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
        except Exception:
            return []

    async def model_loaded(self) -> bool:
        """Check if the configured model is available."""
        models = await self.list_models()
        return any(m.startswith(self.model.split(":")[0]) for m in models)

    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
        reraise=True,
    )
    async def _generate(self, prompt: str) -> str:
        """Raw generation call — retried on transient network errors."""
        client = await self._get_client()
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "top_p": 0.9,
                "num_predict": 200,
                "stop": ["\n\n", "```", "---"],
            },
        }
        resp = await client.post("/api/generate", json=payload)
        resp.raise_for_status()
        return resp.json().get("response", "").strip()

    def _parse_verdict(self, raw: str) -> TrustVerdict:
        """
        Parse Ollama response into a structured TrustVerdict.
        Tries multiple strategies: direct JSON, JSON extraction, keyword fallback.
        """
        # Strategy 1: direct JSON
        try:
            d = json.loads(raw)
            return self._build_verdict(d, raw)
        except (json.JSONDecodeError, ValueError):
            pass

        # Strategy 2: find JSON block in freetext
        patterns = [
            r'\{[^{}]*?"verdict"\s*:\s*"[^"]*"[^{}]*?\}',
            r'\{.*?"verdict".*?\}',
        ]
        for pattern in patterns:
            m = re.search(pattern, raw, re.DOTALL)
            if m:
                try:
                    d = json.loads(m.group())
                    return self._build_verdict(d, raw)
                except Exception:
                    continue

        # Strategy 3: keyword detection (last resort)
        upper = raw.upper()
        if "DENY" in upper:
            return TrustVerdict(Verdict.DENY, 0.65, "keyword-detected:DENY", raw)
        if "ALLOW" in upper:
            return TrustVerdict(Verdict.ALLOW, 0.65, "keyword-detected:ALLOW", raw)
        return TrustVerdict(Verdict.MONITOR, 0.5, "unparseable-response", raw)

    @staticmethod
    def _build_verdict(d: dict, raw: str) -> TrustVerdict:
        verdict_str = str(d.get("verdict", "MONITOR")).upper()
        confidence = float(d.get("confidence", 0.5))
        reason = str(d.get("reason", "no-reason"))[:100]
        try:
            verdict = Verdict(verdict_str)
        except ValueError:
            verdict = Verdict.MONITOR
        # Enforce low-confidence override
        if confidence < 0.5:
            verdict = Verdict.MONITOR
        return TrustVerdict(verdict, confidence, reason, raw)

    async def evaluate_session(self, session: dict) -> TrustVerdict:
        """Main entry — evaluate a network session and return a verdict."""
        prompt = build_evaluation_prompt(session)
        try:
            raw = await self._generate(prompt)
            verdict = self._parse_verdict(raw)
            log.info(
                "ollama_verdict",
                model=self.model,
                entity=session.get("entity_id"),
                verdict=verdict.verdict.value,
                confidence=verdict.confidence,
                reason=verdict.reason,
            )
            return verdict
        except Exception as exc:
            log.error("ollama_error", error=str(exc), entity=session.get("entity_id"))
            raise

    async def verify_role(self) -> bool:
        """Quick check that the model understands its security role."""
        try:
            raw = await self._generate(VERIFY_PROMPT)
            d = json.loads(raw)
            return d.get("status") == "ok"
        except Exception:
            return False

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
