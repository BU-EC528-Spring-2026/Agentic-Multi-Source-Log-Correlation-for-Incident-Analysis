import json
import re
import time
from abc import ABC, abstractmethod
from typing import Optional, Sequence

import requests
from requests import exceptions as request_exceptions


class InferenceClient(ABC):
    model: str

    @abstractmethod
    def chat_structured(
        self,
        *,
        schema: dict,
        system_prompt: str,
        user_prompt: str,
        seed: Optional[int] = None,
        telemetry: Optional[dict] = None,
    ) -> dict: ...

    @abstractmethod
    def get_inference_telemetry(self) -> dict: ...


class OpenRouterClient(InferenceClient):
    BASE_URL = "https://openrouter.ai/api/v1/chat/completions"

    def __init__(
        self,
        *,
        models: Sequence[str],
        api_key: str,
        temperature: float,
        timeout_seconds: int,
        max_retries: int,
    ):
        seen: set[str] = set()
        self.model_candidates: list[str] = []
        for raw in models:
            mid = str(raw).strip()
            if mid and mid not in seen:
                seen.add(mid)
                self.model_candidates.append(mid)
        if not self.model_candidates:
            raise ValueError("at least one OpenRouter model is required")

        self.model = self.model_candidates[0]

        self.api_key = str(api_key).strip()
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY is required")

        self.temperature = temperature
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be greater than 0")
        self.timeout_seconds = timeout_seconds

        if max_retries < 0:
            raise ValueError("max_retries must be 0 or greater")
        self.max_retries = max_retries
        self.inference_calls: list[dict] = []

    @staticmethod
    def build_http_error_message(status: int | None, detail: str) -> str:
        message = f"OpenRouter API error ({status or '?'}): {detail}"
        if status == 404:
            message += (
                " Check https://openrouter.ai/settings/privacy on the same account "
                "as your API key, clear restrictive provider filters, and verify "
                "OPENROUTER_MODEL points to a live model id. Free models usually "
                "end with ':free'."
            )
        return message

    def chat_structured(
        self,
        *,
        schema: dict,
        system_prompt: str,
        user_prompt: str,
        seed: Optional[int] = None,
        telemetry: Optional[dict] = None,
    ) -> dict:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        base_payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": self.temperature,
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "response",
                    "schema": schema,
                },
            },
        }
        if seed is not None:
            base_payload["seed"] = seed

        total_attempts = self.max_retries + 1
        routing_errors: list[str] = []
        last_error: Optional[RuntimeError] = None

        for model_id in self.model_candidates:
            payload = {**base_payload, "model": model_id}
            self.model = model_id

            for attempt_number in range(1, total_attempts + 1):
                try:
                    started_at = time.perf_counter()
                    response = requests.post(
                        self.BASE_URL,
                        headers=headers,
                        json=payload,
                        timeout=self.timeout_seconds,
                    )
                    response.raise_for_status()
                    parsed, body = self.parse_model_response(response)
                    self.record_inference_call(
                        body=body,
                        latency_ms=(time.perf_counter() - started_at) * 1000,
                        attempt_count=attempt_number,
                        telemetry=telemetry,
                    )
                    return parsed
                except RuntimeError as exc:
                    routing_errors.append(f"{model_id}: {exc}")
                    last_error = exc
                    break
                except request_exceptions.HTTPError as exc:
                    status = exc.response.status_code if exc.response is not None else None
                    detail = self.preview_text(
                        exc.response.text if exc.response is not None else str(exc)
                    )
                    error = RuntimeError(self.build_http_error_message(status, detail))
                    if status == 404:
                        routing_errors.append(f"{model_id}: {detail[:240]}")
                        last_error = error
                        break
                    if status != 429 and (status is None or status < 500):
                        raise error from exc
                    last_error = error
                except request_exceptions.Timeout as exc:
                    last_error = RuntimeError(
                        f"OpenRouter request timed out after {self.timeout_seconds}s: {exc}"
                    )
                except request_exceptions.ConnectionError as exc:
                    last_error = RuntimeError(f"Could not reach OpenRouter: {exc}")
                except request_exceptions.RequestException as exc:
                    last_error = RuntimeError(f"OpenRouter request failed: {exc}")

                if attempt_number < total_attempts:
                    time.sleep(self.retry_delay_seconds(attempt_number))

        parts = ["OpenRouter: every configured model failed for this request."]
        if routing_errors:
            parts.append("404 / routing: " + " | ".join(routing_errors[:6]))
        if last_error:
            parts.append(str(last_error))
        raise RuntimeError(" ".join(parts)) from last_error

    def parse_model_response(self, response: requests.Response) -> tuple[dict, dict]:
        try:
            body = response.json()
        except ValueError as exc:
            detail = self.preview_text(getattr(response, "text", ""))
            raise RuntimeError(f"OpenRouter returned a non-JSON response body: {detail}") from exc

        if not isinstance(body, dict):
            raise RuntimeError(
                f"OpenRouter response body must be a JSON object, got {type(body).__name__}"
            )

        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise RuntimeError("OpenRouter response missing choices")

        first_choice = choices[0]
        if not isinstance(first_choice, dict):
            raise RuntimeError("OpenRouter response choices[0] must be an object")

        message = first_choice.get("message")
        if not isinstance(message, dict):
            raise RuntimeError("OpenRouter response missing choices[0].message")

        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            refusal = message.get("refusal")
            if isinstance(refusal, str) and refusal.strip():
                raise RuntimeError(
                    f"OpenRouter response did not include structured content: {refusal.strip()}"
                )
            raise RuntimeError("OpenRouter response missing choices[0].message.content")

        cleaned = self.strip_markdown_fences(content)
        try:
            parsed = json.loads(cleaned)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Model returned invalid JSON: {exc.msg}") from exc

        if not isinstance(parsed, dict):
            raise RuntimeError(
                f"Model returned {type(parsed).__name__}, expected a JSON object"
            )
        return parsed, body

    _FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?\s*```$", re.DOTALL)

    @classmethod
    def strip_markdown_fences(cls, text: str) -> str:
        stripped = text.strip()
        match = cls._FENCE_RE.match(stripped)
        if match:
            return match.group(1).strip()
        return stripped

    def record_inference_call(
        self,
        *,
        body: dict,
        latency_ms: float,
        attempt_count: int,
        telemetry: Optional[dict],
    ) -> None:
        entry = {
            "latency_ms": round(latency_ms, 1),
            "attempt_count": attempt_count,
        }
        if telemetry:
            entry.update({key: value for key, value in telemetry.items() if value is not None})

        for body_key, entry_key in (
            ("id", "request_id"),
            ("provider", "provider"),
            ("model", "model"),
        ):
            value = body.get(body_key)
            if value is not None and value != "":
                entry[entry_key] = value

        usage = body.get("usage")
        if isinstance(usage, dict):
            token_usage = {
                key: value
                for key, value in sorted(usage.items())
                if isinstance(value, (int, float))
            }
            if token_usage:
                entry["token_usage"] = token_usage

        self.inference_calls.append(entry)

    def get_inference_telemetry(self) -> dict:
        total_latency_ms = 0.0
        token_usage_totals: dict[str, int | float] = {}
        calls = []

        for item in self.inference_calls:
            calls.append(dict(item))
            total_latency_ms += float(item.get("latency_ms", 0.0))
            for key, value in item.get("token_usage", {}).items():
                token_usage_totals[key] = token_usage_totals.get(key, 0) + value

        telemetry = {
            "call_count": len(calls),
            "total_latency_ms": round(total_latency_ms, 1),
            "calls": calls,
        }
        if calls:
            telemetry["avg_latency_ms"] = round(total_latency_ms / len(calls), 1)
        if token_usage_totals:
            telemetry["token_usage"] = dict(sorted(token_usage_totals.items()))
        return telemetry

    def retry_delay_seconds(self, attempt_number: int) -> float:
        return 0.4 * attempt_number

    def preview_text(self, value: str) -> str:
        text = str(value).strip()
        if not text:
            return "<empty response body>"
        return text[:300]


class GroqClient(InferenceClient):
    _FENCE_RE = re.compile(r"^```(?:json)?\s*\n?(.*?)\n?\s*```$", re.DOTALL)

    def __init__(
        self,
        *,
        api_key: str,
        model: str,
        temperature: float,
        timeout_seconds: int,
        max_retries: int,
    ):
        try:
            from groq import Groq
        except ImportError as exc:
            raise ImportError("The groq package is required: pip install groq") from exc

        if not api_key.strip():
            raise ValueError("Groq API key is required (set groq_demo2_key in .env)")

        self.client = Groq(api_key=api_key, timeout=float(timeout_seconds))
        self.model = model
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.inference_calls: list[dict] = []

    def chat_structured(
        self,
        *,
        schema: dict,
        system_prompt: str,
        user_prompt: str,
        seed: Optional[int] = None,
        telemetry: Optional[dict] = None,
    ) -> dict:
        schema_instruction = (
            "\n\nRespond with ONLY valid JSON (no markdown fences, no commentary) "
            "matching this schema:\n"
            + json.dumps(schema)
        )
        messages = [
            {"role": "system", "content": system_prompt + schema_instruction},
            {"role": "user", "content": user_prompt},
        ]
        kwargs: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature,
            "max_completion_tokens": 4096,
        }
        if seed is not None:
            kwargs["seed"] = seed

        total_attempts = self.max_retries + 1
        last_error: Optional[Exception] = None

        for attempt in range(1, total_attempts + 1):
            try:
                started_at = time.perf_counter()
                completion = self.client.chat.completions.create(**kwargs)
                latency_ms = (time.perf_counter() - started_at) * 1000

                content = completion.choices[0].message.content
                if not content or not content.strip():
                    raise RuntimeError("Groq returned empty content")

                cleaned = self._strip_fences(content)
                parsed = json.loads(cleaned)
                if not isinstance(parsed, dict):
                    raise RuntimeError(
                        f"Groq returned {type(parsed).__name__}, expected a JSON object"
                    )

                self._record_call(
                    completion=completion,
                    latency_ms=latency_ms,
                    attempt=attempt,
                    telemetry=telemetry,
                )
                return parsed

            except json.JSONDecodeError as exc:
                last_error = RuntimeError(f"Groq returned invalid JSON: {exc.msg}")
            except RuntimeError as exc:
                last_error = exc
            except Exception as exc:
                last_error = RuntimeError(f"Groq API error: {exc}")

            if attempt < total_attempts:
                time.sleep(0.4 * attempt)

        raise RuntimeError(
            f"Groq: all {total_attempts} attempt(s) failed. Last error: {last_error}"
        ) from last_error

    @classmethod
    def _strip_fences(cls, text: str) -> str:
        stripped = text.strip()
        match = cls._FENCE_RE.match(stripped)
        return match.group(1).strip() if match else stripped

    def _record_call(
        self,
        *,
        completion: object,
        latency_ms: float,
        attempt: int,
        telemetry: Optional[dict],
    ) -> None:
        entry: dict = {
            "latency_ms": round(latency_ms, 1),
            "attempt_count": attempt,
            "model": self.model,
            "provider": "groq",
        }
        if telemetry:
            entry.update({k: v for k, v in telemetry.items() if v is not None})

        req_id = getattr(completion, "id", None)
        if req_id:
            entry["request_id"] = req_id

        usage = getattr(completion, "usage", None)
        if usage:
            token_usage = {}
            for attr in ("prompt_tokens", "completion_tokens", "total_tokens"):
                val = getattr(usage, attr, None)
                if isinstance(val, (int, float)):
                    token_usage[attr] = val
            if token_usage:
                entry["token_usage"] = token_usage

        self.inference_calls.append(entry)

    def get_inference_telemetry(self) -> dict:
        total_latency_ms = 0.0
        token_usage_totals: dict[str, int | float] = {}
        calls = []

        for item in self.inference_calls:
            calls.append(dict(item))
            total_latency_ms += float(item.get("latency_ms", 0.0))
            for key, value in item.get("token_usage", {}).items():
                token_usage_totals[key] = token_usage_totals.get(key, 0) + value

        telemetry: dict = {
            "call_count": len(calls),
            "total_latency_ms": round(total_latency_ms, 1),
            "calls": calls,
        }
        if calls:
            telemetry["avg_latency_ms"] = round(total_latency_ms / len(calls), 1)
        if token_usage_totals:
            telemetry["token_usage"] = dict(sorted(token_usage_totals.items()))
        return telemetry


def create_client(
    *,
    provider: str = "groq",
    models: Sequence[str] = (),
    api_key: str,
    temperature: float,
    timeout_seconds: int,
    max_retries: int,
) -> InferenceClient:
    if provider == "groq":
        model = models[0] if models else "openai/gpt-oss-120b"
        return GroqClient(
            api_key=api_key,
            model=model,
            temperature=temperature,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
    return OpenRouterClient(
        models=models,
        api_key=api_key,
        temperature=temperature,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )
