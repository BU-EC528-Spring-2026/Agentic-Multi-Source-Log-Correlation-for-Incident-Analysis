import json
import time
from abc import ABC, abstractmethod
from typing import Optional

import requests
from requests import exceptions as request_exceptions


class InferenceClient(ABC):
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
        model: str,
        api_key: str,
        temperature: float,
        timeout_seconds: int,
        max_retries: int,
    ):
        self.model = str(model).strip()
        if not self.model:
            raise ValueError("model is required")

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
        payload = {
            "model": self.model,
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
            payload["seed"] = seed

        total_attempts = self.max_retries + 1
        last_error: Optional[RuntimeError] = None
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
            except request_exceptions.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else None
                detail = self.preview_text(
                    exc.response.text if exc.response is not None else str(exc)
                )
                error = RuntimeError(f"OpenRouter API error ({status or '?'}): {detail}")
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

        raise RuntimeError(f"LLM request failed after {total_attempts} attempts: {last_error}")

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

        try:
            parsed = json.loads(content)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"Model returned invalid JSON: {exc.msg}") from exc

        if not isinstance(parsed, dict):
            raise RuntimeError(
                f"Model returned {type(parsed).__name__}, expected a JSON object"
            )
        return parsed, body

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


def create_client(
    *,
    model: str,
    api_key: str,
    temperature: float,
    timeout_seconds: int,
    max_retries: int,
) -> InferenceClient:
    return OpenRouterClient(
        model=model,
        api_key=api_key,
        temperature=temperature,
        timeout_seconds=timeout_seconds,
        max_retries=max_retries,
    )
