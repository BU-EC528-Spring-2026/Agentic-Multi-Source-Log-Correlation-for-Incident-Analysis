import json
import time
from abc import ABC, abstractmethod
from typing import Optional

import requests


class InferenceClient(ABC):
    @abstractmethod
    def chat_structured(
        self,
        *,
        schema: dict,
        system_prompt: str,
        user_prompt: str,
        seed: Optional[int] = None,
    ) -> dict: ...


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
        if not api_key:
            raise ValueError("OPENROUTER_API_KEY is required")
        self.model = model
        self.api_key = api_key
        self.temperature = temperature
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries

    def chat_structured(
        self,
        *,
        schema: dict,
        system_prompt: str,
        user_prompt: str,
        seed: Optional[int] = None,
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

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                resp = requests.post(
                    self.BASE_URL,
                    headers=headers,
                    data=json.dumps(payload),
                    timeout=self.timeout_seconds,
                )
                resp.raise_for_status()
                body = resp.json()
                content = body["choices"][0]["message"]["content"]
                return json.loads(content)
            except requests.HTTPError as exc:
                status = exc.response.status_code if exc.response is not None else "?"
                detail = exc.response.text[:300] if exc.response is not None else str(exc)
                last_error = RuntimeError(f"OpenRouter API error ({status}): {detail}")
            except json.JSONDecodeError as exc:
                last_error = RuntimeError(f"Model returned invalid JSON: {exc}")
            except requests.ConnectionError as exc:
                last_error = RuntimeError(f"Could not reach OpenRouter: {exc}")
            except Exception as exc:
                last_error = RuntimeError(f"OpenRouter request failed: {exc}")

            if attempt < self.max_retries:
                time.sleep(0.4 * (attempt + 1))

        raise RuntimeError(f"LLM request failed after {self.max_retries + 1} attempts: {last_error}")


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
