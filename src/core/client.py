import json
import time
from typing import Optional

try:
    from ollama import Client
    from ollama import ResponseError
except ModuleNotFoundError:  
    Client = None  

    class ResponseError(Exception):
        status_code = 0
        error = "ollama package not installed"


class LLMClient:
    def __init__(
        self,
        *,
        model: str,
        host: str,
        temperature: float,
        timeout_seconds: int,
        max_retries: int,
    ):
        if Client is None:
            raise RuntimeError(
                "Missing dependency 'ollama'. Install with: pip install -r requirements.txt"
            )
        self.model = model
        self.temperature = temperature
        self.max_retries = max_retries
        self.client = Client(host=host, timeout=timeout_seconds)

    def chat_structured(
        self,
        *,
        schema: dict,
        system_prompt: str,
        user_prompt: str,
        seed: Optional[int] = None,
    ) -> dict:
        options = {"temperature": self.temperature}
        if seed is not None:
            options["seed"] = seed

        last_error: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                response = self.client.chat(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    stream=False,
                    format=schema,
                    options=options,
                )
                content = self.extract_message_content(response)
                return json.loads(content)
            except json.JSONDecodeError as exc:
                last_error = RuntimeError(f"Model returned invalid JSON: {exc}")
            except ResponseError as exc:
                last_error = RuntimeError(f"Ollama API error ({exc.status_code}): {exc.error}")
            except Exception as exc: 
                last_error = RuntimeError(
                    f"Could not complete LLM request. "
                    f"Check Ollama server/model. Details: {exc}"
                )

            if attempt < self.max_retries:
                time.sleep(0.4 * (attempt + 1))

        raise RuntimeError(f"LLM request failed after {self.max_retries + 1} attempts: {last_error}")

    def extract_message_content(self, response: object) -> str:
        if isinstance(response, dict):
            message = response.get("message", {})
            if isinstance(message, dict):
                return str(message.get("content", ""))
            return ""

        message = getattr(response, "message", None)
        if message is None:
            return ""
        content = getattr(message, "content", "")
        return str(content)
