import json
import os
import threading
from typing import Any, Dict, List

import requests
from dotenv import load_dotenv
from openai import OpenAI


class LocalLLMError(RuntimeError):
    pass


class LocalLLMClient:
    def __init__(
        self,
        base_url: str | None = None,
        model: str | None = None,
        api_key: str | None = None,
        timeout: float = 180.0,
    ) -> None:
        load_dotenv()
        self.base_url = base_url or os.getenv("LOCAL_LLM_BASE_URL", "http://localhost:8000/v1")
        self.model = model or os.getenv("LOCAL_LLM_MODEL", "qwen3.6-27b-awq")
        self.api_key = api_key or os.getenv("LOCAL_LLM_API_KEY", "local")
        self.timeout = timeout
        self._thread_local = threading.local()
        self._headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

    def _client(self) -> OpenAI:
        client = getattr(self._thread_local, "client", None)
        if client is None:
            client = OpenAI(
                base_url=self.base_url,
                api_key=self.api_key,
                timeout=self.timeout,
            )
            self._thread_local.client = client
        return client

    def ensure_available(self) -> None:
        try:
            models = self._client().models.list()
        except Exception as exc:
            raise LocalLLMError(
                f"Local LLM server is not reachable at {self.base_url}. "
                "Start the vLLM server or update LOCAL_LLM_BASE_URL."
            ) from exc

        model_ids = {model.id for model in models.data}
        if self.model not in model_ids:
            raise LocalLLMError(
                f"Model {self.model} was not found on the local LLM server. "
                "Update LOCAL_LLM_MODEL or restart vLLM with the correct served model name."
            )

    def chat_json(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 400,
        temperature: float = 0.0,
        retries: int = 1,
    ) -> Dict[str, Any]:
        last_error: Exception | None = None

        for attempt in range(retries + 1):
            retry_messages = messages
            if attempt > 0:
                retry_messages = [
                    {
                        "role": "system",
                        "content": "Return only valid JSON. Do not include markdown or commentary.",
                    },
                    *messages,
                ]

            try:
                data = self._post_chat_completion(
                    messages=retry_messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    response_format={"type": "json_object"},
                )
                content = self._content_from_response(data)
                return self._parse_json(content)
            except Exception as exc:
                last_error = exc

        raise LocalLLMError(f"Local LLM returned invalid JSON after {retries + 1} attempts.") from last_error

    def chat_text(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int = 900,
        temperature: float = 0.0,
    ) -> str:
        data = self._post_chat_completion(
            messages=messages,
            max_tokens=max_tokens,
            temperature=temperature,
        )
        return self._content_from_response(data)

    def _post_chat_completion(
        self,
        messages: List[Dict[str, str]],
        max_tokens: int,
        temperature: float,
        response_format: Dict[str, str] | None = None,
    ) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if response_format is not None:
            payload["response_format"] = response_format

        response = requests.post(
            f"{self.base_url.rstrip('/')}/chat/completions",
            headers=self._headers,
            json=payload,
            timeout=self.timeout,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object response from the local LLM server.")
        return data

    @staticmethod
    def _content_from_response(data: Dict[str, Any]) -> str:
        choices = data.get("choices")
        if not isinstance(choices, list) or not choices:
            raise ValueError(f"Local LLM response did not include choices: {data}")

        message = choices[0].get("message", {})
        content = message.get("content")
        if not isinstance(content, str):
            raise ValueError(f"Local LLM response did not include message content: {data}")
        return content

    @staticmethod
    def _parse_json(content: str) -> Dict[str, Any]:
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start == -1 or end == -1 or end <= start:
                raise
            parsed = json.loads(content[start : end + 1])

        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object from the local LLM.")
        return parsed
