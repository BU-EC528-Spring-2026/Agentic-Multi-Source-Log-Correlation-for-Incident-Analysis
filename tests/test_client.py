import json

import pytest
from unittest.mock import patch, MagicMock

from src.core.client import InferenceClient, OpenRouterClient, create_client


class TestOpenRouterClient:
    def test_implements_interface(self):
        client = OpenRouterClient(
            model="openai/gpt-oss-120b:free",
            api_key="sk-test",
            temperature=0.3,
            timeout_seconds=120,
            max_retries=2,
        )
        assert isinstance(client, InferenceClient)

    def test_stores_config(self):
        client = OpenRouterClient(
            model="openai/gpt-oss-120b:free",
            api_key="sk-test",
            temperature=0.5,
            timeout_seconds=60,
            max_retries=3,
        )
        assert client.model == "openai/gpt-oss-120b:free"
        assert client.api_key == "sk-test"
        assert client.temperature == 0.5
        assert client.timeout_seconds == 60
        assert client.max_retries == 3

    def test_requires_api_key(self):
        with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
            OpenRouterClient(
                model="openai/gpt-oss-120b:free",
                api_key="",
                temperature=0.3,
                timeout_seconds=120,
                max_retries=2,
            )

    @patch("src.core.client.requests")
    def test_chat_structured_returns_parsed_json(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"chunk_id": 1, "summary": "test"}'}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_requests.post.return_value = mock_resp

        client = OpenRouterClient(
            model="openai/gpt-oss-120b:free",
            api_key="sk-test",
            temperature=0.3,
            timeout_seconds=120,
            max_retries=2,
        )
        result = client.chat_structured(
            schema={"type": "object"},
            system_prompt="system",
            user_prompt="user",
        )
        assert result == {"chunk_id": 1, "summary": "test"}

    @patch("src.core.client.requests")
    def test_sends_correct_payload(self, mock_requests):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"ok": true}'}}]
        }
        mock_resp.raise_for_status = MagicMock()
        mock_requests.post.return_value = mock_resp

        client = OpenRouterClient(
            model="openai/gpt-oss-120b:free",
            api_key="sk-test",
            temperature=0.5,
            timeout_seconds=60,
            max_retries=0,
        )
        client.chat_structured(
            schema={"type": "object"},
            system_prompt="sys",
            user_prompt="usr",
            seed=42,
        )

        call_args = mock_requests.post.call_args
        payload = json.loads(call_args.kwargs["data"])
        assert payload["model"] == "openai/gpt-oss-120b:free"
        assert payload["temperature"] == 0.5
        assert payload["seed"] == 42
        assert payload["response_format"]["type"] == "json_schema"
        assert payload["response_format"]["json_schema"]["schema"] == {"type": "object"}
        assert payload["messages"][0] == {"role": "system", "content": "sys"}
        assert payload["messages"][1] == {"role": "user", "content": "usr"}

        headers = call_args.kwargs["headers"]
        assert headers["Authorization"] == "Bearer sk-test"

    @patch("src.core.client.requests")
    def test_retries_on_http_error(self, mock_requests):
        error_resp = MagicMock()
        error_resp.status_code = 500
        error_resp.text = "Internal Server Error"

        ok_resp = MagicMock()
        ok_resp.json.return_value = {
            "choices": [{"message": {"content": '{"recovered": true}'}}]
        }
        ok_resp.raise_for_status = MagicMock()

        import requests as real_requests
        http_error = real_requests.HTTPError(response=error_resp)
        error_resp.raise_for_status = MagicMock(side_effect=http_error)

        mock_requests.post.side_effect = [error_resp, ok_resp]
        mock_requests.HTTPError = real_requests.HTTPError
        mock_requests.ConnectionError = real_requests.ConnectionError

        client = OpenRouterClient(
            model="openai/gpt-oss-120b:free",
            api_key="sk-test",
            temperature=0.3,
            timeout_seconds=120,
            max_retries=1,
        )
        result = client.chat_structured(
            schema={"type": "object"},
            system_prompt="test",
            user_prompt="test",
        )
        assert result == {"recovered": True}
        assert mock_requests.post.call_count == 2

    @patch("src.core.client.requests")
    def test_raises_after_exhausting_retries(self, mock_requests):
        error_resp = MagicMock()
        error_resp.status_code = 429
        error_resp.text = "Rate limited"

        import requests as real_requests
        http_error = real_requests.HTTPError(response=error_resp)
        error_resp.raise_for_status = MagicMock(side_effect=http_error)

        mock_requests.post.return_value = error_resp
        mock_requests.HTTPError = real_requests.HTTPError
        mock_requests.ConnectionError = real_requests.ConnectionError

        client = OpenRouterClient(
            model="openai/gpt-oss-120b:free",
            api_key="sk-test",
            temperature=0.3,
            timeout_seconds=120,
            max_retries=1,
        )
        with pytest.raises(RuntimeError, match="failed after 2 attempts"):
            client.chat_structured(
                schema={"type": "object"},
                system_prompt="test",
                user_prompt="test",
            )


class TestFactory:
    def test_returns_inference_client(self):
        client = create_client(
            model="openai/gpt-oss-120b:free",
            api_key="sk-test",
            temperature=0.3,
            timeout_seconds=120,
            max_retries=2,
        )
        assert isinstance(client, InferenceClient)

    def test_requires_api_key(self):
        with pytest.raises(ValueError, match="OPENROUTER_API_KEY"):
            create_client(
                model="openai/gpt-oss-120b:free",
                api_key="",
                temperature=0.3,
                timeout_seconds=120,
                max_retries=2,
            )


class TestConfig:
    def test_config_vars_exist(self):
        from src.core.config import (
            DEFAULT_CHUNK_SIZE,
            DEFAULT_MAX_LINES,
            DEFAULT_MAX_RETRIES,
            DEFAULT_TEMPERATURE,
            DEFAULT_TIMEOUT_SECONDS,
            OPENROUTER_API_KEY,
            OPENROUTER_MODEL,
        )
        assert isinstance(DEFAULT_TEMPERATURE, float)
        assert isinstance(DEFAULT_MAX_RETRIES, int)
        assert isinstance(DEFAULT_TIMEOUT_SECONDS, int)
        assert isinstance(DEFAULT_CHUNK_SIZE, int)
        assert isinstance(DEFAULT_MAX_LINES, int)
        assert isinstance(OPENROUTER_API_KEY, str)
        assert isinstance(OPENROUTER_MODEL, str)


class TestParser:
    def test_syslog_lines_get_structured_fields(self):
        from src.core.log_parser import parse_log_lines
        lines = ["Jun  5 10:30:00 myhost sshd[1234]: Accepted publickey for user"]
        parsed, skipped = parse_log_lines(lines)
        assert len(parsed) == 1
        assert parsed[0].host == "myhost"
        assert parsed[0].process == "sshd"
        assert parsed[0].pid == "1234"
        assert len(skipped) == 0

    def test_non_syslog_lines_included_as_raw(self):
        from src.core.log_parser import parse_log_lines
        lines = [
            "081109 203615 148 INFO dfs.DataNode$DataXceiver: Receiving block blk_123",
            "2024-01-15 10:23:45.123 ERROR Something went wrong",
        ]
        parsed, skipped = parse_log_lines(lines)
        assert len(parsed) == 2
        assert parsed[0].host == ""
        assert parsed[0].message == lines[0]
        assert parsed[1].host == ""
        assert parsed[1].message == lines[1]
        assert len(skipped) == 0

    def test_mixed_format_file(self):
        from src.core.log_parser import parse_log_lines
        lines = [
            "Jun  5 10:30:00 myhost sshd[1234]: Accepted publickey",
            "081109 203615 148 INFO dfs.DataNode: Receiving block",
            "",
            "Jun  5 10:30:01 myhost kernel: Power event",
        ]
        parsed, skipped = parse_log_lines(lines)
        assert len(parsed) == 3
        assert parsed[0].host == "myhost"
        assert parsed[1].host == ""
        assert parsed[2].host == "myhost"

    def test_empty_lines_excluded(self):
        from src.core.log_parser import parse_log_lines
        lines = ["", "   ", "\t"]
        parsed, skipped = parse_log_lines(lines)
        assert len(parsed) == 0


class TestCLI:
    def test_parser_has_expected_flags(self):
        from src.main import build_parser
        parser = build_parser()
        args = parser.parse_args([])
        assert args.log_file == "loghub/Mac/Mac_2k.log"
        assert args.output_file == "reports/report.json"
        assert hasattr(args, "model")
        assert hasattr(args, "chunk_size")
        assert hasattr(args, "max_lines")
        assert hasattr(args, "temperature")
        assert hasattr(args, "timeout_seconds")
        assert hasattr(args, "max_retries")
        assert hasattr(args, "seed")
        assert hasattr(args, "drop_low_signal")

    def test_no_provider_or_ollama_flags(self):
        from src.main import build_parser
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--provider", "ollama"])
        with pytest.raises(SystemExit):
            parser.parse_args(["--ollama-host", "http://localhost:11434"])

    def test_can_specify_log_file(self):
        from src.main import build_parser
        parser = build_parser()
        args = parser.parse_args(["--log-file", "loghub/HDFS/HDFS_2k.log"])
        assert args.log_file == "loghub/HDFS/HDFS_2k.log"
