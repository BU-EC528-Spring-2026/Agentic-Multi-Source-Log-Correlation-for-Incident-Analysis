import os

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://localhost:11434").rstrip("/")
DEFAULT_MODEL = os.getenv("DEFAULT_MODEL", "llama3.1:8b")
DEFAULT_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))
DEFAULT_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "2"))
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
DEFAULT_CHUNK_SIZE = int(os.getenv("LOG_CHUNK_SIZE", "250"))
DEFAULT_MAX_LINES = int(os.getenv("LOG_MAX_LINES", "2000"))
