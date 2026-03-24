import os
from dotenv import load_dotenv

load_dotenv()

GROQ_API_KEY = os.getenv("groq_demo2_key", os.getenv("GROQ_API_KEY", ""))
GROQ_MODEL = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")

_DEFAULT_OPENROUTER_FALLBACKS = (
    "google/gemma-3-27b-it:free,"
    "meta-llama/llama-3.3-70b-instruct:free,"
    "mistralai/mistral-small-3.1-24b-instruct:free,"
    "qwen/qwen3-coder:free,"
    "nvidia/nemotron-3-nano-30b-a3b:free,"
    "deepseek/r1-120b:free"
)


def openrouter_model_candidates() -> list[str]:
    primary = os.getenv("OPENROUTER_MODEL", "openai/gpt-oss-120b:free").strip()
    raw_fallbacks = os.getenv("OPENROUTER_MODEL_FALLBACKS", _DEFAULT_OPENROUTER_FALLBACKS).strip()
    out: list[str] = []
    if primary:
        out.append(primary)
    for part in raw_fallbacks.split(","):
        slug = part.strip()
        if slug and slug not in out:
            out.append(slug)
    return out if out else ["openai/gpt-oss-120b:free"]


def default_provider() -> str:
    if GROQ_API_KEY:
        return "groq"
    if OPENROUTER_API_KEY:
        return "openrouter"
    return "groq"


OPENROUTER_MODEL_CANDIDATES = openrouter_model_candidates()
OPENROUTER_MODEL = OPENROUTER_MODEL_CANDIDATES[0]
DEFAULT_PROVIDER = default_provider()
DEFAULT_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))
DEFAULT_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "2"))
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
DEFAULT_CHUNK_SIZE = int(os.getenv("LOG_CHUNK_SIZE", "250"))
GROQ_CHUNK_SIZE = int(os.getenv("GROQ_CHUNK_SIZE", "40"))
DEFAULT_MAX_LINES = int(os.getenv("LOG_MAX_LINES", "2000"))
