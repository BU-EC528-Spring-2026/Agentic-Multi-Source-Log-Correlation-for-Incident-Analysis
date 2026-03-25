import os
from dotenv import load_dotenv

load_dotenv(override=True)

BEDROCK_REGION = (
    os.getenv("BEDROCK_REGION", "")
    or os.getenv("AWS_REGION", "")
    or os.getenv("AWS_DEFAULT_REGION", "")
).strip()
BEDROCK_MODEL = (
    os.getenv("BEDROCK_MODEL_ID", "").strip()
    or os.getenv("BEDROCK_MODEL", "").strip()
    or os.getenv("AWS_BEDROCK_MODEL_ID", "").strip()
)


def _aws_credentials_available() -> bool:
    try:
        import boto3

        return boto3.Session().get_credentials() is not None
    except Exception:
        return False


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


def bedrock_configured(model: str | None = None) -> bool:
    model_id = str(model or BEDROCK_MODEL).strip()
    return bool(model_id and BEDROCK_REGION and _aws_credentials_available())


def default_provider() -> str:
    if bedrock_configured():
        return "bedrock"
    if GROQ_API_KEY:
        return "groq"
    if OPENROUTER_API_KEY:
        return "openrouter"
    return "bedrock"


OPENROUTER_MODEL_CANDIDATES = openrouter_model_candidates()
OPENROUTER_MODEL = OPENROUTER_MODEL_CANDIDATES[0]
DEFAULT_PROVIDER = default_provider()
DEFAULT_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0.3"))
DEFAULT_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "2"))
DEFAULT_TIMEOUT_SECONDS = int(os.getenv("LLM_TIMEOUT_SECONDS", "120"))
DEFAULT_CHUNK_SIZE = int(os.getenv("LOG_CHUNK_SIZE", "250"))
GROQ_CHUNK_SIZE = int(os.getenv("GROQ_CHUNK_SIZE", "40"))
DEFAULT_MAX_LINES = int(os.getenv("LOG_MAX_LINES", "2000"))
RETRIEVAL_TOP_K = int(os.getenv("RETRIEVAL_TOP_K", "8"))
RETRIEVAL_CONTEXT = os.getenv("RETRIEVAL_CONTEXT", "1").strip() != "0"
