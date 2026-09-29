"""All configuration in one place. Values come from environment variables
(or a local .env file). Nothing secret is ever hard-coded here."""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # python-dotenv is optional
    pass

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "ctdip.sqlite3"
LEDGER_PATH = DATA_DIR / "audit_ledger.jsonl"
FIXTURES_DIR = BASE_DIR / "fixtures"
IOC_HASH_FILE = BASE_DIR / "config" / "ioc_hashes.txt"

APP_VERSION = "0.1.0"
DETECTION_VERSION = "rules-2026.09.1"   # bump whenever rules or scoring change

# Who is clicking the buttons. The MVP has no login; this name goes in the audit ledger.
ANALYST_NAME = os.getenv("ANALYST_NAME", "demo-analyst")

# --- Microsoft tenant -------------------------------------------------------
TENANT_ID = os.getenv("AZURE_TENANT_ID", "")
# Read-only app registration used by collectors
COLLECTOR_CLIENT_ID = os.getenv("COLLECTOR_CLIENT_ID", "")
COLLECTOR_CLIENT_SECRET = os.getenv("COLLECTOR_CLIENT_SECRET", "")
# Separate, narrowly-scoped app registration used only by response actions
RESPONDER_CLIENT_ID = os.getenv("RESPONDER_CLIENT_ID", "")
RESPONDER_CLIENT_SECRET = os.getenv("RESPONDER_CLIENT_SECRET", "")
TENANT_DOMAINS = [d.strip().lower() for d in os.getenv("TENANT_DOMAINS", "").split(",") if d.strip()]

# --- Azure VM isolation -----------------------------------------------------
AZURE_SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID", "")
# Full resource ID of the pre-created isolation NSG (see docs/vm_isolation.md)
ISOLATION_NSG_ID = os.getenv("ISOLATION_NSG_ID", "")

# Actions listed here run against the real tenant. Everything else is SIMULATED.
# Example: LIVE_ACTIONS=REVOKE_OAUTH_GRANT,REVOKE_USER_SESSIONS,DISABLE_APPLICATION
LIVE_ACTIONS = {a.strip() for a in os.getenv("LIVE_ACTIONS", "").split(",") if a.strip()}

# --- Detection policy (static policy, NOT behavioural baselining) -----------
ALLOWED_COUNTRIES = {c.strip().upper() for c in os.getenv("ALLOWED_COUNTRIES", "US").split(",") if c.strip()}
HIGH_VOLUME_ITEM_THRESHOLD = int(os.getenv("HIGH_VOLUME_ITEM_THRESHOLD", "50"))

# --- LLM --------------------------------------------------------------------
# local     = self-hosted model on your own server (default). Incident data never leaves your network.
# anthropic = hosted API (optional).  none = deterministic summaries only.
LLM_PROVIDER = os.getenv("LLM_PROVIDER", "local").strip().lower()
LLM_MAX_TOKENS = int(os.getenv("LLM_MAX_TOKENS", "1500"))       # max tokens the model may generate
LLM_TEMPERATURE = float(os.getenv("LLM_TEMPERATURE", "0"))       # 0 = most repeatable output

# Local model server. "ollama" uses Ollama's native /api/chat (lets us set the context window).
# "openai" uses any OpenAI-compatible /v1/chat/completions server: llama.cpp server, vLLM, LM Studio.
LOCAL_LLM_API = os.getenv("LOCAL_LLM_API", "ollama").strip().lower()
LOCAL_LLM_BASE_URL = os.getenv("LOCAL_LLM_BASE_URL", "http://localhost:11434").rstrip("/")
LOCAL_LLM_MODEL = os.getenv("LOCAL_LLM_MODEL", "qwen2.5:7b")
LOCAL_LLM_API_KEY = os.getenv("LOCAL_LLM_API_KEY", "")           # only if your server requires one
LOCAL_LLM_CONTEXT = int(os.getenv("LOCAL_LLM_CONTEXT", "16384"))  # context window in tokens
LOCAL_LLM_TIMEOUT = int(os.getenv("LOCAL_LLM_TIMEOUT", "300"))    # seconds; CPU inference is slow

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")
ANTHROPIC_MODEL = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5")


def collector_configured() -> bool:
    return bool(TENANT_ID and COLLECTOR_CLIENT_ID and COLLECTOR_CLIENT_SECRET)


def responder_configured() -> bool:
    return bool(TENANT_ID and RESPONDER_CLIENT_ID and RESPONDER_CLIENT_SECRET)


def llm_configured() -> bool:
    if LLM_PROVIDER == "local":
        return bool(LOCAL_LLM_BASE_URL and LOCAL_LLM_MODEL)
    if LLM_PROVIDER == "anthropic":
        return bool(ANTHROPIC_API_KEY)
    return False


def llm_model_label() -> str:
    if LLM_PROVIDER == "local":
        return f"local:{LOCAL_LLM_MODEL}"
    if LLM_PROVIDER == "anthropic":
        return f"anthropic:{ANTHROPIC_MODEL}"
    return "none"
