"""
Scambait Research Suite - Configuration

All settings for the research panel. Designed for local-only operation.
"""

from pathlib import Path
from typing import List
import os

# Load values from a local .env file if python-dotenv is installed.
# This is optional: every setting below has a safe default, so the tool runs
# fine even without python-dotenv or a .env file present.
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).parent / ".env")
except ImportError:
    pass

# =============================================================================
# BASE PATHS
# =============================================================================

BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / "data"
UPLOAD_DIR = DATA_DIR / "uploads"
EXPORT_DIR = DATA_DIR / "exports"
GEOIP_DIR = DATA_DIR / "geoip"

# Ensure directories exist
for dir_path in [DATA_DIR, UPLOAD_DIR, EXPORT_DIR, GEOIP_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)

# =============================================================================
# DATABASE
# =============================================================================

DATABASE_PATH = DATA_DIR / "scambait.db"
DATABASE_URL = f"sqlite+aiosqlite:///{DATABASE_PATH}"

# =============================================================================
# SERVER SETTINGS (LOCAL ONLY)
# =============================================================================

# SECURITY: Only bind to localhost - never expose to network.
# HOST is intentionally NOT read from the environment: this tool is meant to
# run inside an isolated VM and must never listen on a public interface.
# Change this line deliberately, and only if you understand the risk.
HOST: str = "127.0.0.1"
PORT: int = int(os.environ.get("SCAMBAIT_PORT", "8000"))

# Allowed hosts for CORS and request validation
ALLOWED_HOSTS: List[str] = ["127.0.0.1", "localhost"]

# SECURITY: Block all outbound connections
OUTBOUND_BLOCKED: bool = True

# =============================================================================
# SAFETY CONTROLS
# =============================================================================

# Enable comprehensive audit logging
AUDIT_LOGGING_ENABLED: bool = True

# Maximum file upload size (10MB default)
MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024

# Allowed file extensions for upload (for safety analysis)
ALLOWED_UPLOAD_EXTENSIONS: List[str] = [
    ".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".png", ".jpg", ".jpeg", ".gif", ".bmp",
    ".zip", ".rar", ".7z",
    ".html", ".htm", ".eml", ".msg",
    ".exe", ".dll", ".bat", ".ps1", ".vbs",  # Allowed for analysis only
]

# =============================================================================
# SCRIPTS ENGINE
# =============================================================================

# Default delay range (seconds) for time-wasting
MIN_DELAY_SECONDS: int = 30
MAX_DELAY_SECONDS: int = 300  # 5 minutes

# Typing simulation speed (characters per second)
TYPING_SPEED_CPS: float = 3.0

# =============================================================================
# WALLET HONEYPOT
# =============================================================================

# Fake wallet configuration (NO REAL FUNDS).
#
# The default address is the public Solana "incinerator" burn address, chosen
# precisely because it is well known, controlled by nobody, and cannot receive
# spendable funds - so this honeypot can never accidentally point at a real
# wallet. Override HONEYPOT_ADDRESS in the environment if you want a different
# display address; NEVER put an address you actually control here.
HONEYPOT_WALLET = {
    "address": os.environ.get(
        "HONEYPOT_ADDRESS",
        "1nc1nerator11111111111111111111111111111111",
    ),
    "balance_sol": float(os.environ.get("HONEYPOT_BALANCE_SOL", "47832.91")),
    "balance_usd": float(os.environ.get("HONEYPOT_BALANCE_USD", "4783291.00")),
    "network": "mainnet-beta",
    "disclaimer": "RESEARCH HONEYPOT - NO REAL FUNDS - FOR ANALYSIS ONLY"
}

# =============================================================================
# PATTERN DETECTION
# =============================================================================

# Common scam pattern keywords for auto-flagging
SCAM_PATTERNS = {
    "urgency": [
        "act now", "limited time", "expires today", "urgent",
        "immediately", "don't wait", "last chance", "hurry"
    ],
    "authority": [
        "official", "government", "irs", "fbi", "police",
        "microsoft", "apple", "amazon", "bank", "legal"
    ],
    "fear": [
        "arrest", "warrant", "lawsuit", "suspended", "locked",
        "hacked", "compromised", "virus", "illegal activity"
    ],
    "greed": [
        "winner", "lottery", "inheritance", "million", "bitcoin",
        "investment", "guaranteed", "profit", "returns", "crypto"
    ],
    "social_proof": [
        "everyone", "thousands", "testimonials", "reviews",
        "verified", "trusted", "recommended"
    ],
    "reciprocity": [
        "free", "gift", "bonus", "reward", "no cost",
        "complimentary", "trial"
    ]
}

# =============================================================================
# LOGGING
# =============================================================================

LOG_LEVEL: str = "INFO"
LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"

# =============================================================================
# RESEARCH METADATA
# =============================================================================

# Appended to all sessions for documentation
RESEARCH_METADATA = {
    "tool_name": "Scambait Research Suite",
    "version": "1.0.0",
    "purpose": "Security research and fraud analysis",
    "environment": "Isolated VM - No public network exposure"
}
