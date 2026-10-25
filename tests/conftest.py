"""Test fixtures: configure the environment before importing server.py (it reads env at import)."""

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_TMP = Path(tempfile.mkdtemp(prefix="oauth-mail-mcp-tests-"))

os.environ.setdefault("MAIL_ACCOUNT", "gmail")
os.environ.setdefault("MAIL_ADDRESS", "test@example.com")
os.environ.setdefault("MAIL_MCP_TOKEN", "test-token")
os.environ.setdefault("MAIL_DATA_DIR", str(_TMP))
os.environ.setdefault("MAIL_ALLOW_SEND", "false")
os.environ.setdefault("MAIL_HEALTH_CACHE_SECS", "0")
