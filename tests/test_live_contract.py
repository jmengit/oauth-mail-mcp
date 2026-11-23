"""Contract tests against a real ortie binary.

The unit tests fake `_run`, so they cannot catch a change in ortie's config discovery
or JSON shape. CI points ORTIE_CONTRACT_BIN at each pinned release and runs this file;
locally it skips when the variable is unset.

  ORTIE_CONTRACT_BIN=/path/to/ortie ORTIE_CONTRACT_VERSION=3.0.0 \
      python -m pytest tests/test_live_contract.py -q
"""

import json
import os
import subprocess

import pytest

import server

BIN = os.environ.get("ORTIE_CONTRACT_BIN", "")
EXPECTED = os.environ.get("ORTIE_CONTRACT_VERSION", "")

pytestmark = pytest.mark.skipif(not BIN, reason="ORTIE_CONTRACT_BIN not set")


def ortie(args, env=None):
    return subprocess.run(
        [BIN, *args], capture_output=True, text=True, env=env, timeout=60
    )


@pytest.fixture()
def rendered(tmp_path, monkeypatch):
    monkeypatch.setattr(server, "ACCOUNT", "gmail")
    monkeypatch.setattr(server, "ADDRESS", "smoke@example.com")
    monkeypatch.setattr(server, "CONFIG", tmp_path)
    monkeypatch.setattr(server, "TOKENS", tmp_path / "tokens")
    monkeypatch.setattr(server, "ATTACHMENTS", tmp_path / "attachments")
    server.render_configs()
    return tmp_path / "ortie.toml"


def test_binary_reports_the_expected_version():
    proc = ortie(["--version"])
    assert proc.returncode == 0
    assert EXPECTED in proc.stdout, proc.stdout


def test_generated_config_is_accepted(rendered):
    """A valid config must fail on the missing token, never on the configuration."""
    proc = ortie(["-c", str(rendered), "token", "inspect", "-a", "gmail", "--json"])
    assert proc.returncode != 0
    payload = json.loads(proc.stdout)
    assert "error" in payload
    assert "No configuration found" not in json.dumps(payload)


def test_v3_only_ignores_ortie_config_env(rendered, tmp_path):
    """Documents the v3 break this repo is built around: -c is mandatory."""
    if not EXPECTED.startswith("3"):
        pytest.skip("ortie 2 still reads ORTIE_CONFIG")
    env = dict(os.environ, HOME=str(tmp_path / "home"), ORTIE_CONFIG=str(rendered))
    proc = ortie(["account", "show", "-a", "gmail", "--json"], env=env)
    assert proc.returncode != 0
    assert "No configuration found" in proc.stdout


def test_v3_only_account_show_reads_the_generated_config(rendered):
    if not EXPECTED.startswith("3"):
        pytest.skip("ortie 2 has no account command")
    proc = ortie(["-c", str(rendered), "account", "show", "-a", "gmail", "--json"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["account"]["name"] == "gmail"


def test_v3_only_error_objects_carry_a_code(rendered):
    if not EXPECTED.startswith("3"):
        pytest.skip("ortie 2 prints no stable code")
    proc = ortie(["-c", str(rendered), "token", "bogus", "--json"])
    assert proc.returncode == 2
    payload = json.loads(proc.stdout)
    assert payload["code"] == "usage-invalid"
