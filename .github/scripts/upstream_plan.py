#!/usr/bin/env python3
"""Plan the daily upstream release check.

Compares the versions pinned in versions.env with the latest himalaya and ortie
releases, then classifies each difference:

  * patch/minor -> a pull request that bumps versions.env
  * major       -> an issue, because a major release needs a migration

This exists because ortie 3 dropped ORTIE_CONFIG and renamed every `--json` key.
A version-only bump still builds, then fails at runtime, so majors must never
arrive as an auto-mergeable branch.

Usage:
  upstream_plan.py            plan, write GitHub Actions outputs
  upstream_plan.py --apply    rewrite versions.env from BUMP_JSON (no API calls)
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSIONS = ROOT / "versions.env"
REPOS = {"himalaya": "pimalaya/himalaya", "ortie": "pimalaya/ortie"}
KEYS = {"himalaya": "HIMALAYA_VERSION", "ortie": "ORTIE_VERSION"}


def read_pins() -> dict[str, str]:
    pins = {}
    for line in VERSIONS.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        pins[key.strip()] = value.strip()
    return pins


def latest(repo: str) -> str:
    proc = subprocess.run(
        ["gh", "api", f"repos/{repo}/releases/latest", "--jq", ".tag_name"],
        capture_output=True,
        text=True,
        check=True,
    )
    return proc.stdout.strip().lstrip("v")


def major(version: str) -> str:
    return version.split(".", 1)[0]


def apply_bump(bump: list[dict]) -> None:
    if not bump:
        print("nothing to bump")
        return
    lines = VERSIONS.read_text(encoding="utf-8").splitlines()
    for entry in bump:
        key = KEYS[entry["dep"]]
        lines = [
            f"{key}={entry['latest']}" if line.startswith(f"{key}=") else line
            for line in lines
        ]
    VERSIONS.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"bumped {', '.join(e['dep'] for e in bump)}")


def plan() -> int:
    pins = read_pins()
    bump, majors = [], []
    for dep, repo in REPOS.items():
        pinned = pins.get(KEYS[dep], "")
        if not pinned:
            print(f"::error::{KEYS[dep]} missing from versions.env")
            return 1
        newest = latest(repo)
        print(f"{dep}: pinned {pinned}, latest {newest}")
        if newest == pinned:
            continue
        entry = {"dep": dep, "pinned": pinned, "latest": newest}
        if major(newest) != major(pinned):
            majors.append(entry)
        else:
            bump.append(entry)

    branch = ""
    if bump:
        branch = "chore/upstream-" + "-".join(f"{e['dep']}-{e['latest']}" for e in bump)

    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as out:
            out.write(f"bump={json.dumps(bump, separators=(',', ':'))}\n")
            out.write(f"major={json.dumps(majors, separators=(',', ':'))}\n")
            out.write(f"branch={branch}\n")
    return 0


def main() -> int:
    if "--apply" in sys.argv:
        apply_bump(json.loads(os.environ.get("BUMP_JSON") or "[]"))
        return 0
    return plan()


if __name__ == "__main__":
    raise SystemExit(main())
