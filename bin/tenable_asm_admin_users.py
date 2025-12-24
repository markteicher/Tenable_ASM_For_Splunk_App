#!/usr/bin/env python3
# bin/tenable_asm_admin_users.py
#
# Tenable ASM Admin Users -> Splunk scripted input
# Endpoint: GET https://asm.cloud.tenable.com/api/1.0/admin/users
# Output: JSONL to stdout (1 user per line), preserves all fields (including companies[])

import json
import os
import socket
import sys
import traceback
from configparser import ConfigParser
from datetime import datetime, timezone
from typing import Any, Dict, List

import requests

BASE_URL = "https://asm.cloud.tenable.com/api/1.0/admin/users"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def app_root() -> str:
    # .../etc/apps/<app>/bin/tenable_asm_admin_users.py -> .../etc/apps/<app>
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def read_settings() -> Dict[str, str]:
    """
    Reads settings written by setup.xml into local/asm_settings.conf.
    Falls back to default/asm_settings.conf if local isn't present.
    """
    root = app_root()
    candidates = [
        os.path.join(root, "local", "asm_settings.conf"),
        os.path.join(root, "default", "asm_settings.conf"),
    ]

    cp = ConfigParser()
    if not cp.read(candidates):
        raise RuntimeError("asm_settings.conf not found in local/ or default/")

    if not cp.has_section("tenable_asm"):
        raise RuntimeError("asm_settings.conf missing [tenable_asm] stanza")

    s = cp["tenable_asm"]

    api_key = (s.get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("Missing tenable_asm.api_key in asm_settings.conf")

    proxy_enabled = (s.get("proxy_enabled") or "0").strip()
    proxy_url = (s.get("proxy_url") or "").strip()

    timeout_s = (s.get("timeout_seconds") or "60").strip()
    try:
        timeout_seconds = str(int(timeout_s))
    except Exception:
        timeout_seconds = "60"

    verify_tls = (s.get("verify_tls") or "1").strip()

    return {
        "api_key": api_key,
        "proxy_enabled": proxy_enabled,
        "proxy_url": proxy_url,
        "timeout_seconds": timeout_seconds,
        "verify_tls": verify_tls,
    }


def emit(event: Dict[str, Any]) -> None:
    # JSONL: one event per line, no formatting
    sys.stdout.write(json.dumps(event, ensure_ascii=False, separators=(",", ":")) + "\n")


def extract_users(payload: Any) -> List[Dict[str, Any]]:
    """
    Authoritative per your working script:
      payload is a dict with key 'list' containing user records.
    """
    if not isinstance(payload, dict):
        raise RuntimeError("Unexpected /admin/users payload type (expected object)")

    users = payload.get("list")
    if not isinstance(users, list):
        raise RuntimeError("Unexpected /admin/users payload (missing 'list' array)")

    # Keep only dict records; do not reshape fields.
    return [u for u in users if isinstance(u, dict)]


def main() -> int:
    settings = read_settings()

    headers = {
        "accept": "application/json",
        # Match YOUR working code: Authorization is the raw API key (no 'Bearer ')
        "Authorization": settings["api_key"],
    }

    sess = requests.Session()
    if settings["proxy_enabled"] == "1" and settings["proxy_url"]:
        sess.proxies.update({"http": settings["proxy_url"], "https": settings["proxy_url"]})

    verify_tls = settings["verify_tls"] != "0"
    timeout = int(settings["timeout_seconds"])

    host = socket.gethostname()
    ingested_at = utc_now()

    resp = sess.get(BASE_URL, headers=headers, timeout=timeout, verify=verify_tls)
    if resp.status_code != 200:
        emit(
            {
                "event_type": "tenable_asm_admin_users_error",
                "endpoint": BASE_URL,
                "http_status": resp.status_code,
                "response": resp.text[:8000],
                "host": host,
                "ingested_at": ingested_at,
            }
        )
        return 1

    payload = resp.json()
    users = extract_users(payload)

    # Emit each user record as-is (preserve all user fields + companies[])
    for user in users:
        event = dict(user)
        event["_meta"] = {
            "event_type": "tenable_asm_admin_user",
            "endpoint": BASE_URL,
            "host": host,
            "ingested_at": ingested_at,
        }
        emit(event)

    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:
        emit(
            {
                "event_type": "tenable_asm_admin_users_exception",
                "endpoint": BASE_URL,
                "error": str(exc),
                "traceback": traceback.format_exc()[:15000],
                "host": socket.gethostname(),
                "ingested_at": utc_now(),
            }
        )
        sys.exit(2)
