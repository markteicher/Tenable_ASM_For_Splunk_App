#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
bin/tenable_asm_admin_users.py

Tenable Attack Surface Management – Admin Users
Endpoint: GET https://asm.cloud.tenable.com/api/1.0/admin/users

COMBAT / RESILIENT BEHAVIOR
- Strict stdout discipline: JSON events only
- Proxy support (scheme/host/port/auth)
- Retries with exponential backoff + jitter
- 429 handling with Retry-After
- Connect + read timeout discipline
- Full-fidelity record emission
- Telemetry + normalized error events
"""

import json
import os
import random
import sys
import time
from configparser import ConfigParser
from typing import Any, Dict, Optional, Tuple

import requests


APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
ASM_URL = "https://asm.cloud.tenable.com/api/1.0/admin/users"

# Retry policy
MAX_ATTEMPTS = 6
BASE_BACKOFF = 1.0
MAX_BACKOFF = 30.0

# Timeouts
CONNECT_TIMEOUT = 10
READ_TIMEOUT = 60


# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def emit(event: Dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=False))


def utc_epoch() -> int:
    return int(time.time())


def app_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# ------------------------------------------------------------
# Settings
# ------------------------------------------------------------

def load_settings() -> Tuple[str, Optional[Dict[str, str]]]:
    root = app_root()
    cp = ConfigParser()

    if not cp.read([
        f"{root}/local/asm_settings.conf",
        f"{root}/default/asm_settings.conf",
    ]):
        raise RuntimeError("asm_settings.conf not found")

    if "global" not in cp:
        raise RuntimeError("Missing [global] stanza in asm_settings.conf")

    g = cp["global"]

    api_key = (g.get("asm_api_key") or "").strip()
    if not api_key:
        raise RuntimeError("Missing asm_api_key")

    proxy_enabled = (g.get("proxy_enabled") or "false").lower() == "true"

    proxy = None
    if proxy_enabled:
        scheme = (g.get("proxy_scheme") or "").strip()
        host = (g.get("proxy_host") or "").strip()
        port = (g.get("proxy_port") or "").strip()
        user = (g.get("proxy_username") or "").strip()
        pwd = (g.get("proxy_password") or "").strip()

        if not (scheme and host and port):
            raise RuntimeError("Proxy enabled but scheme/host/port not fully defined")

        auth = f"{user}:{pwd}@" if user and pwd else ""
        proxy_url = f"{scheme}://{auth}{host}:{port}"
        proxy = {"http": proxy_url, "https": proxy_url}

    return api_key, proxy


# ------------------------------------------------------------
# Backoff
# ------------------------------------------------------------

def sleep_backoff(attempt: int, retry_after: Optional[float] = None) -> None:
    if retry_after is not None:
        delay = min(float(retry_after), MAX_BACKOFF)
        time.sleep(delay + random.uniform(0, 0.5))
        return

    delay = min(BASE_BACKOFF * (2 ** (attempt - 1)), MAX_BACKOFF)
    time.sleep(delay + random.uniform(0, 0.75))


def retry_after(resp: requests.Response) -> Optional[float]:
    ra = resp.headers.get("Retry-After")
    try:
        return float(ra) if ra else None
    except Exception:
        return None


# ------------------------------------------------------------
# Fetch
# ------------------------------------------------------------

def fetch_users(api_key: str, proxies: Optional[Dict[str, str]]) -> Dict[str, Any]:
    headers = {
        "accept": "application/json",
        "Authorization": api_key,  # raw token, as required
    }

    sess = requests.Session()
    if proxies:
        sess.proxies.update(proxies)

    start = time.time()
    last_status = None
    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            resp = sess.get(
                ASM_URL,
                headers=headers,
                timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
            )

            last_status = resp.status_code

            if resp.status_code == 429:
                sleep_backoff(attempt, retry_after(resp))
                continue

            if resp.status_code in (500, 502, 503, 504):
                sleep_backoff(attempt)
                continue

            if resp.status_code in (400, 401, 403, 404):
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:2000]}")

            resp.raise_for_status()

            payload = resp.json()
            users = payload.get("list")

            if not isinstance(users, list):
                raise RuntimeError("Invalid payload: missing list[]")

            return {
                "http_status": resp.status_code,
                "latency_ms": int((time.time() - start) * 1000),
                "attempts": attempt,
                "users": users,
                "total": payload.get("total", len(users)),
            }

        except Exception as e:
            last_error = e
            sleep_backoff(attempt)

    raise RuntimeError(
        f"Failed after {MAX_ATTEMPTS} attempts "
        f"(last_status={last_status}, error={last_error})"
    )


# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

def main() -> None:
    emit({
        "event_type": "asm_admin_users_run_start",
        "ts": utc_epoch(),
        "endpoint": ASM_URL,
    })

    try:
        api_key, proxies = load_settings()
        result = fetch_users(api_key, proxies)

        for user in result["users"]:
            emit({
                "event_type": "asm_admin_user",
                "ts": utc_epoch(),
                "record": user,
            })

        emit({
            "event_type": "asm_admin_users_run_summary",
            "ts": utc_epoch(),
            "endpoint": ASM_URL,
            "http_status": result["http_status"],
            "attempts": result["attempts"],
            "latency_ms": result["latency_ms"],
            "records_retrieved": len(result["users"]),
            "raw_total": result["total"],
            "proxy_used": bool(proxies),
        })

    except Exception as e:
        emit({
            "event_type": "asm_admin_users_error",
            "ts": utc_epoch(),
            "endpoint": ASM_URL,
            "error": str(e),
        })
        sys.exit(1)


if __name__ == "__main__":
    main()
