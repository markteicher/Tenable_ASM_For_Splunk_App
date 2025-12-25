#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bin/tenable_asm_admin_users.py

Tenable Attack Surface Management – Admin Users
Endpoint: GET https://asm.cloud.tenable.com/api/1.0/admin/users

COMBAT / RESILIENT BEHAVIOR
- Strict stdout discipline: emits ONLY JSON events (one per line)
- Proxy support (enabled toggle + URL)
- Retries with exponential backoff + jitter
- 429 handling with Retry-After support
- Timeout discipline (connect + read)
- Emits operational telemetry events: counts + latency + status
- Emits normalized error event on failure
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
URL = "https://asm.cloud.tenable.com/api/1.0/admin/users"

# Retry policy (combat defaults)
MAX_ATTEMPTS = 6
BASE_BACKOFF_SECONDS = 1.0
MAX_BACKOFF_SECONDS = 30.0

# Requests timeout policy (connect, read)
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_READ_TIMEOUT = 60


def emit(event: Dict[str, Any]) -> None:
    """Emit a single event to stdout for Splunk ingestion."""
    print(json.dumps(event, ensure_ascii=False))


def _utc_epoch() -> int:
    return int(time.time())


def app_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_settings() -> Tuple[str, str, str, int, int, int]:
    """
    Loads settings from:
      - local/asm_settings.conf (preferred)
      - default/asm_settings.conf (fallback)

    Expected stanza: [tenable_asm]
      api_key
      proxy_enabled (0/1)
      proxy_url
      timeout_seconds (optional, used as read timeout)
      connect_timeout_seconds (optional)
      max_attempts (optional)
    """
    root = app_root()
    cp = ConfigParser()

    if not cp.read([f"{root}/local/asm_settings.conf", f"{root}/default/asm_settings.conf"]):
        raise RuntimeError("asm_settings.conf not found in local/ or default/")

    if "tenable_asm" not in cp:
        raise RuntimeError("Missing [tenable_asm] stanza in asm_settings.conf")

    s = cp["tenable_asm"]

    api_key = (s.get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("Missing api_key in [tenable_asm]")

    proxy_enabled = (s.get("proxy_enabled") or "0").strip()
    proxy_url = (s.get("proxy_url") or "").strip()

    # Read timeout (historical field)
    timeout_seconds = int((s.get("timeout_seconds") or str(DEFAULT_READ_TIMEOUT)).strip())

    # Optional connect timeout
    connect_timeout_seconds = int((s.get("connect_timeout_seconds") or str(DEFAULT_CONNECT_TIMEOUT)).strip())

    # Optional override attempts
    max_attempts = int((s.get("max_attempts") or str(MAX_ATTEMPTS)).strip())

    return api_key, proxy_enabled, proxy_url, timeout_seconds, connect_timeout_seconds, max_attempts


def _sleep_backoff(attempt: int, retry_after: Optional[float] = None) -> None:
    """
    attempt is 1-based attempt number (1..N)
    Implements exponential backoff with jitter, clamped.
    If Retry-After supplied, we honor it (plus small jitter).
    """
    if retry_after is not None:
        delay = max(0.0, float(retry_after))
        delay = min(delay, MAX_BACKOFF_SECONDS)
        delay = delay + random.uniform(0.0, 0.5)
        time.sleep(delay)
        return

    exp = min(MAX_BACKOFF_SECONDS, BASE_BACKOFF_SECONDS * (2 ** (attempt - 1)))
    delay = exp + random.uniform(0.0, 0.75)
    delay = min(delay, MAX_BACKOFF_SECONDS)
    time.sleep(delay)


def _extract_retry_after(resp: requests.Response) -> Optional[float]:
    ra = resp.headers.get("Retry-After")
    if not ra:
        return None
    try:
        return float(ra)
    except Exception:
        return None


def fetch_admin_users(
    api_key: str,
    proxy_enabled: str,
    proxy_url: str,
    read_timeout: int,
    connect_timeout: int,
    max_attempts: int,
) -> Dict[str, Any]:
    """
    Returns a dict with:
      {
        "http_status": int,
        "latency_ms": int,
        "attempts": int,
        "users": list,
        "raw_total": int,
      }
    Raises on terminal failure.
    """

    headers = {
        "accept": "application/json",
        # IMPORTANT: matches your working pattern (raw token string)
        "Authorization": api_key,
    }

    sess = requests.Session()

    if proxy_enabled == "1" and proxy_url:
        sess.proxies.update({"http": proxy_url, "https": proxy_url})

    timeout = (connect_timeout, read_timeout)

    start = time.time()
    last_exc: Optional[Exception] = None
    last_status: Optional[int] = None

    for attempt in range(1, max_attempts + 1):
        try:
            resp = sess.get(URL, headers=headers, timeout=timeout)

            last_status = resp.status_code

            # Rate limit
            if resp.status_code == 429:
                _sleep_backoff(attempt, _extract_retry_after(resp))
                continue

            # Retryable server errors
            if resp.status_code in (500, 502, 503, 504):
                _sleep_backoff(attempt)
                continue

            # Auth / perms / bad request should not loop forever
            if resp.status_code in (400, 401, 403, 404):
                body = ""
                try:
                    body = resp.text[:4000]
                except Exception:
                    body = ""
                raise RuntimeError(f"HTTP {resp.status_code} from ASM admin/users. Body: {body}")

            resp.raise_for_status()

            payload = resp.json()
            users = payload.get("list", [])
            total = payload.get("total", None)

            latency_ms = int((time.time() - start) * 1000)

            # Validate expected type
            if not isinstance(users, list):
                raise RuntimeError("ASM admin/users payload missing 'list' array")

            return {
                "http_status": resp.status_code,
                "latency_ms": latency_ms,
                "attempts": attempt,
                "users": users,
                "raw_total": total if total is not None else len(users),
            }

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_exc = e
            _sleep_backoff(attempt)
            continue
        except requests.exceptions.RequestException as e:
            # Some request errors can be transient; retry a few times
            last_exc = e
            _sleep_backoff(attempt)
            continue
        except Exception as e:
            # Terminal logic / parse / 4xx
            last_exc = e
            break

    latency_ms = int((time.time() - start) * 1000)
    status_note = f" last_http_status={last_status}" if last_status is not None else ""
    raise RuntimeError(f"Failed to fetch ASM admin users after {max_attempts} attempts.{status_note} error={last_exc} latency_ms={latency_ms}")


def main() -> None:
    run_ts = _utc_epoch()

    # Heartbeat / start event
    emit({
        "event_type": "asm_admin_users_run_start",
        "ts": run_ts,
        "endpoint": URL,
        "app": APP_NAME,
    })

    try:
        api_key, proxy_enabled, proxy_url, read_timeout, connect_timeout, max_attempts = load_settings()

        result = fetch_admin_users(
            api_key=api_key,
            proxy_enabled=proxy_enabled,
            proxy_url=proxy_url,
            read_timeout=read_timeout,
            connect_timeout=connect_timeout,
            max_attempts=max_attempts,
        )

        users = result["users"]
        processed = 0

        # Emit each user as an event (combat: full fidelity)
        for u in users:
            processed += 1
            emit({
                "event_type": "asm_admin_user",
                "ts": _utc_epoch(),
                "source_endpoint": URL,
                "record": u,  # keep all fields, no assumptions
            })

        # Summary telemetry event
        emit({
            "event_type": "asm_admin_users_run_summary",
            "ts": _utc_epoch(),
            "endpoint": URL,
            "http_status": result.get("http_status"),
            "attempts": result.get("attempts"),
            "latency_ms": result.get("latency_ms"),
            "records_retrieved": len(users),
            "records_processed": processed,
            "raw_total": result.get("raw_total"),
            "proxy_enabled": True if proxy_enabled == "1" else False,
        })

    except Exception as e:
        emit({
            "event_type": "asm_admin_users_error",
            "ts": _utc_epoch(),
            "endpoint": URL,
            "error": str(e),
        })
        sys.exit(1)


if __name__ == "__main__":
    main()
