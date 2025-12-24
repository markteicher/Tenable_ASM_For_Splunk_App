#!/usr/bin/env python3
# bin/tenable_asm_suggestions.py
#
# Tenable Attack Surface Management – Suggestions
# Endpoint: POST /api/1.0/suggestions/list
#
# Emits one event per suggestion.

import json
import sys
import time
import requests
import splunk.entity as entity
from typing import Dict, Any, Optional


APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

API_URL = "https://asm.cloud.tenable.com/api/1.0/suggestions/list"


def emit(event: Dict[str, Any]) -> None:
    print(json.dumps(event, ensure_ascii=False))


def load_settings() -> Dict[str, Any]:
    return entity.getEntity(
        f"configs/conf-{CONF_FILE}",
        CONF_STANZA,
        namespace=APP_NAME,
        owner="nobody",
    )


def get_str(cfg: Dict[str, Any], key: str, default: str = "") -> str:
    val = cfg.get(key)
    return str(val).strip() if val is not None else default


def get_int(cfg: Dict[str, Any], key: str, default: int) -> int:
    try:
        return int(cfg.get(key, default))
    except Exception:
        return default


def get_bool(cfg: Dict[str, Any], key: str, default: bool = False) -> bool:
    v = str(cfg.get(key, str(default))).strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def main() -> None:
    try:
        cfg = load_settings()

        api_key = get_str(cfg, "api_key")
        if not api_key:
            raise RuntimeError("Missing api_key in asm_settings.conf")

        proxy = get_str(cfg, "proxy")
        timeout = get_int(cfg, "timeout_seconds", 60)

        # suggestion options (stored in asm_settings.conf; no hardcoding behavior)
        include_archived = get_bool(cfg, "suggestions_include_archived", False)

        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": api_key,
        }

        session = requests.Session()
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        # Note: Tenable examples show querystring usage for is_archived; we follow that.
        url = f"{API_URL}?is_archived={'true' if include_archived else 'false'}"

        resp = session.post(url, headers=headers, json={}, timeout=timeout)
        resp.raise_for_status()

        payload = resp.json()
        suggestions = payload.get("list", payload if isinstance(payload, list) else [])

        now = int(time.time())

        if isinstance(suggestions, list):
            for s in suggestions:
                # Emit raw suggestion object fields as-is, plus minimal envelope.
                emit({
                    "event_type": "asm_suggestion",
                    "retrieved_at": now,
                    **(s if isinstance(s, dict) else {"raw": s})
                })
        else:
            emit({
                "event_type": "asm_suggestion",
                "retrieved_at": now,
                "raw": suggestions
            })

    except Exception as exc:
        emit({
            "event_type": "asm_suggestion_error",
            "error": str(exc),
            "ts": int(time.time())
        })
        sys.exit(1)


if __name__ == "__main__":
    main()
