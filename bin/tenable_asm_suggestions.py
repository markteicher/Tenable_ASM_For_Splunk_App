#!/usr/bin/env python3
# bin/tenable_asm_suggestions.py
#
# Tenable Attack Surface Management – Suggestions
# Endpoint: POST /api/1.0/suggestions/list
# Supports archived + non-archived suggestions

import json
import sys
import time
import requests
import splunk.entity as entity
from typing import Dict, Any, List

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


def fetch_suggestions(
    session: requests.Session,
    headers: Dict[str, str],
    is_archived: bool,
    timeout: int
) -> List[Dict[str, Any]]:

    payload = {
        "is_archived": is_archived
    }

    resp = session.post(API_URL, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    data = resp.json()

    return data.get("suggestions", [])


def main() -> None:
    try:
        cfg = load_settings()

        api_key = get_str(cfg, "api_key")
        if not api_key:
            raise RuntimeError("Missing api_key in asm_settings.conf")

        proxy = get_str(cfg, "proxy")
        timeout = get_int(cfg, "timeout_seconds", 60)

        headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "Authorization": api_key
        }

        session = requests.Session()
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        now = int(time.time())

        for archived_flag in (False, True):
            suggestions = fetch_suggestions(
                session=session,
                headers=headers,
                is_archived=archived_flag,
                timeout=timeout
            )

            for s in suggestions:
                emit({
                    "event_type": "asm_suggestion",
                    "suggestion_id": s.get("id"),
                    "suggestion_text": s.get("suggestion_text"),
                    "suggestion_type": s.get("suggestion_type"),
                    "rules": s.get("suggestion_details", {}).get("rules", []),
                    "created_at": s.get("created_at"),
                    "deleted_at": s.get("deleted_at"),
                    "is_archived": archived_flag,
                    "retrieved_at": now
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
