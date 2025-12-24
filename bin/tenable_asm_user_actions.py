#!/usr/bin/env python3
# bin/tenable_asm_user_actions.py
#
# Tenable Attack Surface Management – User Action Logs
# Endpoint: GET /api/1.0/logs
#
# Emits one JSON event per action

import json
import sys
import time
import requests
import splunk.entity as entity
from typing import Dict, Any, List


APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

BASE_URL = "https://asm.cloud.tenable.com/api/1.0/logs"
PAGE_SIZE = 100


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
            "Authorization": api_key
        }

        session = requests.Session()
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        offset = 0

        while True:
            params = {
                "limit": PAGE_SIZE,
                "offset": offset
            }

            resp = session.get(
                BASE_URL,
                headers=headers,
                params=params,
                timeout=timeout
            )
            resp.raise_for_status()

            payload = resp.json()
            events: List[Dict[str, Any]] = payload.get("list", [])

            if not events:
                break

            for ev in events:
                emit({
                    "event_type": "asm_user_action",
                    "id": ev.get("id"),
                    "action": ev.get("action"),
                    "target": ev.get("target"),
                    "actor": ev.get("actor"),
                    "actor_id": ev.get("actor_id"),
                    "inventory_id": ev.get("inventory_id"),
                    "description_values": ev.get("description_values"),
                    "created_at": ev.get("created_at")
                })

            if len(events) < PAGE_SIZE:
                break

            offset += PAGE_SIZE

    except Exception as exc:
        emit({
            "event_type": "asm_user_actions_error",
            "error": str(exc),
            "ts": int(time.time())
        })
        sys.exit(1)


if __name__ == "__main__":
    main()
