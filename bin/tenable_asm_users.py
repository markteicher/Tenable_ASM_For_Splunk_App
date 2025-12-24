#!/usr/bin/env python3
# bin/tenable_asm_users.py
#
# Tenable Attack Surface Management – Users
# Endpoint: GET /api/1.0/admin/users
#
# Emits one JSON event per user (Splunk scripted input compatible)

import json
import sys
import time
import requests
import splunk.entity as entity
from typing import Dict, Any, List


APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

BASE_URL = "https://asm.cloud.tenable.com/api/1.0/admin/users"


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

        resp = session.get(BASE_URL, headers=headers, timeout=timeout)
        resp.raise_for_status()

        payload = resp.json()
        users: List[Dict[str, Any]] = payload.get("list", [])

        for user in users:
            event = {
                "event_type": "asm_user",
                "id": user.get("id"),
                "email": user.get("email"),
                "authid": user.get("authid"),
                "access_level": user.get("access_level"),
                "created_at": user.get("created_at"),
                "first_login": user.get("first_login"),
                "user_inventories_limit": user.get("user_inventories_limit"),
                "business_id": user.get("business_id"),
                "mfa": user.get("mfa"),
                "ext_user_id": user.get("ext_user_id"),
                "workspace": user.get("workspace"),
                "companies": [
                    c.get("name")
                    for c in user.get("companies", [])
                    if c.get("name")
                ],
            }

            emit(event)

    except Exception as exc:
        emit({
            "event_type": "asm_users_error",
            "error": str(exc),
            "ts": int(time.time())
        })
        sys.exit(1)


if __name__ == "__main__":
    main()
