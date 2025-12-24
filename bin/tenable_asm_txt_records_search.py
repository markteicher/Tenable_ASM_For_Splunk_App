#!/usr/bin/env python3
# bin/tenable_asm_txt_records_search.py
#
# Tenable Attack Surface Management – TXT Record Search
# Endpoint: POST /api/1.0/txt-records/search

import json
import sys
import time
import requests
import splunk.entity as entity
from typing import Dict, Any, List

APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

API_URL = "https://asm.cloud.tenable.com/api/1.0/txt-records/search"


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
            "content-type": "application/json",
            "Authorization": api_key
        }

        session = requests.Session()
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        # Empty POST body = return all searchable TXT records
        resp = session.post(API_URL, headers=headers, json={}, timeout=timeout)
        resp.raise_for_status()

        payload = resp.json()
        records: List[Dict[str, Any]] = payload.get("txt_records", [])

        now = int(time.time())

        for rec in records:
            emit({
                "event_type": "asm_txt_record_search",
                "retrieved_at": now,
                **rec
            })

    except Exception as exc:
        emit({
            "event_type": "asm_txt_record_search_error",
            "error": str(exc),
            "ts": int(time.time())
        })
        sys.exit(1)


if __name__ == "__main__":
    main()
