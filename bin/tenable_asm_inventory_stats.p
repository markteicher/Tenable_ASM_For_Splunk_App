#!/usr/bin/env python3
# bin/tenable_asm_inventory_stats.py
#
# Tenable Attack Surface Management – Inventory Statistics
# Endpoint: POST /api/1.0/inventory
#
# Emits a single snapshot event with inventory counts & limits

import json
import sys
import time
import requests
import splunk.entity as entity
from typing import Dict, Any

APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

API_URL = "https://asm.cloud.tenable.com/api/1.0/inventory"


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

        resp = session.post(
            API_URL,
            headers=headers,
            json={},
            timeout=timeout
        )
        resp.raise_for_status()

        data = resp.json()
        stats = data.get("stats", {})

        emit({
            "event_type": "asm_inventory_stats",
            "total_assets": stats.get("total"),
            "domains": stats.get("domaincount"),
            "subdomains": stats.get("subdomaincount"),
            "hosts": stats.get("hostcount"),
            "ips": stats.get("ipcount"),
            "hidden_count": data.get("hiddenCount"),
            "free_limit_reached": data.get("freeLimitReached"),
            "retrieved_at": int(time.time())
        })

    except Exception as exc:
        emit({
            "event_type": "asm_inventory_stats_error",
            "error": str(exc),
            "ts": int(time.time())
        })
        sys.exit(1)


if __name__ == "__main__":
    main()
