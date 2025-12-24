#!/usr/bin/env python3
# bin/tenable_asm_inventories.py
#
# Tenable Attack Surface Management – Inventories
# Endpoint: GET /api/1.0/inventories/list

import json
import sys
import time
from typing import Any, Dict

import requests
import splunk.entity as entity

APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

API_URL = "https://asm.cloud.tenable.com/api/1.0/inventories/list"


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
    now = int(time.time())

    try:
        cfg = load_settings()

        api_key = get_str(cfg, "api_key")
        if not api_key:
            raise RuntimeError("Missing api_key in asm_settings.conf")

        proxy = get_str(cfg, "proxy")
        timeout = get_int(cfg, "timeout_seconds", 60)

        headers = {
            "accept": "application/json",
            "Authorization": api_key,
        }

        session = requests.Session()
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        resp = session.get(API_URL, headers=headers, timeout=timeout)
        resp.raise_for_status()

        payload = resp.json()
        inventories = payload.get("list", [])

        for inv in inventories:
            emit({
                "event_type": "asm_inventory",
                "inventory_id": inv.get("inventory_id"),
                "inventory_name": inv.get("inventory_name"),
                "current_asset_count": inv.get("current_asset_count"),
                "source_suggestions": inv.get("source_suggestions"),
                "business_id": inv.get("business_id"),
                "users_total": inv.get("users_total"),
                "api_key_present": bool(inv.get("api_key")),
                "enumeration_wordlist": inv.get("enumeration_wordlist"),
                "has_custom_wordlist": inv.get("has_custom_wordlist"),
                "retrieved_at": now,
            })

    except Exception as exc:
        emit({
            "event_type": "asm_inventory_error",
