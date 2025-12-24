#!/usr/bin/env python3
# bin/tenable_asm_user_actions.py
#
# Tenable ASM -> User Action Logs
# Endpoint: GET https://asm.cloud.tenable.com/api/1.0/user-action-logs
# Response shape (per Tenable): { "list": [...], "total": <int> }
#
# Output: 1 JSON event per line to stdout (Splunk scripted input friendly)

import json
import sys
import time
from typing import Any, Dict, List, Optional

import requests
import splunk.entity as entity


APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

BASE_URL = "https://asm.cloud.tenable.com/api/1.0/user-action-logs"


def _emit(obj: Dict[str, Any]) -> None:
    print(json.dumps(obj, ensure_ascii=False))


def _load_settings() -> Dict[str, Any]:
    return entity.getEntity(
        f"configs/conf-{CONF_FILE}",
        CONF_STANZA,
        namespace=APP_NAME,
        owner="nobody",
    )


def _get_int(settings: Dict[str, Any], key: str, default: int) -> int:
    try:
        v = str(settings.get(key, "")).strip()
        return int(v) if v else default
    except Exception:
        return default


def _get_str(settings: Dict[str, Any], key: str, default: str = "") -> str:
    v = settings.get(key)
    return str(v).strip() if v is not None else default


def main() -> None:
    try:
        settings = _load_settings()
        api_key = _get_str(settings, "api_key")
        if not api_key:
            raise RuntimeError("Missing api_key in local/asm_settings.conf [settings]")

        proxy = _get_str(settings, "proxy")
        timeout = _get_int(settings, "timeout_seconds", 60)

        # paging controls (can be overridden later via asm_settings.conf if you want)
        limit = _get_int(settings, "user_action_limit", 200)
        if limit <= 0:
            limit = 200
        # don’t assume Tenable max; cap to something sane
        if limit > 500:
            limit = 500

        headers = {
            "accept": "application/json",
            "Authorization": api_key,  # EXACT: matches your working ASM scripts
        }

        sess = requests.Session()
        if proxy:
            sess.proxies.update({"http": proxy, "https": proxy})

        offset = 0
        total_seen = 0

        while True:
            params = {"offset": offset, "limit": limit}
            resp = sess.get(BASE_URL, headers=headers, params=params, timeout=timeout)
            resp.raise_for_status()

            payload = resp.json()
            events: List[Dict[str, Any]] = payload.get("list", []) or []
            total = payload.get("total", None)

            for ev in events:
                _emit(ev)
            total_seen += len(events)

            # stop conditions
            if not events:
                break
            if len(events) < limit:
                break
            if isinstance(total, int) and total_seen >= total:
                break

            offset += len(events)

    except Exception as e:
        _emit(
            {
                "event_type": "tenable_asm_user_action_logs_error",
                "error": str(e),
                "ts": int(time.time()),
            }
        )
        sys.exit(1)


if __name__ == "__main__":
    main()
