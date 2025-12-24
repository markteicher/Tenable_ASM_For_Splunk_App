#!/usr/bin/env python3
# bin/tenable_asm_suggestions.py
#
# Tenable ASM – Suggestions (active + archived)
# Endpoint: POST https://asm.cloud.tenable.com/api/1.0/suggestions/list?is_archived={true|false}
#
# Output: one JSON event per suggestion, including all suggestion fields returned by the API.
# Adds only: is_archived (request context).

import json
import sys
import requests
import splunk.entity as entity
from typing import Any, Dict, List, Optional


APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

API_URL = "https://asm.cloud.tenable.com/api/1.0/suggestions/list"


def emit(obj: Any) -> None:
    sys.stdout.write(json.dumps(obj, ensure_ascii=False) + "\n")


def load_settings() -> Dict[str, Any]:
    return entity.getEntity(
        f"configs/conf-{CONF_FILE}",
        CONF_STANZA,
        namespace=APP_NAME,
        owner="nobody",
    )


def get_str(cfg: Dict[str, Any], key: str, default: str = "") -> str:
    v = cfg.get(key)
    return str(v).strip() if v is not None else default


def get_int(cfg: Dict[str, Any], key: str, default: int) -> int:
    try:
        return int(cfg.get(key, default))
    except Exception:
        return default


def fetch_suggestions(
    session: requests.Session,
    headers: Dict[str, str],
    timeout: int,
    is_archived: bool,
) -> List[Dict[str, Any]]:
    """
    Returns the API's suggestions list for one archived mode.
    Expected response:
      { "suggestions": [ { ... } ], "total": 0 }
    """
    url = f"{API_URL}?is_archived={'true' if is_archived else 'false'}"

    # API example shows POST (no required body)
    resp = session.post(url, headers=headers, timeout=timeout)
    resp.raise_for_status()

    payload = resp.json()
    suggestions = payload.get("suggestions", None)

    if not isinstance(suggestions, list):
        raise RuntimeError("Unexpected response shape: 'suggestions' list not found")

    return suggestions


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
            "Authorization": api_key,
        }

        session = requests.Session()
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})

        # 1) Active suggestions (is_archived=false)
        active = fetch_suggestions(session, headers, timeout, is_archived=False)
        for s in active:
            if isinstance(s, dict):
                out = dict(s)               # keep all returned suggestion fields
                out["is_archived"] = False  # add request context only
                emit(out)

        # 2) Archived suggestions (is_archived=true)
        archived = fetch_suggestions(session, headers, timeout, is_archived=True)
        for s in archived:
            if isinstance(s, dict):
                out = dict(s)
                out["is_archived"] = True
                emit(out)

    except Exception as exc:
        emit({"error": str(exc)})
        sys.exit(1)


if __name__ == "__main__":
    main()
