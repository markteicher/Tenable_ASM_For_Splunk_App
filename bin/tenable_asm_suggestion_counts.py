#!/usr/bin/env python3
import json
import os
import requests
from datetime import datetime

BASE_URL = "https://asm.cloud.tenable.com/api/1.0/suggestions/count"

API_KEY = os.getenv("TENABLE_ASM_API_KEY")
PROXY = os.getenv("TENABLE_ASM_PROXY")

if not API_KEY:
    raise SystemExit("Missing TENABLE_ASM_API_KEY")

HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "Authorization": API_KEY
}

proxies = {"http": PROXY, "https": PROXY} if PROXY else None

def fetch_count(is_archived):
    url = f"{BASE_URL}?is_archived={'true' if is_archived else 'false'}"
    r = requests.post(url, headers=HEADERS, proxies=proxies, timeout=60)
    r.raise_for_status()
    return r.json()["count"]

def main():
    ts = datetime.utcnow().isoformat() + "Z"

    for archived in (False, True):
        count = fetch_count(archived)
        event = {
            "timestamp": ts,
            "is_archived": archived,
            "suggestion_count": count
        }
        print(json.dumps(event))

if __name__ == "__main__":
    main()
