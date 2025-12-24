#!/usr/bin/env python3
import json
import os
import sys
from configparser import ConfigParser

import requests

URL = "https://asm.cloud.tenable.com/api/1.0/admin/users"

def app_root():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

def load_settings():
    root = app_root()
    cp = ConfigParser()
    if not cp.read([f"{root}/local/asm_settings.conf", f"{root}/default/asm_settings.conf"]):
        raise RuntimeError("asm_settings.conf not found")

    s = cp["tenable_asm"]
    api_key = (s.get("api_key") or "").strip()
    if not api_key:
        raise RuntimeError("Missing api_key in [tenable_asm]")

    proxy_enabled = (s.get("proxy_enabled") or "0").strip()
    proxy_url = (s.get("proxy_url") or "").strip()
    timeout = int((s.get("timeout_seconds") or "60").strip())

    return api_key, proxy_enabled, proxy_url, timeout

def main():
    api_key, proxy_enabled, proxy_url, timeout = load_settings()

    headers = {
        "accept": "application/json",
        "Authorization": api_key,   # EXACTLY like your working script
    }

    sess = requests.Session()
    if proxy_enabled == "1" and proxy_url:
        sess.proxies.update({"http": proxy_url, "https": proxy_url})

    r = sess.get(URL, headers=headers, timeout=timeout)
    r.raise_for_status()

    data = r.json()
    users = data["list"]  # EXACTLY like your working script

    for u in users:
        print(json.dumps(u, ensure_ascii=False))

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(json.dumps({"event_type": "tenable_asm_admin_users_error", "error": str(e)}))
        sys.exit(1)
