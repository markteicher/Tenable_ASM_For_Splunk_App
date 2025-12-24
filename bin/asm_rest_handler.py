#!/usr/bin/env python3
"""
Tenable Attack Surface Management – REST Handler
Handles setup, validation, and input control for the Splunk App
"""

import json
import socket
import time
import requests

from splunk.rest import simpleRequest
from splunk.persistconn.application import PersistentServerConnectionApplication

CONF_FILE = "asm_settings"
CONF_STANZA = "global"


class ASMRestHandler(PersistentServerConnectionApplication):
    """
    REST handler for Tenable ASM Splunk App
    """

    # ---------- Utility Methods ----------

    def _read_conf(self):
        _, content = simpleRequest(
            f"/servicesNS/nobody/{self.app_name}/configs/conf-{CONF_FILE}",
            method="GET",
            getargs={"output_mode": "json"},
        )
        data = json.loads(content)
        return data["entry"][0]["content"]

    def _write_conf(self, settings: dict):
        for key, value in settings.items():
            simpleRequest(
                f"/servicesNS/nobody/{self.app_name}/configs/conf-{CONF_FILE}/{CONF_STANZA}",
                method="POST",
                postargs={key: value},
            )

    def _build_proxy(self, cfg: dict):
        if cfg.get("proxy_enabled") != "true":
            return None

        scheme = cfg.get("proxy_scheme", "http")
        host = cfg.get("proxy_host")
        port = cfg.get("proxy_port")

        if not host or not port:
            raise ValueError("Proxy enabled but host/port missing")

        auth = ""
        if cfg.get("proxy_username") and cfg.get("proxy_password"):
            auth = f"{cfg['proxy_username']}:{cfg['proxy_password']}@"

        proxy_url = f"{scheme}://{auth}{host}:{port}"
        return {"http": proxy_url, "https": proxy_url}

    # ---------- REST Handlers ----------

    def get_config(self, request):
        cfg = self._read_conf()
        return {
            "status": 200,
            "payload": cfg,
        }

    def save_config(self, request):
        payload = json.loads(request["payload"])
        self._write_conf(payload)
        return {
            "status": 200,
            "payload": {"message": "Configuration saved"},
        }

    def test_auth(self, request):
        payload = json.loads(request["payload"])
        api_key = payload.get("asm_api_key")

        if not api_key:
            return {
                "status": 400,
                "payload": {"error": "API key missing"},
            }

        headers = {
            "accept": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

        try:
            r = requests.get(
                "https://asm.cloud.tenable.com/api/1.0/global",
                headers=headers,
                timeout=10,
            )
            r.raise_for_status()
        except Exception as e:
            return {
                "status": 401,
                "payload": {"error": str(e)},
            }

        return {
            "status": 200,
            "payload": {"message": "Authentication successful"},
        }

    def test_proxy(self, request):
        payload = json.loads(request["payload"])
        cfg = payload.copy()

        try:
            proxies = self._build_proxy(cfg)
            start = time.time()
            r = requests.get(
                "https://www.google.com",
                proxies=proxies,
                timeout=10,
            )
            latency = round((time.time() - start) * 1000, 2)
            r.raise_for_status()
        except Exception as e:
            return {
                "status": 502,
                "payload": {
                    "error": "Proxy test failed",
                    "detail": str(e),
                },
            }

        return {
            "status": 200,
            "payload": {
                "message": "Proxy connectivity successful",
                "latency_ms": latency,
            },
        }

    def apply_inputs(self, request):
        cfg = self._read_conf()
        index = cfg.get("asm_index")

        if not index:
            return {
                "status": 400,
                "payload": {"error": "Index not configured"},
            }

        input_map = {
            "enable_assets": "tenable_asm_assets.py",
            "enable_inventories": "tenable_asm_inventories.py",
            "enable_suggestions": "tenable_asm_suggestions.py",
            "enable_alerts": "tenable_asm_alerts.py",
            "enable_subscriptions": "tenable_asm_subscriptions.py",
            "enable_txt_records": "tenable_asm_txt_records.py",
            "enable_activity_logs": "tenable_asm_logs.py",
        }

        for flag, script in input_map.items():
            enabled = cfg.get(flag) == "true"
            simpleRequest(
                f"/servicesNS/nobody/{self.app_name}/data/inputs/script/{script}",
                method="POST",
                postargs={
                    "disabled": "0" if enabled else "1",
                    "index": index,
                },
            )

        return {
            "status": 200,
            "payload": {"message": "Inputs applied"},
        }

    # ---------- Dispatcher ----------

    def handle(self, args):
        path = args["path"].strip("/")

        if path.endswith("/config/get"):
            return self.get_config(args)
        if path.endswith("/config/save"):
            return self.save_config(args)
        if path.endswith("/auth/test"):
            return self.test_auth(args)
        if path.endswith("/proxy/test"):
            return self.test_proxy(args)
        if path.endswith("/inputs/apply"):
            return self.apply_inputs(args)

        return {
            "status": 404,
            "payload": {"error": "Unknown endpoint"},
        }
