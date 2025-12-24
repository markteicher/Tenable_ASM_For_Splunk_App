#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Tenable Attack Surface Management – REST Handler
------------------------------------------------
Responsibilities:
- Save ASM configuration (API key, index, proxy)
- Enable/disable modular inputs
- Test proxy connectivity (google.com + asm.cloud.tenable.com)
- Test ASM API authentication
- Persist settings into asm_settings.conf
"""

import json
import time
import socket
import ssl
import urllib.request
from urllib.error import URLError, HTTPError

import splunk.admin as admin
import splunk.entity as entity


APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"


ASM_BASE_URL = "https://asm.cloud.tenable.com"
PROXY_TEST_URLS = [
    "https://www.google.com",
    ASM_BASE_URL
]


# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def _now_ms():
    return int(time.time() * 1000)


def _write_conf(settings: dict):
    entity.setEntity(
        f"configs/conf-{CONF_FILE}",
        CONF_STANZA,
        settings,
        namespace=APP_NAME,
        owner="nobody"
    )


def _read_conf():
    try:
        return entity.getEntity(
            f"configs/conf-{CONF_FILE}",
            CONF_STANZA,
            namespace=APP_NAME,
            owner="nobody"
        )
    except Exception:
        return {}


def _proxy_handler(proxy):
    if not proxy:
        return None
    return urllib.request.ProxyHandler({
        "http": proxy,
        "https": proxy
    })


def _http_request(url, headers=None, proxy=None, timeout=10):
    handlers = []
    if proxy:
        handlers.append(_proxy_handler(proxy))
    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=headers or {})
    return opener.open(req, timeout=timeout)


# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

def test_proxy(proxy_url: str):
    results = []
    for url in PROXY_TEST_URLS:
        start = _now_ms()
        try:
            resp = _http_request(url, proxy=proxy_url)
            latency = _now_ms() - start
            tls = resp.fp.raw._sock.version() if hasattr(resp.fp.raw, "_sock") else None
            results.append({
                "url": url,
                "status": "success",
                "http_status": resp.status,
                "latency_ms": latency,
                "tls_version": tls
            })
        except Exception as e:
            latency = _now_ms() - start
            results.append({
                "url": url,
                "status": "failure",
                "error": str(e),
                "latency_ms": latency
            })
    return results


def test_auth(api_key: str, proxy: str = None):
    headers = {
        "accept": "application/json",
        "Authorization": api_key
    }
    try:
        resp = _http_request(
            f"{ASM_BASE_URL}/api/1.0/inventory",
            headers=headers,
            proxy=proxy
        )
        return {
            "status": "success",
            "http_status": resp.status
        }
    except HTTPError as e:
        return {
            "status": "failure",
            "http_status": e.code,
            "error": e.read().decode("utf-8", errors="ignore")
        }
    except Exception as e:
        return {
            "status": "failure",
            "error": str(e)
        }


def set_input_state(script_name: str, enabled: bool):
    stanza = f"script://./bin/{script_name}"
    entity.setEntity(
        "configs/conf-inputs",
        stanza,
        {"disabled": "0" if enabled else "1"},
        namespace=APP_NAME,
        owner="nobody"
    )


# ------------------------------------------------------------
# REST Controller
# ------------------------------------------------------------

class ASMRestHandler(admin.MConfigHandler):

    def setup(self):
        for arg in [
            "action",
            "api_key",
            "proxy",
            "index",
            "inputs"
        ]:
            self.supportedArgs.addOptArg(arg)

    def handle(self):
        action = self.callerArgs.get("action", [""])[0]

        if action == "save":
            self._handle_save()
        elif action == "proxy_test":
            self._handle_proxy_test()
        elif action == "auth_test":
            self._handle_auth_test()
        else:
            raise admin.ArgValidationException("Invalid action")

    # --------------------------------------------------------

    def _handle_save(self):
        api_key = self.callerArgs.get("api_key", [""])[0]
        proxy = self.callerArgs.get("proxy", [""])[0]
        index = self.callerArgs.get("index", [""])[0]
        inputs_raw = self.callerArgs.get("inputs", ["[]"])[0]

        try:
            inputs = json.loads(inputs_raw)
        except Exception:
            raise admin.ArgValidationException("Invalid inputs JSON")

        settings = {
            "api_key": api_key,
            "proxy": proxy,
            "index": index,
            "last_updated": str(int(time.time()))
        }

        _write_conf(settings)

        for script, enabled in inputs.items():
            set_input_state(script, enabled)

        self.writeResponse({
            "status": "success",
            "message": "Configuration saved"
        })

    # --------------------------------------------------------

    def _handle_proxy_test(self):
        proxy = self.callerArgs.get("proxy", [""])[0]
        result = test_proxy(proxy)
        self.writeResponse({
            "status": "ok",
            "results": result
        })

    # --------------------------------------------------------

    def _handle_auth_test(self):
        api_key = self.callerArgs.get("api_key", [""])[0]
        proxy = self.callerArgs.get("proxy", [""])[0]
        result = test_auth(api_key, proxy)
        self.writeResponse(result)


# ------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------

admin.init(ASMRestHandler, admin.CONTEXT_NONE)
