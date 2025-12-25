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

Actions:
- action=save
- action=proxy_test
- action=auth_test
"""

import json
import time
import ssl
import socket
import urllib.request
from urllib.error import HTTPError, URLError

import splunk.admin as admin
import splunk.entity as entity

APP_NAME = "Tenable_Attack_Surface_Management_for_Splunk"
CONF_FILE = "asm_settings"
CONF_STANZA = "settings"

ASM_BASE_URL = "https://asm.cloud.tenable.com"

# Proxy test targets (must be stable and simple)
PROXY_TEST_URLS = [
    "https://www.google.com",
    ASM_BASE_URL,
]

# Auth test target (must require auth, low cost, stable)
# NOTE: /api/1.0/inventory is not reliable. Use inventories/list (GET).
AUTH_TEST_PATH = "/api/1.0/inventories/list"


# ------------------------------------------------------------
# Utilities
# ------------------------------------------------------------

def _now_ms() -> int:
    return int(time.time() * 1000)


def _write_conf(settings: dict) -> None:
    entity.setEntity(
        f"configs/conf-{CONF_FILE}",
        CONF_STANZA,
        settings,
        namespace=APP_NAME,
        owner="nobody",
    )


def _read_conf() -> dict:
    try:
        return entity.getEntity(
            f"configs/conf-{CONF_FILE}",
            CONF_STANZA,
            namespace=APP_NAME,
            owner="nobody",
        )
    except Exception:
        return {}


def _build_proxy_handler(proxy: str):
    if not proxy:
        return None
    return urllib.request.ProxyHandler({"http": proxy, "https": proxy})


def _open_url(url: str, headers: dict = None, proxy: str = None, timeout: int = 15):
    handlers = []
    ph = _build_proxy_handler(proxy)
    if ph:
        handlers.append(ph)

    opener = urllib.request.build_opener(*handlers)
    req = urllib.request.Request(url, headers=headers or {})
    return opener.open(req, timeout=timeout)


def _safe_read_body(resp, max_bytes: int = 4096) -> str:
    try:
        data = resp.read(max_bytes)
        if isinstance(data, bytes):
            return data.decode("utf-8", errors="ignore")
        return str(data)
    except Exception:
        return ""


def _tls_probe(hostname: str, port: int = 443, proxy: str = None, timeout: int = 10) -> dict:
    """
    Best-effort TLS info probe.
    - If proxy is provided (HTTP proxy), urllib handles CONNECT and we can’t reliably introspect here,
      so return proxy-aware message.
    - Without proxy, do a direct TLS handshake to capture TLS version + cipher.
    """
    if proxy:
        return {
            "mode": "proxy",
            "note": "TLS inspection skipped for proxy path (CONNECT handled by proxy/urllib)."
        }

    ctx = ssl.create_default_context()
    start = _now_ms()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                latency_ms = _now_ms() - start
                return {
                    "mode": "direct",
                    "tls_version": ssock.version(),
                    "cipher": ssock.cipher()[0] if ssock.cipher() else None,
                    "latency_ms": latency_ms,
                }
    except Exception as e:
        latency_ms = _now_ms() - start
        return {
            "mode": "direct",
            "error": str(e),
            "latency_ms": latency_ms,
        }


def _normalize_url(url: str) -> str:
    return url.strip()


def _extract_hostname(url: str) -> str:
    # Minimal parse (avoid extra deps)
    u = url.replace("https://", "").replace("http://", "")
    return u.split("/")[0].split(":")[0]


# ------------------------------------------------------------
# Tests
# ------------------------------------------------------------

def test_proxy(proxy_url: str) -> list:
    """
    Proxy test:
      - For each target URL: measure HTTP status + latency
      - Add TLS probe details (direct only; proxy path returns note)
    """
    results = []
    proxy_url = (proxy_url or "").strip()

    for url in PROXY_TEST_URLS:
        url = _normalize_url(url)
        start = _now_ms()

        record = {
            "url": url,
            "proxy": proxy_url if proxy_url else "",
            "status": "unknown",
            "http_status": None,
            "latency_ms": None,
            "tls": {},
            "error": None,
        }

        try:
            resp = _open_url(url, proxy=proxy_url if proxy_url else None, timeout=15)
            latency = _now_ms() - start

            record["status"] = "success"
            record["http_status"] = getattr(resp, "status", None)
            record["latency_ms"] = latency

            # TLS probe (best-effort)
            host = _extract_hostname(url)
            record["tls"] = _tls_probe(host, proxy=proxy_url if proxy_url else None)

            # Drain small body to avoid open handles (best-effort)
            _safe_read_body(resp, max_bytes=512)

        except HTTPError as e:
            latency = _now_ms() - start
            record["status"] = "failure"
            record["http_status"] = e.code
            record["latency_ms"] = latency
            record["error"] = e.read().decode("utf-8", errors="ignore")[:1024]
            host = _extract_hostname(url)
            record["tls"] = _tls_probe(host, proxy=proxy_url if proxy_url else None)

        except URLError as e:
            latency = _now_ms() - start
            record["status"] = "failure"
            record["latency_ms"] = latency
            record["error"] = str(e.reason) if hasattr(e, "reason") else str(e)
            host = _extract_hostname(url)
            record["tls"] = _tls_probe(host, proxy=proxy_url if proxy_url else None)

        except Exception as e:
            latency = _now_ms() - start
            record["status"] = "failure"
            record["latency_ms"] = latency
            record["error"] = str(e)
            host = _extract_hostname(url)
            record["tls"] = _tls_probe(host, proxy=proxy_url if proxy_url else None)

        results.append(record)

    return results


def test_auth(api_key: str, proxy: str = None) -> dict:
    """
    Auth test:
      - Calls a stable authenticated endpoint.
      - Returns HTTP status and small response snippet for diagnostics.
    """
    api_key = (api_key or "").strip()
    proxy = (proxy or "").strip()

    headers = {
        "accept": "application/json",
        "Authorization": api_key,
    }

    url = f"{ASM_BASE_URL}{AUTH_TEST_PATH}"

    start = _now_ms()
    try:
        resp = _open_url(url, headers=headers, proxy=proxy if proxy else None, timeout=20)
        latency_ms = _now_ms() - start
        body_snip = _safe_read_body(resp, max_bytes=1024)

        return {
            "status": "success",
            "url": url,
            "http_status": getattr(resp, "status", None),
            "latency_ms": latency_ms,
            "response_snippet": body_snip,
        }

    except HTTPError as e:
        latency_ms = _now_ms() - start
        return {
            "status": "failure",
            "url": url,
            "http_status": e.code,
            "latency_ms": latency_ms,
            "error": e.read().decode("utf-8", errors="ignore")[:4096],
        }

    except Exception as e:
        latency_ms = _now_ms() - start
        return {
            "status": "failure",
            "url": url,
            "latency_ms": latency_ms,
            "error": str(e),
        }


def set_input_state(script_name: str, enabled: bool) -> None:
    stanza = f"script://./bin/{script_name}"
    entity.setEntity(
        "configs/conf-inputs",
        stanza,
        {"disabled": "0" if enabled else "1"},
        namespace=APP_NAME,
        owner="nobody",
    )


# ------------------------------------------------------------
# REST Controller
# ------------------------------------------------------------

class ASMRestHandler(admin.MConfigHandler):
    def setup(self):
        for arg in ["action", "api_key", "proxy", "index", "inputs"]:
            self.supportedArgs.addOptArg(arg)

    def handle(self):
        action = self.callerArgs.get("action", [""])[0].strip()

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
        api_key = self.callerArgs.get("api_key", [""])[0].strip()
        proxy = self.callerArgs.get("proxy", [""])[0].strip()
        index = self.callerArgs.get("index", [""])[0].strip()
        inputs_raw = self.callerArgs.get("inputs", ["{}"])[0].strip()

        # Required fields for a working app setup
        if not api_key:
            raise admin.ArgValidationException("Missing api_key")
        if not index:
            raise admin.ArgValidationException("Missing index")

        try:
            inputs = json.loads(inputs_raw) if inputs_raw else {}
            if not isinstance(inputs, dict):
                raise ValueError("inputs must be a JSON object")
        except Exception:
            raise admin.ArgValidationException("Invalid inputs JSON")

        settings = {
            "api_key": api_key,
            "proxy": proxy,
            "index": index,
            "timeout_seconds": "60",
            "last_updated": str(int(time.time())),
        }

        _write_conf(settings)

        # Toggle modular inputs
        for script, enabled in inputs.items():
            set_input_state(str(script), bool(enabled))

        self.writeResponse({
            "status": "success",
            "message": "Configuration saved",
        })

    # --------------------------------------------------------

    def _handle_proxy_test(self):
        proxy = self.callerArgs.get("proxy", [""])[0].strip()
        result = test_proxy(proxy)
        self.writeResponse({
            "status": "ok",
            "results": result,
        })

    # --------------------------------------------------------

    def _handle_auth_test(self):
        api_key = self.callerArgs.get("api_key", [""])[0].strip()
        proxy = self.callerArgs.get("proxy", [""])[0].strip()

        if not api_key:
            raise admin.ArgValidationException("Missing api_key")

        result = test_auth(api_key, proxy)
        self.writeResponse(result)


# ------------------------------------------------------------
# Entrypoint
# ------------------------------------------------------------

admin.init(ASMRestHandler, admin.CONTEXT_NONE)
