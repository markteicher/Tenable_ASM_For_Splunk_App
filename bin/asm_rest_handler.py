#!/usr/bin/env python3
"""
Tenable Attack Surface Management – REST Handler
Handles setup, validation, and input control for the Splunk App
"""

import json
import socket
import time

import requests
from splunk.persistconn.application import PersistentServerConnectionApplication
from splunk.rest import simpleRequest

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
        payload = json.loads(request.get("payload") or "{}")
        self._write_conf(payload)
        return {
            "status": 200,
            "payload": {"message": "Configuration saved"},
        }

    def test_auth(self, request):
        payload = json.loads(request.get("payload") or "{}")
        api_key = payload.get("asm_api_key")

        if not api_key:
            return {"status": 400, "payload": {"error": "API key missing"}}

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
            return {"status": 401, "payload": {"error": str(e)}}

        return {"status": 200, "payload": {"message": "Authentication successful"}}

    # ---------- HARDENED PROXY TEST ----------

    def test_proxy(self, request):
        payload = json.loads(request.get("payload") or "{}")

        # Accept proxy fields either directly from the setup button post,
        # or in the persisted config format.
        cfg = payload.copy()

        test_url = payload.get("test_url") or "https://www.google.com"
        timeout = int(payload.get("timeout") or 10)

        result = {
            "success": False,
            "test_url": test_url,
            "final_url": None,
            "http_status": None,
            "latency_ms": None,
            "resolved_ip": None,
            "tls": {
                "tls_version": None,
                "cipher": None,
            },
            "cert": {
                "subject_cn": None,
                "issuer_cn": None,
                "not_before": None,
                "not_after": None,
                "sans_count": None,
            },
            "error": None,
        }

        try:
            # Best-effort DNS resolution for reporting
            try:
                host = test_url.split("://", 1)[-1].split("/", 1)[0]
                result["resolved_ip"] = socket.gethostbyname(host)
            except Exception:
                pass

            proxies = self._build_proxy(cfg)  # uses proxy_enabled + host/port/etc.

            start = time.time()

            # stream=True to best-effort expose the underlying socket for TLS introspection
            r = requests.get(
                test_url,
                proxies=proxies,
                timeout=timeout,
                verify=True,
                allow_redirects=True,
                stream=True,
                headers={"User-Agent": "Splunk-ASM-ProxyTest/1.0"},
            )

            result["latency_ms"] = round((time.time() - start) * 1000.0, 2)
            result["http_status"] = r.status_code
            result["final_url"] = r.url

            # Raise for non-2xx to keep failure shape consistent
            r.raise_for_status()

            # --- TLS details (best effort; depends on Python/urllib3 internals) ---
            sock = None
            try:
                sock = getattr(getattr(getattr(r, "raw", None), "connection", None), "sock", None)
            except Exception:
                sock = None

            if sock:
                try:
                    result["tls"]["tls_version"] = getattr(sock, "version", lambda: None)()
                except Exception:
                    pass

                try:
                    c = getattr(sock, "cipher", lambda: None)()
                    result["tls"]["cipher"] = c[0] if isinstance(c, tuple) and len(c) > 0 else str(c)
                except Exception:
                    pass

                # Certificate parsing is also best-effort (format differs by environment)
                try:
                    cert = sock.getpeercert() or {}
                except Exception:
                    cert = {}

                try:
                    subj = cert.get("subject") or []
                    for entry in subj:
                        for k, v in entry:
                            if str(k).lower() == "commonname":
                                result["cert"]["subject_cn"] = v
                                raise StopIteration
                except StopIteration:
                    pass
                except Exception:
                    pass

                try:
                    iss = cert.get("issuer") or []
                    for entry in iss:
                        for k, v in entry:
                            if str(k).lower() == "commonname":
                                result["cert"]["issuer_cn"] = v
                                raise StopIteration
                except StopIteration:
                    pass
                except Exception:
                    pass

                try:
                    result["cert"]["not_before"] = cert.get("notBefore")
                    result["cert"]["not_after"] = cert.get("notAfter")
                    sans = cert.get("subjectAltName") or []
                    result["cert"]["sans_count"] = len(sans) if isinstance(sans, list) else None
                except Exception:
                    pass

            result["success"] = True
            return {"status": 200, "payload": result}

        except requests.exceptions.SSLError as e:
            result["error"] = f"TLS/SSL error: {e}"
            return {"status": 502, "payload": result}

        except requests.exceptions.ProxyError as e:
            result["error"] = f"Proxy error: {e}"
            return {"status": 502, "payload": result}

        except requests.exceptions.ConnectTimeout as e:
            result["error"] = f"Connect timeout: {e}"
            return {"status": 504, "payload": result}

        except requests.exceptions.ReadTimeout as e:
            result["error"] = f"Read timeout: {e}"
            return {"status": 504, "payload": result}

        except requests.exceptions.HTTPError as e:
            result["error"] = f"HTTP error: {e}"
            return {"status": 502, "payload": result}

        except Exception as e:
            result["error"] = f"Unexpected error: {e}"
            return {"status": 502, "payload": result}

    def apply_inputs(self, request):
        cfg = self._read_conf()
        index = cfg.get("asm_index")

        if not index:
            return {"status": 400, "payload": {"error": "Index not configured"}}

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

        return {"status": 200, "payload": {"message": "Inputs applied"}}

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

        return {"status": 404, "payload": {"error": "Unknown endpoint"}}
