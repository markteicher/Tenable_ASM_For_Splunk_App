#!/usr/bin/env python3

import requests
import splunk.admin as admin
from splunk.entity import getEntity

GOOGLE_TEST_URL = "https://www.google.com/generate_204"
ASM_TEST_URL = "https://asm.cloud.tenable.com/api/1.0/global"

class ProxyTestHandler(admin.MConfigHandler):

    def handleList(self, confInfo):

        results = []

        try:
            settings = getEntity(
                'configs/conf-tenable_asm',
                'settings',
                namespace=self.appName,
                owner='nobody'
            )

            api_key = settings.get('asm_api_key')
            proxy_host = settings.get('proxy_host')
            proxy_port = settings.get('proxy_port')
            proxy_user = settings.get('proxy_user')
            proxy_pass = settings.get('proxy_pass')

            if not api_key:
                raise Exception("ASM API key is not configured")

            proxies = None
            if proxy_host and proxy_port:
                if proxy_user and proxy_pass:
                    proxy_url = f"http://{proxy_user}:{proxy_pass}@{proxy_host}:{proxy_port}"
                else:
                    proxy_url = f"http://{proxy_host}:{proxy_port}"

                proxies = {
                    "http": proxy_url,
                    "https": proxy_url
                }

            # ----------------------------
            # Stage 1: Internet test
            # ----------------------------
            try:
                r = requests.get(
                    GOOGLE_TEST_URL,
                    proxies=proxies,
                    timeout=10
                )
                r.raise_for_status()
                results.append("✔ Internet connectivity via proxy: OK")
            except Exception as e:
                results.append(f"✖ Internet connectivity via proxy FAILED: {e}")
                raise

            # ----------------------------
            # Stage 2: ASM API test
            # ----------------------------
            headers = {
                "accept": "application/json",
                "Authorization": f"Bearer {api_key}"
            }

            try:
                r = requests.get(
                    ASM_TEST_URL,
                    headers=headers,
                    proxies=proxies,
                    timeout=15
                )
                r.raise_for_status()
                results.append("✔ Tenable ASM API connectivity: OK")
            except Exception as e:
                results.append(f"✖ Tenable ASM API connectivity FAILED: {e}")
                raise

            confInfo['result'].append({
                'status': 'success',
                'details': results
            })

        except Exception:
            confInfo['result'].append({
                'status': 'error',
                'details': results
            })

admin.init(ProxyTestHandler, admin.CONTEXT_NONE)
