#!/usr/bin/env python3

import json
import sys
import requests
import splunk.admin as admin
from splunk.entity import getEntity

ASM_TEST_URL = "https://asm.cloud.tenable.com/api/1.0/global"

class ProxyTestHandler(admin.MConfigHandler):

    def handleList(self, confInfo):
        try:
            # Read saved setup values
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

            headers = {
                "accept": "application/json",
                "Authorization": f"Bearer {api_key}"
            }

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

            r = requests.get(
                ASM_TEST_URL,
                headers=headers,
                proxies=proxies,
                timeout=15
            )

            r.raise_for_status()

            confInfo['result'].append({
                'status': 'success',
                'message': 'Proxy connection successful'
            })

        except Exception as e:
            confInfo['result'].append({
                'status': 'error',
                'message': str(e)
            })

admin.init(ProxyTestHandler, admin.CONTEXT_NONE)
