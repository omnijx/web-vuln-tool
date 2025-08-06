# mytool/plugins/xss.py

from mytool.plugins.base import Plugin
from mytool.attacks.payloads import PayloadManager
import aiohttp
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

class XssPlugin(Plugin):
    name = "xss"

    def __init__(self, options=None):
        super().__init__()
        self.options = options

    async def run(self, target: str, options):
        # 1) Baseline 검사
        base_ok, _ = await self.test_payload(target, "test", options)
        if not base_ok:
            return {"vulnerable": False, "details": []}

        details = []
        vectors = PayloadManager.load().get("xss", {})

        # 2) Reflective XSS
        for payload in vectors.get("reflective", []):
            ok, resp_text = await self.test_payload(target, payload, options)
            details.append({
                "category": "reflective",
                "payload": payload,
                "success": ok,
                "response_text": resp_text,
            })

        # 3) Stored XSS
        if self.options:
            for payload in vectors.get("stored", []):
                self.attack_stored(payload)
                html = self.fetch_page()
                stored_ok = self._detect_xss(html, payload)
                details.append({
                    "category": "stored",
                    "payload": payload,
                    "success": stored_ok,
                    "response_text": html,
                })

        # 4) DOM-based XSS
        for payload in vectors.get("dom_based", []):
            url_with_hash = f"{target}#{aiohttp.helpers.quote(payload, safe='')}"
            ok, resp_text = await self.test_payload(url_with_hash, payload, options)
            details.append({
                "category": "dom_based",
                "payload": payload,
                "success": ok,
                "response_text": resp_text,
            })

        return {
            "vulnerable": any(item["success"] for item in details),
            "details": details,
        }

    async def test_payload(self, target: str, payload: str, options):
        if "INJECT_HERE" in target:
            encoded = aiohttp.helpers.quote(payload, safe='')
            url = target.replace("INJECT_HERE", encoded)
        else:
            url = target

        headers = getattr(options, "headers", {}) or {}
        timeout = getattr(options, "timeout", None)

        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(url, timeout=timeout) as resp:
                    text = await resp.text()
                    detected = self._detect_xss(text, payload)
                    return detected, text
            except Exception as e:
                return False, str(e)

    def attack_stored(self, payload: str):
        submit_url = urljoin(self.options.target, "/submit")
        data = {"input_field": payload}
        return requests.post(submit_url, data=data, timeout=self.options.timeout)

    def fetch_page(self):
        view_url = urljoin(self.options.target, "/view")
        resp = requests.get(view_url, timeout=self.options.timeout)
        resp.raise_for_status()
        return resp.text

    def _detect_xss(self, html: str, payload: str) -> bool:
        # 원시 HTML에서 우선 검사
        if payload in html:
            return True

        soup = BeautifulSoup(html, "html.parser")
        # <script> 태그 내부
        for script in soup.find_all("script"):
            if payload in script.get_text():
                return True
        # 모든 태그 속성값
        for tag in soup.find_all():
            for attr_val in tag.attrs.values():
                vals = attr_val if isinstance(attr_val, (list, tuple)) else [attr_val]
                for v in vals:
                    if v and payload in v:
                        return True
        return False
