# mytool/plugins/xss.py

from mytool.plugins.base import Plugin
from mytool.attacks.payloads import PayloadManager
import aiohttp
import requests
from urllib.parse import urljoin

class XssPlugin(Plugin):
    name = "xss"

    def __init__(self, options=None):
        """
        options=None을 허용하여 baseline/reflective 테스트를 지원합니다.
        stored 테스트 시 options가 필요합니다.
        """
        super().__init__()
        self.options = options

    async def run(self, target: str, options):
        # 1) Baseline 반사형 체크: 'test'가 반영되지 않으면 취약하지 않음
        base_ok, _ = await self.test_payload(target, "test", options)
        if not base_ok:
            return {"vulnerable": False, "details": []}

        details = []

        # 페이로드 벡터 로드
        vectors = PayloadManager.load().get("xss", {})

        # 2) Reflective XSS 검사
        for payload in vectors.get("reflective", []):
            ok, resp_text = await self.test_payload(target, payload, options)
            details.append({
                "category": "reflective",
                "payload": payload,
                "success": ok,
                "response_text": resp_text,
            })

        # 3) Stored XSS 검사 (options가 있을 때)
        if self.options:
            for payload in vectors.get("stored", []):
                self.attack_stored(payload)
                html = self.fetch_page()
                stored_ok = payload in html
                details.append({
                    "category": "stored",
                    "payload": payload,
                    "success": stored_ok,
                    "response_text": html,
                })

        # 4) DOM-based XSS 검사
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
        # 반사형 테스트는 INJECT_HERE 치환
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
                    return (payload in text, text)
            except Exception as e:
                return (False, str(e))

    def attack_stored(self, payload: str):
        submit_url = urljoin(self.options.target, "/submit")
        data = {"input_field": payload}
        return requests.post(submit_url, data=data, timeout=self.options.timeout)

    def fetch_page(self):
        view_url = urljoin(self.options.target, "/view")
        resp = requests.get(view_url, timeout=self.options.timeout)
        resp.raise_for_status()
        return resp.text
