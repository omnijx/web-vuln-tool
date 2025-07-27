# mytool/plugins/xss.py

from mytool.plugins.base import Plugin
from mytool.attacks.payloads import PayloadManager
import aiohttp
import requests
from urllib.parse import urljoin

class XssPlugin(Plugin):
    name = "xss"

    def __init__(self, options):
        super().__init__()
        self.options = options

    async def run(self, target: str, options):
        details = []

        # 1) Reflected baseline (간단 확인용)
        base_ok, _ = await self.test_payload(target, "test", options)
        details.append({
            "category": "reflected_baseline",
            "payload": "test",
            "success": base_ok,
            "response_text": "",
        })
        if not base_ok:
            return {"vulnerable": False, "details": details}

        # 로드된 페이로드 벡터
        data = PayloadManager.load()
        vectors = data.get("xss", {})

        # 2) Reflected XSS 전체 카테고리
        for payload in vectors.get("reflective", []):
            ok, resp_text = await self.test_payload(target, payload, options)
            details.append({
                "category": "reflective",
                "payload": payload,
                "success": ok,
                "response_text": resp_text,
            })

        # 3) Stored XSS
        for payload in vectors.get("stored", []):
            # POST로 저장
            self.attack_stored(payload)
            # GET으로 확인
            html = self.fetch_page()
            stored_ok = payload in html
            details.append({
                "category": "stored",
                "payload": payload,
                "success": stored_ok,
                "response_text": html,
            })

        # 4) DOM-based XSS
        for payload in vectors.get("dom_based", []):
            # 해시(#) 뒤에 페이로드 붙이기
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
        # INJECT_HERE 구문은 reflective 테스트에서만 활용하세요
        if "INJECT_HERE" in target:
            encoded = aiohttp.helpers.quote(payload, safe='')
            url = target.replace("INJECT_HERE", encoded)
        else:
            url = target
        headers = options.headers or {}

        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(url, timeout=options.timeout) as resp:
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
