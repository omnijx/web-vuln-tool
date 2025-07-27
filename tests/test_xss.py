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

        # 1) Reflected baseline
        base_ok, _ = await self.test_payload(target, "test", options)
        details.append({
            "category": "reflected_baseline",
            "payload": "test",
            "success": base_ok,
            "response_text": "",
        })
        if not base_ok:
            return {"vulnerable": False, "details": details}

        # 2) Stored XSS
        stored_payload = "<script>alert('stored')</script>"
        # POST로 저장
        post_resp = self.attack_stored(stored_payload)
        # GET으로 확인
        stored_html = self.fetch_page()
        stored_ok = stored_payload in stored_html
        details.append({
            "category": "stored",
            "payload": stored_payload,
            "success": stored_ok,
            "response_text": stored_html,
        })

        # 3) Reflected 카테고리별 페이로드
        data = PayloadManager.load()
        vectors = data.get("xss", {})
        for category, plist in vectors.items():
            if category in ("stored", "dom"):
                continue
            for payload in plist:
                ok, resp_text = await self.test_payload(target, payload, options)
                details.append({
                    "category": category,
                    "payload": payload,
                    "success": ok,
                    "response_text": resp_text,
                })

        # 4) DOM XSS
        dom_list = vectors.get("dom", [])
        for payload in dom_list:
            # 해시(#) 뒤에 페이로드 붙이기
            url_with_hash = f"{target}#{aiohttp.helpers.quote(payload, safe='')}"
            ok, resp_text = await self.test_payload(url_with_hash, payload, options)
            details.append({
                "category": "dom",
                "payload": payload,
                "success": ok,
                "response_text": resp_text,
            })

        return {
            "vulnerable": any(item["success"] for item in details),
            "details": details,
        }

    async def test_payload(self, target: str, payload: str, options):
        # URL에 페이로드 삽입(Reflected용)
        encoded = aiohttp.helpers.quote(payload, safe='')
        # 실제 요청 URL 구하기
        url = target.replace("INJECT_HERE", encoded)
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
