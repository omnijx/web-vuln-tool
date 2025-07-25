# mytool/plugins/xss.py

from mytool.plugins.base import Plugin
from mytool.attacks.payloads import PayloadManager
import aiohttp

class XssPlugin(Plugin):
    name = "xss"

    async def run(self, target: str, options):
        # 1) Baseline reflection 체크 (test)
        base_ok, _ = await self.test_payload(target, "test", options)
        if not base_ok:
            return {"vulnerable": False, "details": []}

        # 2) Payloads.yaml 에서 각 카테고리별 벡터 가져오기
        data = PayloadManager.load()
        xss_vectors = data["xss"]

        details = []
        for category, vectors in xss_vectors.items():
            for payload in vectors:
                ok, resp = await self.test_payload(target, payload, options)
                details.append({
                    "category": category,         # reflective / stored / dom_based
                    "payload": payload,
                    "success": ok,
                    "response_text": resp,
                })

        return {
            "vulnerable": any(d["success"] for d in details),
            "details": details,
        }

    async def test_payload(self, target: str, payload: str, options):
        # INJECT_HERE → payload 치환 후 GET
        url = target.replace("INJECT_HERE", aiohttp.helpers.quote(payload, safe=''))
        headers = options.headers or {}
        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(url, timeout=options.timeout) as r:
                    text = await r.text()
                    return (payload in text, text)
            except Exception as e:
                return (False, str(e))
