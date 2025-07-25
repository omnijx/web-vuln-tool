# mytool/plugins/xss.py

from mytool.plugins.base import Plugin
from mytool.attacks.payloads import PayloadManager
import aiohttp

class XssPlugin(Plugin):
    name = "xss"

    async def run(self, target: str, options):
        # 1) Baseline reflection check
        base_ok, _ = await self.test_payload(target, "test", options)
        if not base_ok:
            return {"vulnerable": False, "details": []}

        # 2) Category-based payload testing
        data = PayloadManager.load()
        vectors = data.get("xss", {})

        details = []
        for category, payload_list in vectors.items():
            for payload in payload_list:
                ok, resp = await self.test_payload(target, payload, options)
                details.append({
                    "category": category,
                    "payload": payload,
                    "success": ok,
                    "response_text": resp,
                })

        return {
            "vulnerable": any(item["success"] for item in details),
            "details": details,
        }

    async def test_payload(self, target: str, payload: str, options):
        # Replace placeholder
        encoded = aiohttp.helpers.quote(payload, safe='')
        url = target.replace("INJECT_HERE", encoded)
        headers = options.headers or {} 

        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(url, timeout=options.timeout) as resp:
                    text = await resp.text()
                    return (payload in text, text)
            except Exception as e:
                return (False, str(e))
