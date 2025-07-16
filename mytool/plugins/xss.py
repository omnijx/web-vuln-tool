# mytool/plugins/xss.py

from mytool.plugins.base import Plugin
from mytool.attacks.payloads import PayloadManager
import aiohttp

class XssPlugin(Plugin):
    name = "xss"

    async def run(self, target: str, options):
        details = []
        payloads = PayloadManager.get("xss")
        for p in payloads:
            ok, resp = await self.test_payload(target, p, options)
            details.append({
                "payload": p,
                "success": ok,
                "response_text": resp,
            })
        return {
            "vulnerable": any(item["success"] for item in details),
            "details": details,
        }

    async def test_payload(self, target: str, payload: str, options):
        url = target.replace("INJECT_HERE", aiohttp.helpers.quote(payload, safe=''))
        timeout = options.timeout
        headers = options.headers or {}

        async with aiohttp.ClientSession(headers=headers) as session:
            try:
                async with session.get(url, timeout=timeout) as resp:
                    text = await resp.text()
                    return (payload in text, text)
            except Exception as e:
                return (False, str(e))
