# tests/test_xss_dom.py

import pytest
from types import SimpleNamespace
from mytool.plugins.xss import XssPlugin
from mytool.attacks.payloads import PayloadManager

@pytest.fixture
def plugin():
    opts = SimpleNamespace(
        target="http://localhost:8000",
        headers={},
        timeout=5
    )
    return XssPlugin(opts)

@pytest.mark.asyncio
async def test_xss_dom(monkeypatch, plugin):
    dom_payload = "<img src=x onerror=alert('dom')>"

    # 1) PayloadManager.load 모킹: 'dom_based' 카테고리로 페이로드 지정
    fake_vectors = {"dom_based": [dom_payload]}
    monkeypatch.setattr(PayloadManager, "load", staticmethod(lambda: {"xss": fake_vectors}))

    # 2) test_payload 모킹: baseline("test")과 DOM 페이로드는 True
    async def fake_test_payload(url, payload, options):
        if payload == "test":
            return True, ""  # baseline 통과
        if payload == dom_payload:
            return True, f"<script>document.body.innerHTML='{payload}'</script>"
        return False, ""
    monkeypatch.setattr(plugin, "test_payload", fake_test_payload)

    # 3) run() 호출
    result = await plugin.run(plugin.options.target, plugin.options)

    # 4) 결과 검증 (category == "dom_based")
    dom_items = [d for d in result["details"] if d["category"] == "dom_based"]
    assert dom_items, "DOM 기반 카테고리 항목(dom_based)이 있어야 합니다"
    assert dom_items[0]["success"] is True
