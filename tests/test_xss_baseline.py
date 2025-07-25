# tests/test_xss_baseline.py

import pytest
from mytool.plugins.xss import XssPlugin
from mytool.config import ScanOptions

@pytest.mark.asyncio
async def test_reflection_not_allowed(httpserver):
    # 1) /vuln?input=test 요청에 "nope" 응답 → 반영 안 됨
    httpserver.expect_request("/vuln", query_string={"input": "test"}) \
              .respond_with_data("nope")

    base = httpserver.url_for("/vuln")
    target = f"{base}?input=INJECT_HERE"
    opts = ScanOptions(plugin_names=["xss"], timeout=3, concurrency=1)
    plugin = XssPlugin()

    result = await plugin.run(target, opts)

    # 반영이 안 되면 details 비어 있고 vulnerable는 False
    assert result["vulnerable"] is False
    assert result["details"] == []

@pytest.mark.asyncio
async def test_reflection_then_payload(httpserver):
    # 1) baseline: ?input=test → "test" 리턴
    httpserver.expect_request("/vuln", query_string={"input": "test"}) \
              .respond_with_data("test")
    # 2) payload: ?input=<script>alert(1)</script> → 그 스크립트 그대로 리턴
    payload = "<script>alert(1)</script>"
    httpserver.expect_request("/vuln", query_string={"input": payload}) \
              .respond_with_data(payload)

    base = httpserver.url_for("/vuln")
    target = f"{base}?input=INJECT_HERE"
    opts = ScanOptions(plugin_names=["xss"], timeout=3, concurrency=1)
    plugin = XssPlugin()

    result = await plugin.run(target, opts)

    # baseline 통과 후, 실제 페이로드가 반영되어야 vulnerable=True
    assert result["vulnerable"] is True
    # details 중에 response_text에 payload가 들어있는지 확인
    assert any(payload in d["response_text"] for d in result["details"])
