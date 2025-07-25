# tests/test_xss_reflective.py

import pytest
from mytool.plugins.xss import XssPlugin
from mytool.config import ScanOptions

@pytest.mark.asyncio
async def test_reflective_xss(httpserver):
    payload = "<script>alert(1)</script>"

    # 1) Baseline reflection 체크
    httpserver.expect_request(
        "/vuln",
        query_string={"input": "test"}
    ).respond_with_data("test")

    # 2) Reflective XSS 체크
    httpserver.expect_request(
        "/vuln",
        query_string={"input": payload}   # <-- 여기 payload 변수 끝에 불필요한 따옴표 제거
    ).respond_with_data(payload)

    plugin = XssPlugin()
    opts = ScanOptions(plugin_names=["xss"], timeout=3, concurrency=1)
    target = f"{httpserver.url_for('/vuln')}?input=INJECT_HERE"

    res = await plugin.run(target, opts)

    # reflective 카테고리 성공 확인
    assert res["vulnerable"] is True
    assert any(d["category"] == "reflective" and d["success"] for d in res["details"])
