import pytest
from mytool.plugins.xss import XssPlugin
from mytool.config import ScanOptions
from pytest_httpserver import HTTPServer

@pytest.mark.asyncio
async def test_xss_detects_reflected_xss(httpserver: HTTPServer):
    # 1) 페이로드 및 테스트 엔드포인트 설정
    payload = "<script>alert(1)</script>"

    # 2) 경로를 첫 번째 인자로, 쿼리 문자열은 키워드 인자로 전달
    httpserver.expect_request(
        "/vuln",
        query_string={"input": "test"}
    ).respond_with_data(payload)

    # 3) base URL과 target URL 구성
    base = httpserver.url_for("/vuln")            # e.g. "http://localhost:50432/vuln"
    target = f"{base}?input=INJECT_HERE"

    # 4) ScanOptions 객체 생성
    opts = ScanOptions(plugin_names=["xss"], timeout=5, concurrency=1)

    # 5) 플러그인 인스턴스 생성 및 실행
    plugin = XssPlugin()
    result = await plugin.run(target, opts)

    # 6) 결과 검증
    assert result["vulnerable"] is True
    assert any(payload in detail["response_text"] for detail in result["details"])
