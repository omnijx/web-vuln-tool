# tests/test_xss_stored.py

import pytest
from types import SimpleNamespace
from mytool.plugins.xss import XssPlugin

@pytest.fixture
def plugin():
    # 간단한 options 객체
    opts = SimpleNamespace(
        target="http://localhost:8000",
        headers={},
        timeout=5
    )
    return XssPlugin(opts)

def test_xss_stored(monkeypatch, plugin):
    """
    1) POST로 페이로드 전송 → mock 응답
    2) GET으로 페이지 로드 → mock HTML에 payload 포함 확인
    """
    payload = "<script>alert('stored')</script>"

    # --- Step 1: requests.post 모킹 ---
    class DummyPostResponse:
        def __init__(self):
            self.status_code = 200
            self.text = ""  # 실제 값은 필요 없습니다
        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception("HTTP Error")

    def fake_post(url, data, timeout):
        # URL, 필드명이 맞는지 검증(Optional)
        assert url.endswith("/submit")
        assert data.get("input_field") == payload
        assert timeout == plugin.options.timeout
        return DummyPostResponse()

    monkeypatch.setattr("requests.post", fake_post)

    # --- Step 2: requests.get 모킹 ---
    class DummyGetResponse:
        def __init__(self, text):
            self.status_code = 200
            self.text = text
        def raise_for_status(self):
            if self.status_code >= 400:
                raise Exception("HTTP Error")

    def fake_get(url, timeout):
        # URL이 /view로 끝나는지 확인(Optional)
        assert url.endswith("/view")
        assert timeout == plugin.options.timeout
        # 이 HTML에 payload가 포함돼 있다고 가정
        html = f"<html><body>{payload}</body></html>"
        return DummyGetResponse(html)

    monkeypatch.setattr("requests.get", fake_get)

    # 실제 호출: 네트워크가 아닌 fake_post/fake_get이 실행됩니다.
    resp = plugin.attack_stored(payload)
    assert resp.status_code == 200

    page_html = plugin.fetch_page()
    assert payload in page_html
