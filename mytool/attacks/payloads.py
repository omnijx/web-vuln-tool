# mytool/attacks/payloads.py

import yaml
import urllib.parse
import base64
from pathlib import Path

# 현재 파일 기준으로 attacks/payloads.yaml 경로 계산
PAYLOAD_FILE = Path(__file__).parent / "payloads.yaml"

def generate_variants(payload: str) -> list[str]:
    variants = [payload]

    # 1) URL 인코딩
    variants.append(urllib.parse.quote(payload, safe=''))

    # 2) Unicode 이스케이프 (\uXXXX 형태)
    uni = ''.join(f'\\u{ord(c):04x}' for c in payload)
    variants.append(uni)

    # 3) Base64 + javascript:eval atob() 래핑
    b64 = base64.b64encode(payload.encode()).decode()
    variants.append(f"javascript:eval(atob('{b64}'))")

    return list(dict.fromkeys(variants))


class PayloadManager:
    @staticmethod
    def load() -> dict:
        """
        YAML에서 원본 페이로드를 불러온 뒤,
        각 카테고리별로 generate_variants()를 적용해 확장해서 리턴.
        """
        with open(PAYLOAD_FILE, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        xss = data.get("xss", {})
        expanded = {}
        for category, lst in xss.items():
            all_vars = []
            for p in lst:
                all_vars.extend(generate_variants(p))
            expanded[category] = list(dict.fromkeys(all_vars))

        data["xss"] = expanded
        return data
