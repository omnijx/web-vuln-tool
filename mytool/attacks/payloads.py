import yaml
from pathlib import Path
from typing import List

class PayloadManager:
    _data = None

    @classmethod
    def load(cls, path: str = None):
        if cls._data is None:
            file = Path(path or Path(__file__).parent / "payloads.yaml")
            cls._data = yaml.safe_load(file.read_text())
        return cls._data

    @classmethod
    def get(cls, vuln_type: str, category: str = None) -> List[str]:
        data = cls.load()
        if vuln_type not in data:
            return []
        if category:
            return data[vuln_type].get(category, [])
        # category 미지정 시 모든 카테고리 합쳐서 반환
        payloads = []
        for lst in data[vuln_type].values():
            payloads.extend(lst)
        return payloads
