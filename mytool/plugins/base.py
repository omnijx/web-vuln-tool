# mytool/plugins/base.py

from abc import ABC, abstractmethod
from typing import Any
from mytool.config import ScanOptions

class Plugin(ABC):
    """
    모든 공격 모듈은 이 인터페이스를 상속받아야 합니다.
    """

    name: str  # 플러그인 식별자, 예: "xss", "sqli", "traversal"

    @abstractmethod
    async def run(self, target: str, options: ScanOptions) -> Any:
        """
        실제 스캔 로직을 비동기로 구현하는 메서드.
        - target: 검사할 URL
        - options: ScanOptions 객체
        - 반환값: 결과 객체(딕셔너리, 또는 커스텀 타입)
        """
        pass
