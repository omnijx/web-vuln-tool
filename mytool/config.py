# mytool/config.py
from typing import List, Dict, Optional
from pydantic_settings import BaseSettings

class ScanOptions(BaseSettings):
    """
    스캔 옵션: 어떤 플러그인을 쓸지, 타임아웃이나 동시성 수 등 설정
    환경변수(.env)나 --config YAML/JSON 파일도 지원하도록 확장 가능
    """
    plugin_names: List[str]
    timeout: int = 10
    concurrency: int = 5
    headers: Optional[Dict[str, str]] = None

    class Config:
        # .env 파일이 있으면 읽어서 환경변수로 사용할 수 있어요
        env_file = ".env"
