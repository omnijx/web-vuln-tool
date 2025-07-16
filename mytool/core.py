# mytool/core.py

import asyncio
from typing import List
from mytool.config import ScanOptions
from mytool.report import ScanReport
from mytool.plugins.base import Plugin
import importlib

def load_plugins(names: List[str]) -> List[Plugin]:
    """
    plugin_names 리스트에 적힌 이름으로
    mytool.plugins.<name> 모듈을 동적으로 import 해서
    해당 모듈 안의 plugin 클래스를 반환합니다.
    """
    plugins: List[Plugin] = []
    for name in names:
        module = importlib.import_module(f"mytool.plugins.{name}")
        # 모듈 안에 name을 대문자로 바꾼 클래스가 있다고 가정 (예: XssPlugin)
        cls = getattr(module, f"{name.capitalize()}Plugin")
        plugins.append(cls())
    return plugins

async def scan(target: str, options: ScanOptions) -> ScanReport:
    """
    1) options.plugin_names 로 플러그인 로딩
    2) 각 플러그인 .run() 호출해서 결과 수집(비동기 병렬)
    3) ScanReport 에 담아서 반환
    """
    report = ScanReport(target=target)

    # 1) 플러그인 로딩
    plugins: List[Plugin] = load_plugins(options.plugin_names)

    # 2) 비동기로 모두 실행
    tasks = [plugin.run(target, options) for plugin in plugins]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # 3) 결과를 report 에 추가
    for plugin, result in zip(plugins, results):
        # 에러가 발생하면 result에 Exception 오브젝트가 담김
        if isinstance(result, Exception):
            report.add(plugin.name, {"error": str(result)})
        else:
            report.add(plugin.name, result)

    return report
