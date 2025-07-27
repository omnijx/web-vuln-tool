# mytool/report.py

from typing import Any, Dict, List

class ScanReport:
    """
    스캔 결과를 담는 리포트 객체의 최소 스펙을 정의한 스텁 클래스입니다.
    이후 .to_json(), .to_html(), .to_markdown() 메서드를 구현하세요.
    """

    def __init__(self, target: str, results: List[Dict[str, Any]]):
        self.target = target
        self.results = results

    def to_json(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "results": self.results,
        }

    def to_html(self) -> str:
        # 간단한 HTML 테이블 형태 예시
        rows = ""
        for item in self.results:
            rows += f"<tr><td>{item['category']}</td><td>{item['payload']}</td><td>{item['success']}</td></tr>"
        return f"""
        <html>
          <head><title>Scan Report for {self.target}</title></head>
          <body>
            <h1>Scan Report: {self.target}</h1>
            <table border="1">
              <tr><th>Category</th><th>Payload</th><th>Success</th></tr>
              {rows}
            </table>
          </body>
        </html>
        """

    def to_markdown(self) -> str:
        md = f"# Scan Report for {self.target}\n\n"
        md += "| Category | Payload | Success |\n"
        md += "|----------|---------|---------|\n"
        for item in self.results:
            md += f"| {item['category']} | `{item['payload']}` | {item['success']} |\n"
        return md
