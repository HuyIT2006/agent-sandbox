"""
inspector.py
Thành viên 2: Bộ kiểm tra cú pháp tĩnh (Static Code & Command Inspector)
Phân tích AST mã Python và kiểm tra lệnh Bash trước khi cho phép gửi sang Sandbox.
"""

import ast
import re
from typing import Dict, Any, List

DANGEROUS_PYTHON_MODULES = {
    "os", "subprocess", "socket", "ctypes", "pty", "shutil",
    "importlib", "signal", "multiprocessing", "threading"
}

DANGEROUS_PYTHON_CALLS = {
    "eval", "exec", "compile", "__import__", "open"
}

DANGEROUS_SHELL_PATTERNS = [
    (r":\(\)\s*\{\s*:\|\:&\s*\}\s*;\s*:", "Fork Bomb detected"),
    (r"rm\s+-rf\s+(/|/\*|~|\$HOME)", "Phá hoại hệ thống file gốc"),
    (r"mkfs|dd\s+if=.*of=/dev", "Thao tác ghi đè ổ đĩa"),
    (r"(nc|netcat|bash\s+-i|/dev/tcp/)\s*", "Reverse Shell payload"),
    (r"(curl|wget)\s+.*\|\s*(bash|sh)", "Tải và thực thi script trực tiếp từ Internet"),
    (r"(base64\s+-d|xxd\s+-r)\s*\|\s*(bash|sh)", "Thực thi payload giải mã obfuscated"),
]


class CodeInspector:
    @staticmethod
    def inspect_bash(command: str) -> Dict[str, Any]:
        """Phân tích lệnh Bash bằng regex & pattern matching."""
        violations = []

        for pattern, reason in DANGEROUS_SHELL_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                violations.append(reason)

        is_safe = len(violations) == 0
        risk_level = "CRITICAL" if violations else ("LOW" if len(command) < 100 else "MEDIUM")

        return {
            "type": "bash",
            "is_safe": is_safe,
            "risk_level": risk_level,
            "violations": violations,
            "command": command,
        }

    @staticmethod
    def inspect_python(code: str) -> Dict[str, Any]:
        """Phân tích mã Python bằng cây cú pháp trừu tượng (AST)."""
        violations = []
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                # 1. Bắt câu lệnh import: import os, subprocess
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name.split('.')[0] in DANGEROUS_PYTHON_MODULES:
                            violations.append(f"Import thư viện nhạy cảm: '{alias.name}'")

                # 2. Bắt from module import: from os import system
                elif isinstance(node, ast.ImportFrom):
                    if node.module and node.module.split('.')[0] in DANGEROUS_PYTHON_MODULES:
                        violations.append(f"Import từ module nhạy cảm: '{node.module}'")

                # 3. Bắt hàm eval(), exec(), __import__()
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in DANGEROUS_PYTHON_CALLS:
                        violations.append(f"Gọi hàm nguy hiểm: '{node.func.id}()'")

            is_safe = len(violations) == 0
            risk_level = "CRITICAL" if violations else "LOW"

        except SyntaxError as e:
            return {
                "type": "python",
                "is_safe": False,
                "risk_level": "HIGH",
                "violations": [f"Lỗi cú pháp Python (SyntaxError): {str(e)}"],
                "code": code,
            }

        return {
            "type": "python",
            "is_safe": is_safe,
            "risk_level": risk_level,
            "violations": violations,
            "code": code,
        }


if __name__ == "__main__":
    test_cmd = "rm -rf /"
    print("Bash Test:", CodeInspector.inspect_bash(test_cmd))

    test_py = "import os\nos.system('ls')"
    print("Python Test:", CodeInspector.inspect_python(test_py))
