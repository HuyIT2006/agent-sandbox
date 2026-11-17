"""
inspector.py
Thành viên 2: Bộ kiểm tra cú pháp tĩnh nâng cao (Advanced Static Code & Command Inspector)
Phân tích AST mã Python bằng ast.NodeVisitor và phân tích cú pháp Bash bằng bashlex AST
trước khi gửi sang Sandbox.
"""

import ast
import re
import shlex
from typing import Dict, Any, List, Set, Optional

# Thử import bashlex để phân tích AST shell
try:
    import bashlex
    import bashlex.errors
    BASHLEX_AVAILABLE = True
except ImportError:
    bashlex = None
    BASHLEX_AVAILABLE = False

# ==========================================
# CẤU HÌNH PYTHON INSPECTOR
# ==========================================

# 1. Các module hệ thống có nguy cơ phá hoại hoặc breakout (CRITICAL)
DANGEROUS_PYTHON_MODULES_CRITICAL: Set[str] = {
    "os", "subprocess", "socket", "ctypes", "pty", "shutil",
    "importlib", "signal", "multiprocessing", "threading"
}

# 2. Các module cần theo dõi rủi ro (HIGH / MEDIUM)
DANGEROUS_PYTHON_MODULES_HIGH: Set[str] = {
    "sys", "pickle", "marshal", "shelve"
}

# 3. Các hàm thực thi mã động nguy hiểm tuyệt đối (CRITICAL)
DANGEROUS_PYTHON_CALLS_CRITICAL: Set[str] = {
    "eval", "exec", "compile", "__import__"
}

# 4. Các thuộc tính nhạy cảm thường dùng trong Python Jailbreak / Sandbox Escape (CRITICAL)
DANGEROUS_PYTHON_ATTRIBUTES_CRITICAL: Set[str] = {
    "__subclasses__", "__bases__", "__base__", "__mro__",
    "__globals__", "__code__", "__closure__", "__builtins__"
}

# 5. Các đường dẫn hệ thống nhạy cảm không được phép mở bằng open()
SENSITIVE_FILESYSTEM_TARGETS = [
    "/etc", "/proc", "/sys", "/dev", "/root", "/boot",
    "c:\\windows", "c:\\boot", "c:\\system volume information",
    "/var/run", "/etc/shadow", "/etc/passwd"
]


class PythonSecurityVisitor(ast.NodeVisitor):
    """
    AST Visitor duyệt cây cú pháp Python để phát hiện hành vi nguy hiểm,
    kỹ thuật Sandbox Breakout, Reflection và Obfuscation.
    """

    def __init__(self):
        self.violations: List[str] = []
        self.risk_level: str = "LOW"

    def _elevate_risk(self, level: str, reason: str):
        self.violations.append(reason)
        ranking = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        if ranking.get(level, 0) > ranking.get(self.risk_level, 0):
            self.risk_level = level

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            root_module = alias.name.split('.')[0]
            if root_module in DANGEROUS_PYTHON_MODULES_CRITICAL:
                self._elevate_risk(
                    "CRITICAL",
                    f"Import thư viện nhạy cảm mức độ CRITICAL: '{alias.name}'"
                )
            elif root_module in DANGEROUS_PYTHON_MODULES_HIGH:
                self._elevate_risk(
                    "HIGH",
                    f"Import thư viện nhạy cảm mức độ HIGH: '{alias.name}'"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            root_module = node.module.split('.')[0]
            if root_module in DANGEROUS_PYTHON_MODULES_CRITICAL:
                self._elevate_risk(
                    "CRITICAL",
                    f"Import từ module nhạy cảm mức độ CRITICAL: '{node.module}'"
                )
            elif root_module in DANGEROUS_PYTHON_MODULES_HIGH:
                self._elevate_risk(
                    "HIGH",
                    f"Import từ module nhạy cảm mức độ HIGH: '{node.module}'"
                )
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name):
        # Bắt truy cập trực tiếp tên nhạy cảm __builtins__ hoặc builtins
        if node.id in ("__builtins__", "builtins"):
            self._elevate_risk(
                "CRITICAL",
                f"Truy cập trực tiếp vào đối tượng nhạy cảm: '{node.id}'"
            )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        # 1. Phát hiện Sandbox Escape qua reflection / MRO traversal
        if node.attr in DANGEROUS_PYTHON_ATTRIBUTES_CRITICAL:
            self._elevate_risk(
                "CRITICAL",
                f"Truy cập thuộc tính Reflection / MRO nguy hiểm: '{node.attr}'"
            )

        # 2. Phát hiện truy cập sys.modules
        if node.attr == "modules":
            if isinstance(node.value, ast.Name) and node.value.id == "sys":
                self._elevate_risk(
                    "CRITICAL",
                    "Truy cập 'sys.modules' để tìm cách gọi module bị hạn chế"
                )
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        func_name = None

        # Trường hợp gọi hàm trực tiếp: eval(), exec(), open()
        if isinstance(node.func, ast.Name):
            func_name = node.func.id

            if func_name in DANGEROUS_PYTHON_CALLS_CRITICAL:
                self._elevate_risk(
                    "CRITICAL",
                    f"Gọi hàm thực thi mã động nguy hiểm: '{func_name}()'"
                )

            elif func_name == "open":
                # Phân tích ngữ cảnh hàm open() - Không mặc định là CRITICAL
                self._check_open_call(node)

            elif func_name in ("getattr", "hasattr", "setattr"):
                # Phân tích getattr(obj, "attr") gián tiếp
                self._check_reflection_call(node, func_name)

        # Trường hợp gọi phương thức: os.system(), obj.eval()
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if attr_name in DANGEROUS_PYTHON_CALLS_CRITICAL:
                self._elevate_risk(
                    "CRITICAL",
                    f"Gọi phương thức thực thi mã động: '{attr_name}()'"
                )
            elif attr_name in ("system", "popen", "spawn", "execv", "execl"):
                self._elevate_risk(
                    "CRITICAL",
                    f"Gọi phương thức thực thi tiến trình: '{attr_name}()'"
                )

        self.generic_visit(node)

    def _check_open_call(self, node: ast.Call):
        """Phân tích ngữ cảnh open(): chỉ chặn hoặc cảnh báo cao khi đường dẫn nhạy cảm."""
        if not node.args:
            self._elevate_risk("MEDIUM", "Gọi hàm open() không có đối số rõ ràng")
            return

        first_arg = node.args[0]
        # Nếu đường dẫn là chuỗi hằng số (Constant / Str)
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            path_str = first_arg.value.lower()
            for sensitive_target in SENSITIVE_FILESYSTEM_TARGETS:
                if path_str.startswith(sensitive_target) or sensitive_target in path_str:
                    self._elevate_risk(
                        "CRITICAL",
                        f"Thao tác mở file tại đường dẫn nhạy cảm: '{first_arg.value}'"
                    )
                    return
            if ".." in path_str:
                self._elevate_risk(
                    "HIGH",
                    f"Thao tác mở file có dấu hiệu Directory Traversal ('..'): '{first_arg.value}'"
                )
                return

            # Nếu mở file tương đối hoặc file trong workspace bình thường
            self._elevate_risk(
                "MEDIUM",
                f"Thao tác mở file cục bộ: '{first_arg.value}' (cần kiểm soát phạm vi)"
            )
        else:
            # Đường dẫn là biến động
            self._elevate_risk(
                "MEDIUM",
                "Thao tác mở file với đường dẫn động (cần kiểm soát trong workspace)"
            )

    def _check_reflection_call(self, node: ast.Call, func_name: str):
        """Phân tích getattr(obj, 'danger') hoặc setattr."""
        if len(node.args) >= 2:
            attr_arg = node.args[1]
            if isinstance(attr_arg, ast.Constant) and isinstance(attr_arg.value, str):
                target_attr = attr_arg.value
                if target_attr in DANGEROUS_PYTHON_CALLS_CRITICAL or target_attr in DANGEROUS_PYTHON_ATTRIBUTES_CRITICAL:
                    self._elevate_risk(
                        "CRITICAL",
                        f"Sử dụng {func_name}() để truy cập gián tiếp thuộc tính/hàm nguy hiểm: '{target_attr}'"
                    )
                elif target_attr in ("system", "popen", "spawn", "execve"):
                    self._elevate_risk(
                        "CRITICAL",
                        f"Sử dụng {func_name}() để gọi gián tiếp lệnh hệ thống: '{target_attr}'"
                    )


# ==========================================
# CẤU HÌNH BASH INSPECTOR
# ==========================================

# Pattern Regex bổ trợ cho các biến thể Obfuscation & Fork Bomb nguy hiểm
DANGEROUS_SHELL_PATTERNS = [
    (r":\(\)\s*\{\s*:\|\:&\s*\}\s*;\s*:", "Fork Bomb detected (:(){ :|:& };:)"),
    (r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f[a-zA-Z]*\s+(/|/\*|~|\$HOME)", "Lệnh phá hoại hệ thống file gốc (rm -rf)"),
    (r"mkfs|dd\s+if=.*of=/dev", "Thao tác ghi đè thiết bị ổ đĩa (/dev)"),
    (r"(nc|netcat|ncat)\s+.*(-e|/bin/sh|/bin/bash)", "Reverse Shell payload qua netcat"),
    (r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", "Reverse Shell payload qua /dev/tcp/"),
    (r"(curl|wget)\s+.*\|\s*(bash|sh)", "Tải và thực thi script trực tiếp từ Internet qua pipe"),
    (r"(base64\s+-d|xxd\s+-r)\s*\|\s*(bash|sh)", "Thực thi payload giải mã obfuscated qua pipe"),
]

SENSITIVE_BASH_TARGETS = {
    "/", "/*", "~", "$HOME", "/etc", "/etc/*", "/usr", "/bin", "/boot",
    "/dev", "/sys", "/proc", "/var", "/root"
}


class CodeInspector:
    """Bộ kiểm tra cú pháp và an toàn mã nguồn cho cả Python và Bash."""

    @staticmethod
    def inspect_python(code: str) -> Dict[str, Any]:
        """
        Phân tích mã Python bằng cây cú pháp trừu tượng (AST) với NodeVisitor.
        Trả về kết quả kiểm tra theo schema chuẩn: is_safe, risk_level, violations, code.
        """
        try:
            tree = ast.parse(code)
            visitor = PythonSecurityVisitor()
            visitor.visit(tree)

            violations = visitor.violations
            risk_level = visitor.risk_level

            # An toàn khi không có vi phạm CRITICAL hoặc HIGH
            is_safe = (risk_level in ("LOW", "MEDIUM"))

            return {
                "type": "python",
                "is_safe": is_safe,
                "risk_level": risk_level,
                "violations": violations,
                "code": code,
            }

        except SyntaxError as e:
            # Nguyên tắc Fail-Closed: Lỗi cú pháp phải được đánh dấu rủi ro
            return {
                "type": "python",
                "is_safe": False,
                "risk_level": "HIGH",
                "violations": [f"Lỗi cú pháp Python (SyntaxError): {str(e)}"],
                "code": code,
            }
        except Exception as e:
            # Bắt mọi ngoại lệ bất thường trong quá trình phân tích
            return {
                "type": "python",
                "is_safe": False,
                "risk_level": "HIGH",
                "violations": [f"Lỗi phân tích cú pháp AST: {str(e)}"],
                "code": code,
            }

    @classmethod
    def inspect_bash(cls, command: str) -> Dict[str, Any]:
        """
        Phân tích lệnh Bash kết hợp AST của bashlex và pattern matching.
        Áp dụng nguyên tắc Fail-Closed khi phân tích cú pháp gặp lỗi.
        """
        violations: List[str] = []
        highest_risk = "LOW"

        def elevate(level: str, reason: str):
            nonlocal highest_risk
            violations.append(reason)
            ranking = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
            if ranking.get(level, 0) > ranking.get(highest_risk, 0):
                highest_risk = level

        # 1. Lớp phòng thủ 1: Regex bổ trợ bắt nhanh các mẫu nguy hiểm đặc trưng (Fork bomb, raw /dev/tcp)
        for pattern, reason in DANGEROUS_SHELL_PATTERNS:
            if re.search(pattern, command, re.IGNORECASE):
                elevate("CRITICAL", reason)

        # 2. Lớp phòng thủ 2: Phân tích AST bằng bashlex nếu khả dụng
        if BASHLEX_AVAILABLE:
            try:
                parts = bashlex.parse(command)
                for ast_node in parts:
                    cls._visit_bashlex_node(ast_node, elevate)

            except bashlex.errors.ParsingError as pe:
                # Fail-Closed: Lỗi cú pháp Bash không được mặc định an toàn
                elevate(
                    "HIGH",
                    f"Lỗi phân tích cú pháp Bash (bashlex.ParsingError): {str(pe)}"
                )
            except Exception as e:
                elevate(
                    "HIGH",
                    f"Lỗi ngoại lệ khi duyệt AST Bash: {str(e)}"
                )
        else:
            # Thông báo cảnh báo khi thiếu thư viện bashlex
            elevate(
                "MEDIUM",
                "Thư viện 'bashlex' chưa sẵn sàng, hệ thống sử dụng quy tắc Regex dự phòng"
            )

        # Đánh giá độ dài lệnh cho các lệnh bình thường
        if highest_risk == "LOW" and len(command) > 200:
            highest_risk = "MEDIUM"

        is_safe = (highest_risk in ("LOW", "MEDIUM")) and (len(violations) == 0 or highest_risk == "MEDIUM")
        # Đảm bảo nếu có bất kỳ vi phạm CRITICAL nào, is_safe phải False
        if highest_risk in ("CRITICAL", "HIGH"):
            is_safe = False

        return {
            "type": "bash",
            "is_safe": is_safe,
            "risk_level": highest_risk,
            "violations": violations,
            "command": command,
        }

    @classmethod
    def _visit_bashlex_node(cls, node: Any, elevate_fn):
        """Duyệt đệ quy từng node trong cây AST của bashlex."""
        if not node:
            return

        node_kind = getattr(node, "kind", None)

        # 1. Node command
        if node_kind == "command":
            cls._inspect_command_node(node, elevate_fn)

        # 2. Node pipeline
        elif node_kind == "pipeline":
            cls._inspect_pipeline_node(node, elevate_fn)

        # 3. Node redirect
        elif node_kind == "redirect":
            cls._inspect_redirect_node(node, elevate_fn)

        # 4. Node command substitution ($(cmd) hoặc `cmd`)
        elif node_kind == "commandsubstitution":
            # Đệ quy phân tích lệnh bên trong thay vì tự động chặn tất cả
            sub_command = getattr(node, "command", None)
            if sub_command:
                cls._visit_bashlex_node(sub_command, elevate_fn)

        # Duyệt qua các thành phần con (parts) nếu có
        parts = getattr(node, "parts", [])
        for child in parts:
            cls._visit_bashlex_node(child, elevate_fn)

    @classmethod
    def _inspect_command_node(cls, node: Any, elevate_fn):
        """Phân tích chi tiết một node command đơn lẻ."""
        parts = getattr(node, "parts", [])
        words = [p.word for p in parts if getattr(p, "kind", None) == "word" and hasattr(p, "word")]

        if not words:
            return

        cmd_name = words[0].strip()

        # Kiểm tra rm với các cờ xóa đệ quy/cưỡng chế
        if cmd_name == "rm":
            has_recursive = any(w.startswith("-") and any(c in w for c in "rR") for w in words[1:])
            has_force = any(w.startswith("-") and any(c in w for c in "fF") for w in words[1:])
            targets = [w for w in words[1:] if not w.startswith("-")]

            for target in targets:
                clean_target = target.rstrip("/")
                is_sensitive_target = (
                    clean_target in SENSITIVE_BASH_TARGETS
                    or target == "/"
                    or target.startswith("/etc")
                    or target.startswith("/usr")
                    or target.startswith("/bin")
                    or target.startswith("/boot")
                    or target.startswith("/dev")
                )
                if is_sensitive_target:
                    if has_recursive:
                        elevate_fn(
                            "CRITICAL",
                            f"Lệnh phá hủy hệ thống: 'rm' với tùy chọn đệ quy trên mục tiêu nhạy cảm '{target}'"
                        )
                    else:
                        elevate_fn(
                            "HIGH",
                            f"Lệnh 'rm' trên đường dẫn hệ thống nhạy cảm: '{target}'"
                        )


        # Kiểm tra các lệnh ghi đè đĩa
        elif cmd_name in ("mkfs", "fdisk", "parted"):
            elevate_fn("CRITICAL", f"Lệnh định dạng/thao tác phân vùng đĩa nhạy cảm: '{cmd_name}'")

        elif cmd_name == "dd":
            for w in words[1:]:
                if w.startswith("of=/dev/"):
                    elevate_fn("CRITICAL", f"Lệnh dd ghi đè trực tiếp lên thiết bị khối: '{w}'")

        # Kiểm tra các lệnh điều khiển hệ thống
        elif cmd_name in ("shutdown", "reboot", "poweroff", "init"):
            elevate_fn("CRITICAL", f"Lệnh tắt/khởi động lại hệ điều hành: '{cmd_name}'")

        # Kiểm tra netcat / reverse shell
        elif cmd_name in ("nc", "netcat", "ncat"):
            if any("-e" in w for w in words[1:]) or any("/bin/" in w for w in words[1:]):
                elevate_fn("CRITICAL", f"Lệnh mạng có tham số thực thi shell (Reverse Shell): '{' '.join(words)}'")

    @classmethod
    def _inspect_pipeline_node(cls, node: Any, elevate_fn):
        """Phân tích các lệnh liên kết qua pipeline (|)."""
        parts = getattr(node, "parts", [])
        pipeline_cmds = []

        for p in parts:
            if getattr(p, "kind", None) == "command":
                cmd_words = [w.word for w in getattr(p, "parts", []) if getattr(w, "kind", None) == "word"]
                if cmd_words:
                    pipeline_cmds.append(cmd_words[0])

        # Phát hiện pattern: curl/wget ... | sh/bash
        network_downloaders = {"curl", "wget", "fetch"}
        shells = {"sh", "bash", "zsh", "dash", "python", "python3"}

        has_downloader = any(c in network_downloaders for c in pipeline_cmds)
        has_shell = any(c in shells for c in pipeline_cmds)

        if has_downloader and has_shell:
            elevate_fn(
                "CRITICAL",
                f"Phát hiện chuỗi pipeline tải từ mạng và thực thi trực tiếp: {' | '.join(pipeline_cmds)}"
            )

        # Phát hiện pattern: base64 -d | sh
        if "base64" in pipeline_cmds and has_shell:
            elevate_fn(
                "CRITICAL",
                "Phát hiện chuỗi pipeline giải mã base64 và thực thi trực tiếp qua shell"
            )

    @classmethod
    def _inspect_redirect_node(cls, node: Any, elevate_fn):
        """Phân tích chuyển hướng đầu ra (redirection)."""
        output_target = getattr(node, "output", None)
        output_str = ""
        if isinstance(output_target, str):
            output_str = output_target
        elif hasattr(output_target, "word"):
            output_str = getattr(output_target, "word", "")

        if output_str:
            clean_out = output_str.strip()
            for sensitive in SENSITIVE_BASH_TARGETS:
                if clean_out.startswith(sensitive) or clean_out == sensitive:
                    elevate_fn(
                        "CRITICAL",
                        f"Chuyển hướng đầu ra ghi đè vào file hệ thống nhạy cảm: '{clean_out}'"
                    )
                    break



if __name__ == "__main__":
    test_cmd = "rm -rf /"
    print("Bash Test:", CodeInspector.inspect_bash(test_cmd))

    test_py = "import os\nos.system('ls')"
    print("Python Test:", CodeInspector.inspect_python(test_py))
