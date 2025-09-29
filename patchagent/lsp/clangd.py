import atexit
import json
import subprocess
from pathlib import Path
from typing import IO, Any, Callable, Dict, List, TypeVar

from patchagent.logger import logger
from patchagent.lsp.language import LanguageServer
# 实现一个面向 clangd 的轻量级 LSP 客户端（ClangdServer），用于在本项目中为 C/C++ 源码提供语义能力
# 通过 stdin/stdout 按 LSP/JSON-RPC 协议通讯：add_header 构包，notify 发送通知，call 发送请求并用 recv 阻塞读取响应
T = TypeVar("T")

# ClangdServer 继承 LanguageServer，封装对 clangd 的 LSP 通信
class ClangdServer(LanguageServer):
    """
    Language Server Protocol Specification:
        https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/
    """

    def __init__(self, source_path: Path):
        super().__init__(source_path)

        self.start()
    # 为消息加 Content-Length 头
    def add_header(self, message: str) -> bytes:
        return f"Content-Length: {len(message.encode())}\r\n\r\n{message}".encode()
    # 发送无返回的通知（method+params）
    def notify(self, method: str, params: Dict) -> None:
        message = json.dumps(
            {
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
            }
        )
        packet = self.add_header(message)
        self.stdin.write(packet)
        self.stdin.flush()
    # 发送请求（带 id），随后通过 recv 阻塞读取匹配 id 的响应
    def call(self, method: str, params: Dict) -> Dict:
        self.current_id += 1
        message = json.dumps(
            {
                "jsonrpc": "2.0",
                "id": self.current_id,
                "method": method,
                "params": params,
            }
        )
        packet = self.add_header(message)

        self.stdin.write(packet)
        self.stdin.flush()

        return self.recv()
    # 循环读取 Content-Length 头与指定长度的 JSON，返回解析后的 dict
    def recv(self) -> Dict:
        while True:
            header = b"Content-Length: "

            read_header = b""
            while len(read_header) < len(header):
                read_header += self.stdout.read(len(header) - len(read_header))

            assert read_header == header, f"Expected header {header!r}, got {read_header!r}"

            content = b""
            while not content.endswith(b"\r\n\r\n"):
                content += self.stdout.read(1)

            num_bytes = int(content.strip())
            raw = b""
            while len(raw) < num_bytes:
                raw += self.stdout.read(num_bytes - len(raw))

            data = json.loads(raw)
            if data.get("id") == self.current_id:
                return data

    def initialize(self) -> None:
        self.call(
            "initialize",
            {
                "processId": None,
                "rootPath": None,
                "rootUri": f"file://{self.source_path}",
                "capabilities": {},
                "trace": "off",
                "workspaceFolders": None,
            },
        )
        self.notify("initialized", {})

    def start(self) -> None:
        compile_command_json = self.source_path / "compile_commands.json"
        assert compile_command_json.is_file(), "compile_commands.json not found"

        self.current_id: int = 0
        self.process: subprocess.Popen[bytes] = subprocess.Popen(
            [
                "/usr/bin/clangd",
                "--clang-tidy",
                "--log=error",
                f"--compile-commands-dir={self.source_path}",
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            bufsize=0,
        )

        assert self.process.stdin is not None
        assert self.process.stdout is not None
        assert self.process.stderr is None

        self.stdin: IO[bytes] = self.process.stdin
        self.stdout: IO[bytes] = self.process.stdout
        # 通过 initialize/initialized 完成 LSP 初始化，进程在 atexit 上注册 stop
        self.initialize()
        atexit.register(self.stop)

    def stop(self) -> None:
        try:
            self.notify("shutdown", {})
            self.notify("exit", {})
        except BrokenPipeError:
            logger.warning("[⚠️] BrokenPipeError encountered, terminating the process directly...")

        self.process.terminate()
    # 捕获 BrokenPipeError，重启 clangd 一次并重试操作，提升健壮性
    def _retry_on_broken_pipe(self, func: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        """
        Retry mechanism for handling BrokenPipeError.
        Restarts the clangd server once and retries the operation.
        """
        try:
            return func(*args, **kwargs)
        except BrokenPipeError:
            logger.warning("[⚠️] BrokenPipeError encountered, restarting clangd server and retrying...")
            self.stop()
            self.start()
            return func(*args, **kwargs)

    def find_definition_internal(self, path: Path, line: int, chr: int) -> List[str]:
        content = path.read_text(errors="ignore")
        # 先 didOpen 带入文件内容（languageId=c）
        self.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": f"file://{path}",
                    "languageId": "c",
                    "version": 1,
                    "text": content,
                }
            },
        )

        # textDocument/definition 请求，过滤返回的 uri，限定在 source_path 项目内
        packet = self.call(
            "textDocument/definition",
            {
                "textDocument": {
                    "uri": f"file://{path}",
                },
                "position": {
                    "line": line,
                    "character": chr,
                },
            },
        )

        results = packet["result"]
        if results is None:
            return []
        # 结果转为相对路径:line:col（转回 1-based）
        locations = []
        for result in results:
            prefix, filepath = f"file://{self.source_path}/", result["uri"]
            if isinstance(filepath, str) and not filepath.startswith(prefix):
                continue

            filepath = filepath[len(prefix) :]
            linum = result["range"]["start"]["line"] + 1
            colnum = result["range"]["start"]["character"] + 1
            locations.append(f"{filepath}:{linum}:{colnum}")

        return locations
    # 同样 didOpen，随后调用 textDocument/hover，返回 contents.value 文本
    def hover_internal(self, path: Path, line: int, chr: int) -> str:
        content = path.read_text(errors="ignore")

        self.notify(
            "textDocument/didOpen",
            {
                "textDocument": {
                    "uri": f"file://{path}",
                    "languageId": "c",
                    "version": 1,
                    "text": content,
                }
            },
        )
        packet = self.call(
            "textDocument/hover",
            {
                "textDocument": {"uri": f"file://{path}"},
                "position": {
                    "line": line,
                    "character": chr,
                },
            },
        )

        results = packet["result"]
        return results["contents"]["value"] if results else ""
    # 两者都通过 _retry_on_broken_pipe 包装，避免 BrokenPipe 导致一次性失败
    def find_definition(self, path: Path, line: int, column: int) -> List[str]:
        assert not path.is_absolute()
        filepath, linum, colnum = self.source_path / path, line - 1, column - 1
        logger.info(f"[🚧] find_definition for {filepath}:{linum}:{colnum}")

        return self._retry_on_broken_pipe(self.find_definition_internal, filepath, linum, colnum)

    def hover(self, path: Path, line: int, column: int) -> str:
        assert not path.is_absolute()
        filepath, linum, colnum = self.source_path / path, line - 1, column - 1
        logger.info(f"[🚧] hover for {filepath}:{linum}:{colnum}")

        return self._retry_on_broken_pipe(self.hover_internal, filepath, linum, colnum)
