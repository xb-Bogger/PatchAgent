import random
import subprocess as sp
from pathlib import Path
from typing import Dict, List

import tree_sitter_java
from tree_sitter import Language, Parser

from patchagent.logger import logger
from patchagent.lsp.language import LanguageServer

# 为 Java 代码提供“快速符号定位”能力：用文本搜索做粗筛，用 tree-sitter 做结构校验并提取完整声明源码；供上层修复/导航使用

# 用 tree-sitter 解析单个 Java 文件，基于 AST 提取给定符号在指定行范围内的完整声明源码
class TreeSitterJavaParser:
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.parser_language = Language(tree_sitter_java.language())
        self.parser = Parser(self.parser_language)

        self.source_code = file_path.read_bytes()
        self.tree = self.parser.parse(self.source_code)

    def get_symbol_source(self, symbol_name: str, line: int) -> str:
        """
         Retrieve the full source code of a symbol based on its start position.
        :param symbol_name: The name of the function to find.
        :param line: The line number of the function's start position (0-based).
        :return: The full source code of the function.
        """
        # Define a query to find "declaration" nodes
        method_declaration_query = self.parser_language.query("""(method_declaration) @func_decl""")
        field_declaration_query = self.parser_language.query("""(field_declaration) @func_decl""")
        constructor_declaration_query = self.parser_language.query("""(constructor_declaration) @func_decl""")

        # TODO do we need class_declaration and interface_declaration

        # type s
        query_list = [method_declaration_query, constructor_declaration_query, field_declaration_query]

        for query in query_list:

            # Execute the query
            captures = query.captures(self.tree.root_node)

            if not captures:
                continue

            # Print the nodes
            for node in captures["func_decl"]:
                if not node.text:
                    continue

                # find the identifier node since it is the method name
                identifier_node = None
                for child_node in node.children:
                    if child_node.type != "identifier":
                        continue
                    if not child_node.text:
                        continue
                    identifier_node = child_node
                    break

                if not identifier_node or not identifier_node.text:
                    continue

                # make sure the identifier node is the symbol we are looking for
                # java may function call
                if identifier_node.text.decode("utf-8", errors="ignore") == symbol_name and node.start_point.row <= line and line <= node.end_point.row:
                    source_code = node.text.decode("utf-8", errors="ignore")
                    return source_code

        return ""

# 提供 locate_symbol(symbol) 能力
class JavaLanguageServer(LanguageServer):
    def __init__(self, source_path: Path):
        super().__init__(source_path)
    # 先用 grep 在工程下定位包含 symbol 的行与文件
    def _locate_symbol(self, symbol: str) -> List[Dict]:
        cmd = f"grep --binary-files=without-match -rnw {self.source_path} -e  {symbol}"

        results = sp.run(cmd, shell=True, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        output = results.stdout.strip()

        if not output:
            return []

        # sometimes the location may be in the comments or in the string literals
        # find the file path, line number and character position
        all_lines = output.splitlines()
        # 过滤出 .java 文件，得到候选 (file, line)
        # filter some files by file type
        filtered_lines = []
        for line in all_lines:

            parts = line.split(":", 2)
            # check if the line is valid
            if len(parts) < 3:
                continue

            _file_path, _lineno, content = parts
            # filter the other files (.md, .txt, etc)
            file_type = _file_path.split(".")[-1]

            filter_header = ["java"]

            if file_type not in filter_header:
                continue

            # find character position
            char_pos = content.find(symbol)
            # the line number is 1-based, we need to convert it to 0-based
            filtered_lines.append((Path(_file_path), int(_lineno) - 1, char_pos))

        # print("num of total file: ", len(filtered_lines))
        # shuffle the list to get random files
        random.shuffle(filtered_lines)

        final_resp = []
        all_source_code = []
        # 对每个候选用 TreeSitterJavaParser 解析，若该行落在某个方法/构造器/字段声明节点范围内且标识符匹配，则返回该声明源码与相对路径位置
        for file_path, lineno, char_pos in filtered_lines:
            # Define server arguments
            try:
                parser = TreeSitterJavaParser(file_path)
                source_code = parser.get_symbol_source(symbol, lineno)

                if source_code and source_code not in all_source_code:

                    # change to 1-based soince ctags is 1-based
                    final_resp.append({"source_code": source_code, "file_path": file_path.relative_to(self.source_path), "line": lineno + 1})
                    all_source_code.append(source_code)
            except Exception as e:
                logger.error(f"[❌] Error while parsing the file {file_path}: {e}")
                return final_resp

        return final_resp

    def locate_symbol(self, symbol: str) -> List[str]:
        parts = symbol.split(".")
        function_name = symbol.split(".")[-1]

        fast_path_locations = self._locate_symbol(function_name)
        # 若候选多且符号形如 a.b.Class.method，优先返回文件名与 Class 匹配的那个；否则返回全部 file:line:0 列表
        if len(fast_path_locations) > 1:
            if len(parts) > 1:
                file_name = parts[-2]
                for location in fast_path_locations:
                    if location["file_path"].name == f"{file_name}.java":
                        return [f"{location['file_path']}:{location['line']}:0"]

        refactored_locations = []
        for res_json in fast_path_locations:
            refactored_locations.append(f"{res_json['file_path']}:{res_json['line']}:0")

        return refactored_locations
