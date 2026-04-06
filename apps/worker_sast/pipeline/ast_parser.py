from __future__ import annotations

from typing import Any

import structlog

from packages.domain.enums import SupportedLanguage
from packages.domain.exceptions import UnsupportedLanguageError

log = structlog.get_logger(__name__)


class ASTParser:
    def __init__(self) -> None:
        self._parsers: dict[SupportedLanguage, Any] = {}
        self._load_parsers()

    def _load_parsers(self) -> None:
        try:
            import tree_sitter_javascript
            import tree_sitter_python
            from tree_sitter import Language, Parser

            self._parsers[SupportedLanguage.PYTHON] = Parser(
                Language(tree_sitter_python.language())
            )
            self._parsers[SupportedLanguage.JAVASCRIPT] = Parser(
                Language(tree_sitter_javascript.language())
            )
            log.info("ast_parser.loaded")
        except ImportError as e:
            log.error("ast_parser.load_failed", error=str(e))
            raise

    def parse(self, code: str, language: SupportedLanguage | None) -> dict:
        if language not in self._parsers:
            raise UnsupportedLanguageError(f"Linguagem não suportada: {language}")
        parser = self._parsers[language]
        tree = parser.parse(code.encode("utf-8"))
        return {
            "language": language.value if language else "unknown",
            "functions": self._extract_functions(tree.root_node, code),
            "imports": self._extract_imports(tree.root_node, code),
            "assignments": self._extract_assignments(tree.root_node, code),
            "calls": self._extract_calls(tree.root_node, code),
        }

    def _extract_functions(self, node, code: str) -> list[dict]:
        functions = []
        for child in node.children:
            if child.type in ("function_definition", "function_declaration"):
                name_node = child.child_by_field_name("name")
                functions.append(
                    {
                        "name": self._get_text(name_node, code),
                        "start_line": child.start_point[0] + 1,
                        "end_line": child.end_point[0] + 1,
                        "params": self._extract_params(child, code),
                    }
                )
            functions.extend(self._extract_functions(child, code))
        return functions

    def _extract_imports(self, node, code: str) -> list[dict]:
        imports = []
        for child in node.children:
            if child.type in ("import_statement", "import_from_statement"):
                imports.append(
                    {"raw": self._get_text(child, code)[:100], "line": child.start_point[0] + 1}
                )
            imports.extend(self._extract_imports(child, code))
        return imports

    def _extract_assignments(self, node, code: str) -> list[dict]:
        assignments = []
        for child in node.children:
            if child.type == "assignment":
                left = child.child_by_field_name("left")
                right = child.child_by_field_name("right")
                assignments.append(
                    {
                        "target": self._get_text(left, code)[:50],
                        "value_type": right.type if right else "unknown",
                        "line": child.start_point[0] + 1,
                    }
                )
            assignments.extend(self._extract_assignments(child, code))
        return assignments

    def _extract_calls(self, node, code: str) -> list[dict]:
        calls = []
        for child in node.children:
            if child.type == "call":
                func = child.child_by_field_name("function")
                calls.append(
                    {"function": self._get_text(func, code)[:80], "line": child.start_point[0] + 1}
                )
            calls.extend(self._extract_calls(child, code))
        return calls

    def _extract_params(self, func_node, code: str) -> list[str]:
        params_node = func_node.child_by_field_name("parameters")
        if not params_node:
            return []
        return [
            self._get_text(p, code)[:30] for p in params_node.children if p.type == "identifier"
        ]

    @staticmethod
    def _get_text(node, code: str) -> str:
        if node is None:
            return ""
        return code[node.start_byte : node.end_byte]
