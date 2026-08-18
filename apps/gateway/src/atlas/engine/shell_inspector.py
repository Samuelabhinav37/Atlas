"""
Shell AST Inspector using bashlex for deterministic runtime command analysis.
Protects against MITRE ATLAS AML.T0086 and OWASP ASI05 (Unexpected RCE).
"""

import re
from dataclasses import dataclass
from typing import Any

import bashlex
from atlas.detectors.deobfuscator import RecursiveDeobfuscator


@dataclass
class ShellScanResult:
    is_safe: bool
    commands_found: list[str]
    detected_risks: list[str]
    violation_reason: str | None


class ShellASTInspector:
    """Parses shell commands into AST nodes and identifies dangerous execution patterns."""

    DANGEROUS_COMMANDS = {
        "rm": ["-rf", "-fr", "/"],
        "mkfs": [],
        "dd": ["if=", "of=/dev"],
        "chmod": ["777", "-R 777", "+x /"],
        "shutdown": [],
        "reboot": [],
        "init": ["0", "6"],
        "nc": ["-e", "-c"],
        "ncat": ["-e", "--exec"],
        "socat": ["exec:"],
    }

    REVERSE_SHELL_PATTERNS = [
        r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+",
        r"bash\s+-i\s+>&",
        r"nc\s+-[a-zA-Z]*e\s+",
        r"socat\s+tcp-connect",
        r"python\s+-c\s+['\"].*import\s+socket",
    ]

    PIPE_EXEC_PATTERNS = [
        r"(?i)\|\s*(sh|bash|zsh|dash|python|perl|ruby)\b",
        r"(?i)(curl|wget)\s+[^\s|]+\s*\|\s*(sh|bash)",
    ]

    SUBSHELL_PATTERNS = [
        r"\$\([^)]+\)",
        r"`[^`]+`",
    ]

    def __init__(self):
        self.deobfuscator = RecursiveDeobfuscator()

    def inspect(self, command_line: str) -> ShellScanResult:
        """Parse command with bashlex and AST visitors to detect malicious behavior."""
        if not command_line or not command_line.strip():
            return ShellScanResult(
                is_safe=True,
                commands_found=[],
                detected_risks=[],
                violation_reason=None,
            )

        # 1. Recursive Deobfuscation
        deob_res = self.deobfuscator.normalize(command_line)
        normalized_cmd = deob_res.normalized_text

        risks = []
        commands_found = []

        # 2. Reverse Shell Signatures
        for pattern in self.REVERSE_SHELL_PATTERNS:
            if re.search(pattern, normalized_cmd):
                risks.append(f"Reverse shell signature detected: {pattern}")

        # 3. Pipe to Shell Execution
        for pattern in self.PIPE_EXEC_PATTERNS:
            if re.search(pattern, normalized_cmd):
                risks.append("Dangerous pipe to shell execution (e.g. curl | sh)")

        # 4. Subshell Command Substitution
        for pattern in self.SUBSHELL_PATTERNS:
            if re.search(pattern, normalized_cmd):
                risks.append("Unauthorized subshell command substitution $(...) detected")

        # 5. AST Parsing via bashlex
        try:
            nodes = bashlex.parse(normalized_cmd)
            for node in nodes:
                self._visit_node(node, commands_found, risks)
        except Exception:
            # If bashlex cannot parse complex shell syntax, check with regex fallback
            risks.append("Unparseable or malformed shell command AST")

        # 6. Check extracted commands against dangerous commands table
        for cmd_entry in commands_found:
            cmd_parts = cmd_entry.split()
            base_cmd = cmd_parts[0].lower() if cmd_parts else ""

            if base_cmd in self.DANGEROUS_COMMANDS:
                required_args = self.DANGEROUS_COMMANDS[base_cmd]
                if not required_args:
                    risks.append(f"Destructive binary invocation forbidden: '{base_cmd}'")
                else:
                    for arg in required_args:
                        if arg in cmd_entry:
                            risks.append(f"Dangerous arguments for command '{base_cmd}': '{arg}'")

        is_safe = len(risks) == 0
        violation_reason = risks[0] if risks else None

        return ShellScanResult(
            is_safe=is_safe,
            commands_found=commands_found,
            detected_risks=risks,
            violation_reason=violation_reason,
        )

    def _visit_node(self, node: Any, commands: list[str], risks: list[str]):
        """Recursive AST node visitor for bashlex AST nodes."""
        kind = getattr(node, "kind", "")

        if kind == "command":
            cmd_words = []
            for part in getattr(node, "parts", []):
                if hasattr(part, "word"):
                    cmd_words.append(part.word)
                elif getattr(part, "kind", "") == "commandsubstitution":
                    risks.append("Unauthorized subshell command substitution $(...) detected")
            if cmd_words:
                commands.append(" ".join(cmd_words))

        elif kind == "pipeline" or kind == "list":
            for part in getattr(node, "parts", []):
                self._visit_node(part, commands, risks)

        elif kind == "compound":
            risks.append("Compound shell control structure detected")
            for part in getattr(node, "list", []):
                self._visit_node(part, commands, risks)
