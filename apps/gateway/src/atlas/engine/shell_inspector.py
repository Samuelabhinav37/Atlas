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
        "mkfs": [],
        "dd": ["if=", "of=/dev"],
        "shutdown": [],
        "reboot": [],
        "init": ["0", "6"],
        "nc": ["-e", "-c"],
        "ncat": ["-e", "--exec"],
        "socat": ["exec:"],
    }

    # Root-level system paths that rm should never target
    DESTRUCTIVE_RM_TARGETS = {
        "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/opt",
        "/proc", "/root", "/sbin", "/srv", "/sys", "/tmp", "/usr", "/var",
        "C:\\", "C:\\Windows", "C:\\System32", "C:\\Program Files",
    }

    REVERSE_SHELL_PATTERNS = [
        re.compile(r"/dev/tcp/\d+\.\d+\.\d+\.\d+/\d+"),
        re.compile(r"bash\s+-i\s+>&"),
        re.compile(r"nc\s+-[a-zA-Z]*e\s+"),
        re.compile(r"socat\s+tcp-connect", re.IGNORECASE),
        re.compile(r"python\s+-c\s+['\"].*import\s+socket"),
    ]

    PIPE_EXEC_PATTERNS = [
        re.compile(r"(?i)\|\s*(sh|bash|zsh|dash|python|perl|ruby)\b"),
        re.compile(r"(?i)(curl|wget)\s+[^\s|]+\s*\|\s*(sh|bash)"),
    ]

    SUBSHELL_PATTERNS = [
        re.compile(r"\$\([^)]+\)"),
        re.compile(r"`[^`]+`"),
    ]

    # chmod dangerous permission patterns
    CHMOD_DANGEROUS_PATTERNS = [
        re.compile(r"\b0?[67][67][67]\b"),       # 777, 0777, 666, 0666, etc.
        re.compile(r"\b(ugo|a)\s*=\s*rwx\b"),    # ugo=rwx, a=rwx
    ]

    # PowerShell dangerous cmdlet patterns
    POWERSHELL_PATTERNS = [
        (re.compile(r"(?i)Remove-Item\s+.*-Recurse.*-Force|Remove-Item\s+.*-Force.*-Recurse"), "PowerShell destructive Remove-Item with -Recurse -Force"),
        (re.compile(r"(?i)\b(Invoke-Expression|iex)\b"), "PowerShell Invoke-Expression (arbitrary code execution)"),
        (re.compile(r"(?i)Invoke-WebRequest\s+.*\|\s*(Invoke-Expression|iex)"), "PowerShell download-and-execute pattern"),
        (re.compile(r"(?i)Set-ExecutionPolicy\s+Unrestricted"), "PowerShell execution policy bypass"),
        (re.compile(r"(?i)\b(Stop-Computer|Restart-Computer)\b"), "PowerShell system shutdown/restart"),
    ]

    # Script interpreter invocation patterns
    INTERPRETER_PATTERNS = [
        re.compile(r"(?i)\bpython[23]?\s+-c\b"),
        re.compile(r"(?i)\bperl\s+-e\b"),
        re.compile(r"(?i)\bnode\s+-e\b"),
        re.compile(r"(?i)\bruby\s+-e\b"),
        re.compile(r"(?i)\blua\s+-e\b"),
    ]

    def __init__(self):
        self.deobfuscator = RecursiveDeobfuscator()

    # Matches one or more trailing glob segments so 'rm -rf /etc/*' and
    # 'rm -rf /*' are compared against DESTRUCTIVE_RM_TARGETS the same way
    # as 'rm -rf /etc' and 'rm -rf /' -- a bare wildcard glob still deletes
    # everything a literal path match would, it just isn't string-equal to
    # the entries in that set.
    _TRAILING_GLOB_RE = re.compile(r"(?:[/\\]\*+)+$")

    def _normalize_rm_path(self, path: str) -> str:
        stripped = self._TRAILING_GLOB_RE.sub("", path)
        stripped = stripped.rstrip("/").rstrip("\\")
        if not stripped or stripped in ("*", "/*", "\\*"):
            return "/"
        return stripped

    def _check_rm_dangerous(self, cmd_parts: list[str]) -> str | None:
        """Check if an rm command is genuinely dangerous (recursive+force on system paths).

        Returns a risk description string if dangerous, None if safe.
        Avoids false positives like `rm -f /workspace/temp/file.txt`.
        """
        if not cmd_parts or cmd_parts[0].lower() != "rm":
            return None

        flags: set[str] = set()
        paths: list[str] = []

        for part in cmd_parts[1:]:
            if part.startswith("-") and not part.startswith("--"):
                # Expand combined flags: -rf -> {r, f}
                for char in part[1:]:
                    flags.add(char)
            elif part.startswith("--"):
                if part == "--recursive":
                    flags.add("r")
                elif part == "--force":
                    flags.add("f")
                elif part == "--no-preserve-root":
                    flags.add("no-preserve-root")
            else:
                paths.append(part)

        has_recursive = "r" in flags or "R" in flags
        has_force = "f" in flags

        # Check for destructive targets
        for path in paths:
            normalized_path = self._normalize_rm_path(path)

            if normalized_path in self.DESTRUCTIVE_RM_TARGETS or normalized_path in ("/", "~"):
                if has_recursive and has_force:
                    return f"Destructive rm -rf targeting system path '{path}'"
                if normalized_path == "/" or normalized_path in {"C:\\", "C:\\Windows"}:
                    return f"Destructive rm targeting root/system path '{path}'"

        # Also catch `rm -rf /` even if flags are split
        if has_recursive and has_force and "no-preserve-root" in flags:
            return "Destructive rm with --no-preserve-root"

        return None

    def _check_find_delete_dangerous(self, cmd_parts: list[str]) -> str | None:
        """Check if a `find ... -delete` targets a system path.

        `find <path> -delete` recursively deletes everything under <path>
        with no confirmation, no -r/-f flags to gate on, and none of rm's
        signature -- it is functionally equivalent to `rm -rf <path>` and
        was previously not checked at all. Only the leading positional path
        argument is inspected (standard `find <path> [expression]` form);
        this deliberately doesn't attempt to parse find's full expression
        grammar.
        """
        if not cmd_parts or cmd_parts[0].lower() != "find":
            return None
        if "-delete" not in cmd_parts:
            return None

        for part in cmd_parts[1:]:
            if part.startswith("-"):
                break
            normalized_path = self._normalize_rm_path(part)
            if normalized_path in self.DESTRUCTIVE_RM_TARGETS or normalized_path in ("/", "~"):
                return f"Destructive 'find -delete' targeting system path '{part}'"
            break

        return None

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
            if pattern.search(normalized_cmd):
                risks.append(f"Reverse shell signature detected: {pattern.pattern}")

        # 3. Pipe to Shell Execution
        for pattern in self.PIPE_EXEC_PATTERNS:
            if pattern.search(normalized_cmd):
                risks.append("Dangerous pipe to shell execution (e.g. curl | sh)")

        # 4. Subshell Command Substitution
        for pattern in self.SUBSHELL_PATTERNS:
            if pattern.search(normalized_cmd):
                risks.append("Unauthorized subshell command substitution $(...) detected")

        # 5. PowerShell Dangerous Cmdlets
        for pattern, description in self.POWERSHELL_PATTERNS:
            if pattern.search(normalized_cmd):
                risks.append(f"Dangerous PowerShell pattern: {description}")

        # 6. Script Interpreter Invocation
        for pattern in self.INTERPRETER_PATTERNS:
            if pattern.search(normalized_cmd):
                risks.append("Script interpreter invocation detected (potential code execution bypass)")

        # 7. AST Parsing via bashlex
        try:
            nodes = bashlex.parse(normalized_cmd)
            for node in nodes:
                self._visit_node(node, commands_found, risks)
        except Exception:
            # If bashlex cannot parse complex shell syntax, check with regex fallback
            risks.append("Unparseable or malformed shell command AST")

        # 8. Check extracted commands against dangerous commands table + rm hardening
        for cmd_entry in commands_found:
            cmd_parts = cmd_entry.split()
            base_cmd = cmd_parts[0].lower() if cmd_parts else ""

            # Special handling for rm with proper flag parsing
            if base_cmd == "rm":
                rm_risk = self._check_rm_dangerous(cmd_parts)
                if rm_risk:
                    risks.append(rm_risk)
            elif base_cmd == "find":
                find_risk = self._check_find_delete_dangerous(cmd_parts)
                if find_risk:
                    risks.append(find_risk)
            elif base_cmd == "chmod":
                # Check for dangerous permission patterns
                for chmod_pat in self.CHMOD_DANGEROUS_PATTERNS:
                    if chmod_pat.search(cmd_entry):
                        risks.append(f"Dangerous chmod permission: '{cmd_entry}'")
                        break
            elif base_cmd in self.DANGEROUS_COMMANDS:
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
