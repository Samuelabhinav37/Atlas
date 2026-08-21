# Atlas: Engineering Notes, Error Log & Operational Guide

> **Living Technical Notes & Troubleshooting Playbook for the Atlas AI Agent Security Control Plane.**

---

## 1. Project Vision & Architecture Review

Every major security framework describes or tests AI systems, but **none enforce runtime constraints**:
- **NIST AI RMF / CAISI**: Outlines risk governance policies at rest.
- **MITRE ATLAS**: Catalogs techniques like `AML.T0051` (Direct Prompt Injection), `AML.T0054` (Context Poisoning), `AML.T0086` (Tool Misuse), and `AML.T0057` (Goal Hijacking).
- **OWASP Agentic Top 10 (2026)**: Catalogs `ASI01` to `ASI10`.

**Atlas is the runtime enforcement layer (Policy Enforcement Point - PEP)** that intercepts agent tool proposals, sanitizes tool returns, enforces least-agency via AST parsing, issues signed delegation envelopes, traps prompt injections with synthetic honeypots, and produces cryptographic audit receipts.

---

## 2. Common Errors Encountered & How We Fixed Them

### Error 1: Windows CLI Execution (`atlas` command not recognized)
* **Symptom**: When running `pip install -e .` on Windows, Python's Microsoft Store app installs `atlas.exe` inside `AppData\Local\Packages\...LocalCache\local-packages\Python313\Scripts` which is not on the default Windows system `PATH`.
* **Root Cause**: Windows environment path isolation for Store-distributed Python installations.
* **Fix & Workaround**:
  1. Add entrypoint to `pyproject.toml`:
     ```toml
     [project.scripts]
     atlas = "atlas.cli:app"
     ```
  2. For zero-configuration reliability across all environments, use Python module invocation:
     ```powershell
     python -m atlas.cli serve --host 127.0.0.1 --port 8000
     python -m atlas.cli red-team
     python -m atlas.cli benchmark
     python -m atlas.cli verify-audit
     ```

---

### Error 2: Windows Console Unicode Encoding Crashes
* **Symptom**: CLI crashed with `UnicodeEncodeError: 'charmap' codec can't encode character '\u2717'` when printing rich checkmarks and crossmarks.
* **Root Cause**: Default Windows `pwsh` code page (`cp1252`) cannot encode standard Unicode icons.
* **Fix**: Replaced all custom Unicode symbols with Windows-safe ASCII indicators: `[OK]`, `[FAIL]`, `[ALLOWED]`, `[BLOCKED]`.

---

### Error 3: Regex Base64 Word Boundary Mismatch on Padded Strings
* **Symptom**: Base64 payloads ending with `=` padding (e.g. `cm0gLXJmIC8=`) failed extraction when using `\b` word boundaries.
* **Root Cause**: In standard regex, `=` is treated as a non-word boundary character, causing `\b` before/after `=` to fail matching.
* **Fix**: Refined the extractor regex in `apps/gateway/src/atlas/detectors/deobfuscator.py` to:
  ```python
  BASE64_CANDIDATE_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")
  ```
  Coupled with strict `base64.b64decode(validate=True)` and printable ASCII text filters.

---

### Error 4: Multi-Agent Subshell Command Substitution Bypass
* **Symptom**: Advanced command substitutions like `cat $(echo /etc/shadow)` or `` `cat /etc/passwd` `` could bypass flat regex allowlists.
* **Root Cause**: Subshells dynamically evaluate before the outer command runs.
* **Fix**: Integrated `bashlex` recursive AST node visitor (`_visit_node`) to traverse `commandsubstitution` nodes alongside subshell regex tripwires in `apps/gateway/src/atlas/engine/shell_inspector.py`.

---

### Error 5: Decorator Positional Argument Binding in Python SDK
* **Symptom**: Wrapping functions like `def execute_sql(query: str)` using `@guard.wrap_tool` failed to extract `query` when passed positionally.
* **Root Cause**: `kwargs` was empty when arguments were passed as positional parameters `*args`.
* **Fix**: Used Python's `inspect.signature(tool_func).bind(*args, **kwargs)` with `apply_defaults()` to reliably convert all arguments into a normalized dictionary.

---

### Error 6: `/v1/agent/evaluate` and Step-Up Approval Trusted Self-Reported Identity
* **Symptom**: Any caller could POST `{"user": {"scopes": ["admin:all"]}, ...}` to `/v1/agent/evaluate` and be evaluated as an admin, and anyone who triggered a Step-Up challenge could immediately approve their own request via `/v1/auth/step-up/approve/{id}` by supplying any `approver_id` string.
* **Root Cause**: `user` identity/scopes and `approver_id` came directly from the client-supplied JSON body, with no verification the caller actually held that identity.
* **Fix**: Added `apps/gateway/src/atlas/auth/tokens.py` (JWT issue/verify via `pyjwt`, which was already a declared dependency but unused). `/v1/agent/evaluate` now derives `user` only from a verified `Authorization: Bearer` token (`get_verified_user` dependency); step-up approve/reject require the verified caller to hold a `step_up:approve` scope (`require_step_up_approver`). Requires `ATLAS_JWT_SECRET` to be set — the gateway refuses a default or generated signing key. The dashboard mints itself a short-lived operator-scoped demo token server-side for its own same-origin fetch calls.

---

## 3. How to Run & Use Atlas

### Method A: Start Gateway & Visual Dashboard
`/v1/agent/evaluate` and the step-up approval endpoints require a signed bearer token
(see `atlas.auth.tokens`), so `ATLAS_JWT_SECRET` must be set before the dashboard's
simulator/approval buttons will work:
```powershell
# In terminal:
$env:ATLAS_JWT_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
python -m atlas.cli serve --host 127.0.0.1 --port 8000
```
Open **[http://localhost:8000/dashboard](http://localhost:8000/dashboard)** in your browser for the real-time visual control plane, live attack simulator, HITL approval queue, and audit feed.

---

### Method B: Use the Python SDK in Agent Frameworks
You can wrap ANY tool or agent with 1 line of Python:

```python
from atlas import AtlasGuard, SecurityViolationError

guard = AtlasGuard(default_agent_role="analyst")

# Option 1: Protect single tool calls directly
hardened_args = guard.protect_call(
    tool_name="sql_query",
    arguments={"query": "SELECT * FROM orders;"},
)
# Automatically returns: {"query": "SELECT * FROM orders LIMIT 100;"}


# Option 2: Wrap any tool function with a decorator
@guard.wrap_tool
def query_db(query: str):
    # This code only executes if authorized!
    return database.execute(query)


# Option 3: Scan ingress user prompts
guard.inspect_prompt("Summarize weekly reports")  # Allowed
# guard.inspect_prompt("Ignore previous instructions...")  # Raises ValueError
```

---

### Method C: Execute Verification & Security Audits
```powershell
# 1. Run all 60 automated unit and adversarial tests
python -m pytest -v

# 2. Run the 20-probe Adversarial Red-Team Fuzzing Suite
python -m atlas.cli red-team

# 3. Verify cryptographic SHA-256 ledger integrity
python -m atlas.cli verify-audit

# 4. Evaluate an MCP JSON-RPC tool call
python -m atlas.cli mcp-eval sql_query '{"query": "DROP TABLE users;"}' --role analyst
```

---

## 4. Summary of Capabilities

| Module | Location | Purpose |
| :--- | :--- | :--- |
| **Python SDK** | `atlas.sdk` | 1-line `@guard.wrap_tool` decorator & `protect_call` |
| **Active Deception** | `atlas.detectors.honeypots` | Synthetic honeypot tools & decoy DB table traps |
| **OpenTelemetry Exporter** | `atlas.telemetry.otel_exporter` | Official 2026 GenAI Semantic Convention traces |
| **Recursive De-obfuscator** | `atlas.detectors.deobfuscator` | NFKC + URL + Base64 + Hex unescaping |
| **Shell AST Inspector** | `atlas.engine.shell_inspector` | Bashlex AST tree walker for RCE & reverse shells |
| **SQL Security Rewriter** | `atlas.engine.sql_rewriter` | SQLGlot AST query limiter & tenant isolation |
| **Multi-Agent ADT** | `atlas.auth.delegation` | HMAC-signed delegation tokens & cascade breakers |
| **Bearer Token Identity** | `atlas.auth.tokens` | JWT issue/verify; sole source of caller identity/scopes for `/v1/agent/evaluate` |
| **HITL Step-Up Auth** | `atlas.auth.step_up` | Asynchronous human approval manager with UI buttons |
| **Cryptographic Ledger** | `atlas.audit.ledger` | SHA-256 hash-chained tamper-evident JSONL trail |
| **Red-Team Fuzzer** | `atlas.redteam.fuzzer` | 20-probe dynamic mutation security score (100.0%) |
