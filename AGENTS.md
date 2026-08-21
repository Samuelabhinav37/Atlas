# Atlas: AI Agent Runtime Security Specification

## 1. Threat Landscape & The Runtime Gap

Modern LLM-powered autonomous agents operate with delegated enterprise authority. Unlike classical static LLM chatbots that only return text, agentic workflows:
- Plan multi-step trajectories.
- Invoke local and remote tools (SQL, Shell, REST APIs, Filesystem).
- Read untrusted dynamic content (RAG, Web searches, Email, Jira).
- Possess memory and persistent state across multi-agent handoffs.

Static compliance frameworks (NIST AI RMF, ISO 42001) define policies, while threat catalogs (MITRE ATLAS, OWASP Agentic Top 10) catalog vulnerabilities. **Atlas serves as the inline Policy Enforcement Point (PEP)** that executes runtime authorization, argument AST validation, inter-tool content sanitization, and cryptographic audit receipts.

---

## 2. Threat Vector Matrix (MITRE ATLAS & OWASP Agentic Top 10)

| MITRE ATLAS Technique | OWASP 2026 Risk | Attack Scenario | Atlas Control Plane Defense |
| :--- | :--- | :--- | :--- |
| **AML.T0051 (Prompt Injection)** | **ASI01 (Agent Goal Hijack)** | Attacker inputs direct instruction overrides to subvert alignment. | Ingress Delimiter & Jailbreak Classifier (`PromptInjectionDetector`) |
| **AML.T0054 (Context Poisoning)** | **ASI06 (Memory Poisoning)** | Attacker embeds instructions in a webpage/PDF read by the agent. | Inter-Tool Content Scrubber & Quarantine Envelope (`InterToolScrubber`) |
| **AML.T0086 (Exfiltration via Tool)** | **ASI02 (Tool Misuse)** | Agent is coerced into issuing SSRF or exfiltrating data to external webhooks. | Egress Guard & Cloud Metadata IP Blocklist (`atlas.engine.evaluator`) |
| **AML.T0086 (Unauthorized Execution)** | **ASI05 (Unexpected RCE)** | Agent attempts path traversal (`../../`) or destructive SQL (`DROP TABLE`). | AST-based Argument Parsers (`sqlglot`, `shlex`) & Least Agency Rules |
| **AML.T0057 (Goal Hijacking)** | **ASI08 (Cascading Failures)** | Agent enters runaway infinite retry loop, excessive token spend, or a tool call that critically diverges from the session's stated goal (e.g. a destructive verb with no basis in it). | Budget Circuit Breakers & Session Depth Caps, plus Goal Drift Check (`POST /v1/agent/session/goal` + `atlas.engine.evaluator`, `SemanticInvariantChecker`) |
| **AML.T0053 (ML Artifact Exfil)** | **ASI03 (Privilege Abuse)** | Agent attempts to leak confidential context or API tokens. | Secret Scrubber (`atlas.detectors.secret_scrubber`, live via `InterToolScrubber`) & Synthetic Canary Traps (`POST /v1/agent/canary` + `atlas.engine.evaluator`'s canary-leak check) |

All enforcement above runs as native Python in `atlas.engine.evaluator.PolicyEvaluator`. `policies/*.rego` is a reference implementation of the same rules in Rego/OPA syntax, kept for anyone who wants to run policy evaluation through OPA instead — it is not currently loaded or queried by the gateway.

---

## 3. Integration Patterns

### Pattern A: OpenAI / Anthropic Reverse Proxy (STUB -- ingress scanning only, no real proxying yet)
`/v1/chat/completions` currently only runs ingress prompt-injection scanning and returns a
canned completion -- it does not call a real upstream model, and since there's no real model
response, it never sees or evaluates `tool_calls` through the PEP. Treat this pattern as a
placeholder for a future real reverse proxy, not a working integration today. User identity
comes from a verified bearer token (same as Pattern B below), not a header:
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key=user_token,  # the OpenAI SDK sends this as `Authorization: Bearer <api_key>`
    default_headers={
        "X-Agent-ID": "analyst_agent_01",
        "X-Agent-Role": "analyst",
    },
)
```

### Pattern B: Direct AuthZEN PEP Interception (LangChain / CrewAI / AutoGen)
Call `/v1/agent/evaluate` before executing any tool in your custom runtime. The caller's
identity and scopes come only from a verified bearer token — never from the request body,
since a self-reported `user` object would let any caller grant itself arbitrary scopes.
Issue tokens with `atlas.auth.tokens.issue_user_token` (server-side, using the same
`ATLAS_JWT_SECRET` the gateway verifies against), then send the token as a header:
```python
import httpx

response = httpx.post(
    "http://localhost:8000/v1/agent/evaluate",
    headers={"Authorization": f"Bearer {user_token}"},
    json={
        "agent": {"agent_id": "sql_bot", "role": "analyst"},
        "tool": "sql_query",
        "arguments": {"query": "SELECT * FROM sales;"},
    },
)
decision = response.json()
if not decision["allowed"]:
    raise PermissionError(f"Atlas blocked action: {decision['reasons']}")
```

### Pattern C: Inter-Tool Return Sanitization
Sanitize untrusted external data retrieved by tools before returning it to the LLM context:
```python
scrub_response = httpx.post(
    "http://localhost:8000/v1/agent/scrub",
    json={
        "tool_name": "web_search",
        "raw_content": untrusted_webpage_html,
    },
)
clean_context = scrub_response.json()["sanitized_content"]
```
