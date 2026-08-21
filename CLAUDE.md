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
| **AML.T0086 (Exfiltration via Tool)** | **ASI02 (Tool Misuse)** | Agent is coerced into issuing SSRF or exfiltrating data to external webhooks. | Rego Egress Policies & Cloud Metadata IP Blocklist (`policies/egress_guard.rego`) |
| **AML.T0086 (Unauthorized Execution)** | **ASI05 (Unexpected RCE)** | Agent attempts path traversal (`../../`) or destructive SQL (`DROP TABLE`). | AST-based Argument Parsers (`sqlglot`, `shlex`) & Least Agency Rules |
| **AML.T0057 (Goal Hijacking)** | **ASI08 (Cascading Failures)** | Agent enters runaway infinite retry loop or excessive token spend. | Budget Circuit Breakers & Session Depth Caps (`policies/budget_guard.rego`) |
| **AML.T0053 (ML Artifact Exfil)** | **ASI03 (Privilege Abuse)** | Agent attempts to leak confidential context or API tokens. | Synthetic Canary Token Traps & Secret Scrubber (`CanaryTrapEngine`) |

---

## 3. Integration Patterns

### Pattern A: OpenAI / Anthropic Reverse Proxy
Point your agent client's `base_url` to Atlas:
```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="your-api-key",
    default_headers={
        "X-User-ID": "usr_9910",
        "X-User-Scopes": "sql_query:execute,read_file:execute",
        "X-Agent-ID": "analyst_agent_01",
        "X-Agent-Role": "analyst",
    },
)
```

### Pattern B: Direct AuthZEN PEP Interception (LangChain / CrewAI / AutoGen)
Call `/v1/agent/evaluate` before executing any tool in your custom runtime:
```python
import httpx

response = httpx.post(
    "http://localhost:8000/v1/agent/evaluate",
    json={
        "user": {"user_id": "sam", "scopes": ["sql_query:execute"]},
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
