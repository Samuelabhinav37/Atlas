# Atlas: Advanced Research & Frontier Security Notes

## 1. Simon Willison's Dual LLM & Taint Tracking Pattern

### The Core Insight
In August 2023 and expanded through 2025/2026, Simon Willison identified the fundamental structural vulnerability of AI agents: **treating untrusted external data as instructions**.

The **Dual LLM Pattern** splits the system into two distinct boundaries:
1. **Privileged LLM (Planner)**: Holds tool access, but **never sees raw untrusted data**.
2. **Quarantined LLM (Data Processor)**: Ingests untrusted web pages, emails, and PDFs, but has **zero tool access**.

```
┌────────────────────────────────────────────────────────────────────────┐
│                        Dual LLM Taint Architecture                     │
│                                                                        │
│  [ Untrusted Source ] ──► [ Quarantined LLM ] ──► [ Sanitized Struct ] │
│  (Web/Email/RAG)          (No Tools Available)             │           │
│                                                            ▼           │
│  [ Privileged LLM ] ◄─────────────────────────── [ Atlas Control Plane]│
│  (Tool Authority) ──► [ Evaluated Tool Call ] ──► [ Protected Action ] │
└────────────────────────────────────────────────────────────────────────┘
```

### How Atlas Adapts This
Atlas implements this without requiring two separate foundation models by acting as the **Deterministic Taint Boundary**:
* When a tool returns data, `InterToolScrubber` neutralizes command sequences and applies an explicit `[ATLAS QUARANTINE]` envelope to prevent the privileged model from parsing untrusted text as system commands.

---

## 2. Model Context Protocol (MCP) Security Analysis

### The MCP Threat Vector
Anthropic's Model Context Protocol (MCP) is the standard JSON-RPC wire protocol for agent tools. Security audits throughout 2025/2026 revealed 3 critical architectural vulnerabilities:
1. **Unchecked STDIO Execution**: Local MCP servers run with full host user permissions, allowing arguments passed by the model to trigger shell injection.
2. **Tool Shadowing & Supply Chain Poisoning**: Untrusted MCP servers can declare duplicate tool names (e.g. shadowing `read_file` with a malicious proxy).
3. **Lack of In-Band Delegation**: Native MCP lacks built-in token down-scoping; once connected, the model has unrestricted access to all registered tools.

### Atlas MCP Gateway Superpowers
Atlas can act as an inline **MCP Security Reverse Proxy**:
* Intercepts `tools/call` JSON-RPC messages before dispatching to the real MCP server.
* Enforces least-privilege rules on tool names and arguments (Python PDP).
* Validates server manifests and hashes tool schemas to prevent tool shadowing.

---

## 3. Authenticated Delegation & The AuthZEN Standard

### Moving Beyond Ambient Authority
When an agent acts on behalf of a user, granting the agent the user's permanent master token creates an **ambient authority vulnerability**.

### The Solution: OAuth Token Exchange (RFC 8693) + AuthZEN
1. **Token Down-Scoping**: When a user delegates a task, Atlas exchanges the user's high-privilege token for a short-lived, task-bound token (`scopes: ["sql_query:read"]`).
2. **AuthZEN Standard Protocol**: Atlas exposes a standardized PEP API (`/v1/agent/evaluate`) conforming to the OpenID Foundation AuthZEN standard, enabling plug-and-play integration with any enterprise PDP (OPA, Permit.io, Axiomatics, Cerbos).

---

## 4. Frontier Roadmap: Ideas to Make Atlas Even More Powerful

| Frontier Capability | Technical Description | Impact |
| :--- | :--- | :--- |
| **1. Dynamic Semantic Drift Invariant** | Generate vector embeddings of initial user task and assert that intermediate tool calls maintain cosine similarity > 0.65 to the user objective. | Stops subtle multi-turn goal hijacking (*AML.T0057*). |
| **2. MCP Native stdio Proxy Wrapper** | A CLI wrapper (`atlas-mcp-wrap <command>`) that transparently filters stdin/stdout JSON-RPC streams between Claude Desktop/Cursor and local tools. | Universal 1-click protection for desktop AI tools. |
| **3. Automated Red Teaming Probe Generator** | Integrated fuzzing tool that generates dynamic prompt injection payloads against newly added tools to verify policy coverage automatically. | Proactive automated security assurance. |
| **4. Multi-Dialect SQL AST Security Rewriter** | Instead of merely denying queries, automatically rewrite queries to inject `LIMIT 50` and tenant partition filters (`WHERE tenant_id = '...'`). | Self-healing autonomous security. |
