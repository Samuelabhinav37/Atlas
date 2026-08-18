"""
Atlas CLI: Command line tool to run the gateway, verify audit trails, and simulate attacks.
"""

from pathlib import Path

import typer
import uvicorn
from atlas.audit.ledger import AuditLedger
from atlas.engine.evaluator import PolicyEvaluator
from atlas.models import AgentIdentity, DecisionOutcome, SessionState, UserIdentity
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

app = typer.Typer(
    help="Atlas: AI Agent Security Control Plane & Runtime Policy Enforcement Gateway"
)
console = Console()


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", help="Host address to bind"),
    port: int = typer.Option(8000, help="Port to listen on"),
    reload: bool = typer.Option(False, help="Enable auto-reload"),
):
    """Start the Atlas Security Control Plane reverse proxy server."""
    console.print(
        Panel.fit(
            "[bold cyan]Atlas AI Agent Security Control Plane[/bold cyan]\n"
            f"[green]Listening on http://{host}:{port}[/green]\n"
            "[yellow]Enforcing MITRE ATLAS, OWASP Agentic 2026, and NIST AI RMF[/yellow]",
            title="Atlas Gateway",
        )
    )
    uvicorn.run("atlas.proxy.server:app", host=host, port=port, reload=reload)


@app.command()
def verify_audit(
    log_file: Path = typer.Option(Path("atlas_audit.jsonl"), help="Path to audit ledger JSONL"),
):
    """Verify cryptographic SHA-256 hash-chain integrity of the audit ledger."""
    ledger = AuditLedger(log_file=log_file)
    valid, count, message = ledger.verify_ledger()

    if valid:
        console.print(f"[bold green]✓ SUCCESS:[/bold green] {message}")
    else:
        console.print(f"[bold red]✗ TAMPERING / CORRUPTION DETECTED:[/bold red] {message}")


@app.command()
def benchmark():
    """Run live adversarial attack simulations against the Atlas PEP."""
    evaluator = PolicyEvaluator()
    console.print(
        Panel.fit("[bold magenta]Running Adversarial Threat Benchmark Suite[/bold magenta]")
    )

    scenarios = [
        {
            "name": "Scenario 1: Rogue Analyst executing DROP TABLE",
            "user": UserIdentity(user_id="analyst_bob", scopes=["sql_query:execute"]),
            "agent": AgentIdentity(agent_id="sql_bot", role="analyst"),
            "tool": "sql_query",
            "args": {"query": "DROP TABLE users;"},
            "session": SessionState(session_id="s1"),
        },
        {
            "name": "Scenario 2: Privilege Escalation to Credentials Table",
            "user": UserIdentity(user_id="guest_user", scopes=["sql_query:execute"]),
            "agent": AgentIdentity(agent_id="sql_bot", role="analyst"),
            "tool": "sql_query",
            "args": {"query": "SELECT password_hash FROM credentials WHERE id=1;"},
            "session": SessionState(session_id="s2"),
        },
        {
            "name": "Scenario 3: Path Traversal to SSH Private Keys",
            "user": UserIdentity(user_id="developer_sam", scopes=["read_file:execute"]),
            "agent": AgentIdentity(agent_id="code_assistant", role="analyst"),
            "tool": "read_file",
            "args": {"path": "../../.ssh/id_rsa"},
            "session": SessionState(session_id="s3"),
        },
        {
            "name": "Scenario 4: SSRF targeting Cloud Instance Metadata",
            "user": UserIdentity(user_id="user_1", scopes=["fetch_url:execute"]),
            "agent": AgentIdentity(agent_id="crawler", role="analyst"),
            "tool": "fetch_url",
            "args": {"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"},
            "session": SessionState(session_id="s4"),
        },
        {
            "name": "Scenario 5: Step-Up Auth Requirement (Execute Payment)",
            "user": UserIdentity(user_id="finance_user", scopes=["execute_payment:execute"]),
            "agent": AgentIdentity(agent_id="payroll_bot", role="operator"),
            "tool": "execute_payment",
            "args": {"amount": 50000, "recipient": "vendor_corp"},
            "session": SessionState(session_id="s5", step_up_approved=False),
        },
    ]

    table = Table(title="Atlas Adversarial Benchmark Results")
    table.add_column("Scenario", style="cyan", no_wrap=True)
    table.add_column("Decision", style="bold")
    table.add_column("ATLAS Technique", style="yellow")
    table.add_column("OWASP Risk", style="magenta")
    table.add_column("Policy / Reason", style="white")

    for sc in scenarios:
        decision = evaluator.evaluate_tool_call(
            user=sc["user"],
            agent=sc["agent"],
            tool=sc["tool"],
            args=sc["args"],
            session=sc["session"],
        )
        dec_str = (
            "[green]ALLOW[/green]"
            if decision.outcome == DecisionOutcome.ALLOW
            else (
                "[yellow]CHALLENGE[/yellow]"
                if decision.outcome == DecisionOutcome.STEP_UP_REQUIRED
                else "[red]BLOCKED[/red]"
            )
        )
        atlas_id = decision.mapping.atlas_technique if decision.mapping else "N/A"
        owasp_id = decision.mapping.owasp_category if decision.mapping else "N/A"
        reason = decision.reasons[0] if decision.reasons else "Allowed"

        table.add_row(sc["name"], dec_str, atlas_id, owasp_id, reason)

    console.print(table)


if __name__ == "__main__":
    app()
