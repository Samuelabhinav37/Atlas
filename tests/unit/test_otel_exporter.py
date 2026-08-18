"""
Unit tests for the OpenTelemetry GenAI Semantic Conventions Exporter.
"""

from atlas.models import DecisionOutcome, PolicyDecision, SecurityTaxonomyMapping
from atlas.telemetry.otel_exporter import OTelGenAIExporter


def test_otel_span_generation():
    mapping = SecurityTaxonomyMapping(
        atlas_technique="AML.T0086",
        atlas_name="Exfiltration via Agent Tool",
        owasp_category="ASI02",
        owasp_name="Tool Misuse",
        nist_control="MANAGE-2.4",
        reason="Blocked destructive SQL",
    )
    decision = PolicyDecision(
        outcome=DecisionOutcome.DENY,
        allowed=False,
        policy_name="atlas.sql.readonly_enforcement",
        reasons=["Analyst cannot execute DROP"],
        mapping=mapping,
    )

    span = OTelGenAIExporter.create_span(
        trace_id="tr_9910",
        user_id="user_bob",
        tenant_id="corp_a",
        agent_id="sql_bot",
        agent_role="analyst",
        tool_name="sql_query",
        arguments={"query": "DROP TABLE users;"},
        decision=decision,
    )

    assert span["trace_id"] == "tr_9910"
    assert span["attributes"]["gen_ai.system"] == "atlas"
    assert span["attributes"]["gen_ai.agent.id"] == "sql_bot"
    assert span["attributes"]["security.decision.outcome"] == "DENY"
    assert span["attributes"]["security.atlas.technique"] == "AML.T0086"
    assert span["attributes"]["security.owasp.category"] == "ASI02"
    assert span["status"]["code"] == "STATUS_CODE_ERROR"
