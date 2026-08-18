"""
Unit tests for the Active Deception and Honeypot Manager.
"""

from atlas.detectors.honeypots import HoneypotManager


def test_honeypot_tool_detection():
    manager = HoneypotManager()
    res = manager.check_trigger(tool_name="dump_admin_credentials", arguments={})

    assert res.triggered is True
    assert res.honeypot_type == "DECOY_TOOL"
    assert "Active Deception Tripwire" in res.violation_reason
    assert res.taxonomy.atlas_technique == "AML.T0051"
    assert res.taxonomy.owasp_category == "ASI01"


def test_decoy_database_table_detection():
    manager = HoneypotManager()
    res = manager.check_trigger(
        tool_name="sql_query",
        arguments={"query": "SELECT * FROM admin_passwords_backup;"},
        extracted_tables=["admin_passwords_backup"],
    )

    assert res.triggered is True
    assert res.honeypot_type == "DECOY_TABLE"
    assert "admin_passwords_backup" in res.violation_reason


def test_legitimate_tool_passthrough():
    manager = HoneypotManager()
    res = manager.check_trigger(
        tool_name="sql_query",
        arguments={"query": "SELECT id FROM orders;"},
        extracted_tables=["orders"],
    )

    assert res.triggered is False
    assert res.honeypot_type is None
