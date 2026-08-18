package atlas.authz

import future.keywords.in

default allow = false
default require_step_up = false

# Allow tool execution if all policy checks pass
allow {
    not is_blocked_tool
    not is_unauthorized_user_scope
    is_valid_role_invocation
}

# Require Step-Up (Human in the loop) for destructive or high-impact actions
require_step_up {
    input.tool in ["send_email", "execute_payment", "modify_iam", "terminate_instance"]
    not input.session.step_up_approved
}

# Block unauthorized tools by role
is_blocked_tool {
    input.tool in input.agent.denied_tools
}

# Validate user scope delegation (User Token Exchange check)
is_unauthorized_user_scope {
    required_scope := concat(":", [input.tool, "execute"])
    not required_scope in input.user.scopes
    not "admin:all" in input.user.scopes
}

# Role-based tool invocation permissions
is_valid_role_invocation {
    input.agent.role == "analyst"
    input.tool in ["sql_query", "read_file", "search_docs", "calculate"]
}

is_valid_role_invocation {
    input.agent.role == "operator"
    input.tool in ["sql_query", "read_file", "write_file", "restart_service", "search_docs"]
}

is_valid_role_invocation {
    input.agent.role == "admin"
}

# Metadata attached to denial responses for ATLAS / OWASP telemetry
violation_meta = {
    "atlas_technique": "AML.T0086",
    "owasp_category": "ASI03",
    "nist_control": "GOVERN-1.2",
    "reason": "Agent role or authenticated user lacks authorized scope for requested tool"
} {
    not allow
}
