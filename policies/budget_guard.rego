package atlas.budget

default allow = false

# Allow execution if within session step limit, token budget, and rate limit
allow {
    not exceeds_step_depth
    not exceeds_token_budget
    not exceeds_rate_limit
}

# Block runaway agent loops
exceeds_step_depth {
    input.session.step_count > input.limits.max_steps_per_turn
}

exceeds_token_budget {
    input.session.total_tokens_consumed > input.limits.max_token_budget
}

exceeds_rate_limit {
    input.session.tool_calls_per_minute > input.limits.max_calls_per_minute
}

violation_meta = {
    "atlas_technique": "AML.T0057",
    "owasp_category": "ASI08",
    "nist_control": "MANAGE-2.4",
    "reason": "Agent runaway loop detected, session step depth cap or token budget exceeded"
} {
    not allow
}
