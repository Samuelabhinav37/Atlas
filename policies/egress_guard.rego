package atlas.egress

import future.keywords.in

default allow = false

# Allow outbound HTTP request if target URL is allowlisted and not targeting internal/cloud metadata
allow {
    input.tool in ["http_request", "fetch_url", "web_search", "send_webhook"]
    not targets_cloud_metadata
    not targets_private_network
    is_domain_allowlisted
}

# Block AWS / GCP / Azure Instance Metadata Services (SSRF target)
targets_cloud_metadata {
    metadata_ips := ["169.254.169.254", "metadata.google.internal", "169.254.169.253"]
    target := metadata_ips[_]
    contains(lower(input.args.url), target)
}

# Block private RFC1918 addresses from agent requests
targets_private_network {
    regex.match("(?i)https?://(localhost|127\\.0\\.0\\.1|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)", input.args.url)
}

# Validate domain against tenant egress allowlist
is_domain_allowlisted {
    allowed_domains := input.tenant.allowed_egress_domains
    domain := allowed_domains[_]
    contains(lower(input.args.url), domain)
}

is_domain_allowlisted {
    input.tenant.allow_public_web == true
}

violation_meta = {
    "atlas_technique": "AML.T0086",
    "owasp_category": "ASI02",
    "nist_control": "MANAGE-2.4",
    "reason": "SSRF attempt, cloud metadata endpoint access, or unauthorized outbound egress domain"
} {
    not allow
}
