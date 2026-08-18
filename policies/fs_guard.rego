package atlas.filesystem

import future.keywords.in

default allow = false

# Allow filesystem operation if path is contained within sandbox and no forbidden extensions
allow {
    input.tool in ["read_file", "write_file", "list_dir"]
    is_within_sandbox
    not has_path_traversal
    not touches_sensitive_files
}

# Ensure path is within the allowed agent workspace root
is_within_sandbox {
    startswith(input.args.path, input.sandbox.workspace_root)
}

# Block path traversal attempts
has_path_traversal {
    regex.match("(\\.\\./|\\.\\.\\\\)", input.args.path)
}

# Block access to credentials, SSH keys, env files, or shadow files
touches_sensitive_files {
    sensitive_patterns := [".env", "id_rsa", "id_ed25519", "shadow", "passwd", ".aws/credentials", ".git/config"]
    pattern := sensitive_patterns[_]
    contains(lower(input.args.path), pattern)
}

violation_meta = {
    "atlas_technique": "AML.T0086",
    "owasp_category": "ASI05",
    "nist_control": "MANAGE-2.4",
    "reason": "Filesystem path traversal, sensitive file access, or sandbox breakout detected"
} {
    not allow
}
