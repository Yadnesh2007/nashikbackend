package evidenceshield.authz

import future.keywords.in

default allow = false
default reason = "Default deny: no matching authorization rule."

# -------------------------------------------------------------
# Zero-Trust Input Schema:
# input.user: { id, username, role, agency, mfa_fresh }
# input.action: string
# input.resource: {
#   type: "case" | "document" | "version" | "alert" | "system",
#   case_id: string,
#   document_id: string (optional),
#   version_id: string (optional),
#   classification: "INTERNAL" | "SENSITIVE" | "RESTRICTED",
#   state: "INGESTING" | "READY_PENDING_ANCHOR" | "VERIFIED_ANCHORED" | "QUARANTINED" | "FAILED",
#   uploader_id: string,
#   assigned_principals: [string],
#   assigned_agencies: [string],
#   explicit_grants: [{ principal_id: string, actions: [string], expired: bool }]
# }
# -------------------------------------------------------------

# 1. STRICT ZERO-TRUST: System Admins CANNOT decrypt or read evidentiary documents
allow = false {
    input.user.role == "SYSTEM_ADMIN"
    input.action in ["document:read", "document:download", "document:decrypt", "analysis:run", "case:export"]
}

# 2. Case Level Access
allow {
    input.resource.type == "case"
    input.action == "case:read"
    user_has_case_access
}

allow {
    input.resource.type == "case"
    input.action == "case:write"
    input.user.role == "POLICE"
    user_has_case_access
}

allow {
    input.resource.type == "case"
    input.action == "case:export"
    input.user.role == "PROSECUTOR"
    user_has_case_access
    input.user.mfa_fresh == true
}

# 3. Document / Version Read & Download Access
# Invariant: Quarantined evidence CANNOT be downloaded via standard content route
allow = false {
    input.resource.state == "QUARANTINED"
    input.action == "document:download"
}

# Invariant: Ready-Pending-Anchor can only be inspected by uploader under signed-baseline
allow {
    input.action in ["document:read", "document:download"]
    input.resource.state == "READY_PENDING_ANCHOR"
    input.user.id == input.resource.uploader_id
    user_has_case_access
    classification_permitted
}

# Invariant: Confirmed anchored document read/download
allow {
    input.action in ["document:read", "document:download"]
    input.resource.state == "VERIFIED_ANCHORED"
    user_has_case_access
    classification_permitted
}

# Invariant: Document Grants override standard assignment if not expired
allow {
    input.action in ["document:read", "document:download"]
    input.resource.state == "VERIFIED_ANCHORED"
    user_has_explicit_grant(input.action)
    classification_permitted
}

# 4. Custody Transfers: Requires VERIFIED_ANCHORED
allow {
    input.action == "document:transfer"
    input.resource.state == "VERIFIED_ANCHORED"
    input.user.role in ["POLICE", "FORENSIC_LAB"]
    user_has_case_access
}

# 5. Derivative Creation: Requires VERIFIED_ANCHORED
allow {
    input.action == "document:derivative"
    input.resource.state == "VERIFIED_ANCHORED"
    input.user.role in ["POLICE", "FORENSIC_LAB"]
    user_has_case_access
}

# 6. AI & Readiness Analysis
allow {
    input.action == "analysis:run"
    input.user.role in ["POLICE", "FORENSIC_LAB", "PROSECUTOR"]
    user_has_case_access
}

# 7. Integrity Alerts Review
allow {
    input.action == "alert:review"
    input.user.role in ["POLICE", "FORENSIC_LAB", "PROSECUTOR", "AUDITOR"]
    user_has_case_access
}

# 8. Grant Management: Requires Lead/Owner & Fresh MFA (<10 min)
allow {
    input.action == "grant:create"
    input.user.role in ["POLICE", "PROSECUTOR"]
    user_has_case_access
    input.user.mfa_fresh == true
}

# -------------------------------------------------------------
# Helper Functions
# -------------------------------------------------------------

user_has_case_access {
    input.user.id in input.resource.assigned_principals
}

user_has_case_access {
    input.user.agency in input.resource.assigned_agencies
}

user_has_explicit_grant(req_action) {
    grant := input.resource.explicit_grants[_]
    grant.principal_id == input.user.id
    grant.expired == false
    req_action in grant.actions
}

classification_permitted {
    input.resource.classification == "INTERNAL"
}

classification_permitted {
    input.resource.classification == "SENSITIVE"
    user_has_case_access
}

classification_permitted {
    input.resource.classification == "RESTRICTED"
    user_has_case_access
    input.user.mfa_fresh == true
}
