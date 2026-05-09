# Andromeda Vault — production config for Railway single-node deployment.
#
# Threat model:
#   - Vault is reachable ONLY via Railway private network (*.railway.internal).
#     Public ingress is disabled at the Railway service level.
#   - mlock is disabled because Railway does not grant CAP_IPC_LOCK. Acceptable
#     for MVP; document in the runbook.
#   - Single-node Raft. Acceptable until traffic justifies HA. Snapshots are
#     taken manually before any infra change.

ui = false

# Listener: plain HTTP on private network. TLS would add complexity for no
# meaningful security gain inside the Railway internal mesh, and the Railway
# proxy doesn't expose this port publicly.
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable   = "true"
}

# Storage: Raft (integrated). State is persisted in the Railway volume mounted
# at /vault/data. The node_id MUST be stable across restarts so the Raft log
# stays consistent — we hardcode it here.
storage "raft" {
  path    = "/vault/data"
  node_id = "andromeda-vault-1"
}

# api_addr / cluster_addr come from VAULT_API_ADDR / VAULT_CLUSTER_ADDR env
# vars set by entrypoint.sh at runtime — Vault HCL doesn't expand ${VAR}
# placeholders, so we expand RAILWAY_PRIVATE_DOMAIN in the shell before exec'ing
# the vault binary.

# Disable mlock — Railway containers don't have CAP_IPC_LOCK. Acceptable trade.
disable_mlock = true

# No telemetry sink configured — add Prometheus when monitoring lands.

# Audit logging is enabled AFTER init via:
#   vault audit enable file file_path=/vault/data/audit.log
# We don't enable it here because Vault refuses to boot if the audit sink is
# unreachable, which would brick the service on first start.
