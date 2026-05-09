#!/bin/sh
# Andromeda Vault entrypoint.
#
# Why we need this: Railway mounts persistent volumes as root-owned with
# restrictive permissions. The hashicorp/vault image runs as the unprivileged
# `vault` user (uid 100), which can't write to the volume on first boot,
# causing "failed to open bolt file: no such file or directory".
#
# This script runs as root, fixes the ownership of /vault/data, then drops
# privileges to `vault` via su-exec before exec'ing the vault binary.

set -e

if [ ! -d /vault/data ]; then
  mkdir -p /vault/data
fi

chown -R vault:vault /vault/data
chmod 700 /vault/data

# Vault HCL doesn't expand ${VAR} placeholders. We expand RAILWAY_PRIVATE_DOMAIN
# here and set VAULT_API_ADDR / VAULT_CLUSTER_ADDR, which the vault binary
# reads at startup and uses to override the corresponding HCL keys (or fill
# them in when absent from the config).
PRIVATE_HOST="${RAILWAY_PRIVATE_DOMAIN:-127.0.0.1}"
export VAULT_API_ADDR="http://${PRIVATE_HOST}:8200"
export VAULT_CLUSTER_ADDR="http://${PRIVATE_HOST}:8201"

exec su-exec vault:vault env \
  VAULT_API_ADDR="${VAULT_API_ADDR}" \
  VAULT_CLUSTER_ADDR="${VAULT_CLUSTER_ADDR}" \
  vault "$@"
