FROM hashicorp/vault:1.18

# Switch to root so the entrypoint can fix volume permissions before dropping
# privileges to the `vault` user. The vault process itself runs unprivileged.
USER root

# Copy the production config and the entrypoint shim.
COPY vault.hcl /vault/config/vault.hcl
COPY entrypoint.sh /usr/local/bin/andromeda-entrypoint.sh
RUN chmod +x /usr/local/bin/andromeda-entrypoint.sh

# Healthcheck: Vault returns sealed=false only after the operator has run
# `vault operator unseal` 3 times. Until then, the service is intentionally
# unhealthy on Railway.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8200/v1/sys/health | grep -q '"sealed":false' || exit 1

EXPOSE 8200

ENTRYPOINT ["/usr/local/bin/andromeda-entrypoint.sh"]
CMD ["server", "-config=/vault/config/vault.hcl"]
