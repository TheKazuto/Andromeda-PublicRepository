DELETE FROM request_costs WHERE route_key IN (
    'ika.oidc.nonce',
    'ika.recovery.primary.oidc.stage',
    'ika.recovery.primary.oidc.open.challenge',
    'ika.recovery.primary.oidc.open',
    'ika.recovery.primary.oidc.use.challenge',
    'ika.recovery.primary.oidc.use.submit',
    'ika.recovery.primary.oidc.close',
    'ika.recovery.primary.oidc.staging.close',
    'ika.oidc.validate'
);
