DELETE FROM request_costs
WHERE route_key IN (
  'gateway.webhooks.admin',
  'gateway.audit.read',
  'gateway.policies.admin',
  'gateway.future-sign.admin'
);
