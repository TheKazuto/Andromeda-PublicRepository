package audit

// Canonical event types — keep in sync with the documentation surfaced
// to clients so they can filter by event_type without guessing.
const (
	EventAPIKeyCreated      = "api_key.created"
	EventAPIKeyRevoked      = "api_key.revoked"
	EventSubscriptionAssign = "subscription.assigned"

	EventDWalletDKGSubmitted = "dwallet.dkg.submitted"
	EventDWalletSignSubmit   = "dwallet.sign.submitted"
	EventDWalletSignComplete = "dwallet.sign.completed"
	EventDWalletPresignDone  = "dwallet.presign.completed"

	EventPolicyDeployed         = "policy.deployed"
	EventPolicyUpdated          = "policy.updated"
	EventPolicyPaused           = "policy.paused"
	EventPolicyResumed          = "policy.resumed"
	EventPolicyRevoked          = "policy.revoked"
	EventPolicyRequestApproved  = "policy.signature_request.approved"
	EventPolicyRequestRejected  = "policy.signature_request.rejected"
	EventPolicySimulateExecuted = "policy.simulate.executed"

	EventRecoveryPrimaryUsed   = "recovery.primary.used"
	EventRecoveryQuorumUsed    = "recovery.quorum.used"
	EventRecoveryPolicyChanged = "recovery.policy.changed"

	EventFutureSignArmed  = "future_sign.armed"
	EventFutureSignFired  = "future_sign.fired"
	EventFutureSignExpire = "future_sign.expired"
	EventFutureSignCancel = "future_sign.cancelled"

	EventWebhookEndpointCreate = "webhook.endpoint.created"
	EventWebhookEndpointUpdate = "webhook.endpoint.updated"
	EventWebhookEndpointDelete = "webhook.endpoint.deleted"
	EventWebhookDeliveryRetry  = "webhook.delivery.retry"

	EventIdempotencyReplayed = "idempotency.replayed"
)

const (
	ResourceAPIKey       = "api_key"
	ResourceSubscription = "subscription"
	ResourceDWallet      = "dwallet"
	ResourcePolicy       = "policy"
	ResourceRecovery     = "recovery"
	ResourceTrigger      = "future_sign_trigger"
	ResourceWebhook      = "webhook"
)
