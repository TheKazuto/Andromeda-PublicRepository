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

	// Login Social — OIDC primary recovery (scheme = 4). No PII in clear:
	// only hashes (issuer/audience/subject), addresses and tx signatures.
	EventRecoveryOidcStaged = "recovery.oidc.jwt_staged"
	EventRecoveryOidcOpened = "recovery.oidc.session_opened"
	EventRecoveryOidcUsed   = "recovery.oidc.primary_used"
	EventRecoveryOidcClosed = "recovery.oidc.session_closed"
	EventOidcTokenValidated = "oidc.id_token.validated"
	EventOidcTokenRejected  = "oidc.id_token.rejected"

	// Login Social — OAuth broker (loginsocial.md §5.4 item 1). The
	// broker handshakes with Google/Apple on behalf of the tenant app;
	// payloads carry only provider name + outcome + non-sensitive reason.
	// Never the id_token, the raw sub, or the redirect URI's query string.
	EventOauthHandshakeStarted   = "oauth.handshake.started"
	EventOauthHandshakeCompleted = "oauth.handshake.completed"
	EventOauthHandshakeRejected  = "oauth.handshake.rejected"
	EventOauthTokenExchanged     = "oauth.token_exchanged"

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
	ResourceOauth        = "oauth"
)
