// Package intents is the gateway-side orchestrator for Andromeda Intents
// (multichain swaps via LI.FI over Ika dWallets). It is the single coordinator:
// it builds the swap through the stateless intents-backend, derives the signing
// material via ika-backend prepare-message, authorizes the signature through the
// PolicyEngine v3 (gas-sponsored), signs via ika-backend, finalizes (insert sig
// + broadcast) through the intents-backend, and persists every intent in the
// gateway's Postgres (which the gateway owns).
//
// Boundaries it preserves:
//   - The engines never talk to each other — the gateway calls each in order.
//   - Custody-free: signing happens in ika-backend from the user's passphrase;
//     the gateway never holds a key.
//   - The PolicyEngine gates every signature on-chain; the gateway cannot bypass it.
//   - Gas split: the approval tx (Solana) is gas-sponsored; the swap tx is paid
//     by the dWallet (it never passes through the gas sponsor).
package intents
