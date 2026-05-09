package policies

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/gagliardetto/solana-go"
	"github.com/go-chi/chi/v5"
)

// MountSDKRoute exposes /v1/policies/{address}/sdk per Andromeda Features
// Roadmap §8. Until the build pipeline that publishes generated TS clients
// is wired (Quasar `quasar idl` → tarball upload), this endpoint surfaces:
//   - the template name (resolved by matching the program id)
//   - canonical PDA derivation hints
//   - links to the source contract under contracts/<template>/
func (s *Service) MountSDKRoute(r chi.Router) {
	r.Get("/v1/policies/{address}/sdk", s.policySDK)
}

func (s *Service) policySDK(w http.ResponseWriter, r *http.Request) {
	addrStr := chi.URLParam(r, "address")
	addr, err := solana.PublicKeyFromBase58(addrStr)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_address", "address must be base58")
		return
	}
	// Best-effort: try each template's PDA derivation against the dwallet
	// (we don't have the dwallet here — the address is the policy PDA).
	// We expose the fact that the address corresponds to a known template
	// by looking at the program owner via RPC.
	resp, err := s.RPCClient.GetAccountInfo(r.Context(), addr)
	if err != nil || resp == nil || resp.Value == nil {
		writeErr(w, http.StatusNotFound, "policy_not_found",
			fmt.Sprintf("policy account %s not found on-chain", addr))
		return
	}
	owner := resp.Value.Owner.String()
	tmplName := ""
	for name, pid := range s.Registry.ProgramIDs {
		if pid.String() == owner {
			tmplName = name
			break
		}
	}
	if tmplName == "" {
		writeErr(w, http.StatusNotFound, "unknown_program",
			fmt.Sprintf("program owner %s is not a registered template", owner))
		return
	}

	// Default version tag: strip the leading "sdk-" prefix so devs see
	// `0.4.0` instead of `sdk-v0.4.0` in their package metadata.
	versionTag := s.SDKVersionTag
	if versionTag == "" {
		versionTag = "sdk-v0.1.0"
	}
	semver := strings.TrimPrefix(versionTag, "sdk-v")
	if semver == versionTag {
		semver = strings.TrimPrefix(versionTag, "sdk-")
	}

	out := map[string]any{
		"address":    addrStr,
		"template":   tmplName,
		"program_id": owner,
		"version":    semver,
		"source_url": fmt.Sprintf("https://github.com/shinkalabs/andromeda/tree/main/contracts/%s", strings.ReplaceAll(tmplName, "_", "-")),
		"docs": map[string]string{
			"templates_catalogue": "/v1/policies/templates",
			"init_endpoint":       fmt.Sprintf("POST /v1/policies/%s/init/prepare", tmplName),
			"request_endpoint":    fmt.Sprintf("POST /v1/policies/%s/request-signature", tmplName),
			"simulate_endpoint":   "POST /v1/signatures/simulate",
		},
	}

	// When the SDK artifacts pipeline (.github/workflows/build-sdk.yml) has
	// published a release, expose direct tarball URLs. Otherwise surface the
	// build command so the dev can produce them locally.
	if s.SDKBaseURL != "" {
		dashName := strings.ReplaceAll(tmplName, "_", "-")
		tarballURL := fmt.Sprintf("%s/%s/%s-ts-client.tgz", s.SDKBaseURL, versionTag, dashName)
		soURL := fmt.Sprintf("%s/%s/%s.so", s.SDKBaseURL, versionTag, strings.ReplaceAll(tmplName, "-", "_"))
		out["typescript"] = map[string]any{
			"tarball_url":     tarballURL,
			"install_command": fmt.Sprintf("npm install %s", tarballURL),
		}
		out["program_binary_url"] = soURL
	} else {
		out["build_command"] = "cargo build-sbf"
		out["client_typescript_path"] = fmt.Sprintf("contracts/%s/target/client/typescript/", strings.ReplaceAll(tmplName, "_", "-"))
		out["note"] = "ANDROMEDA_SDK_BASE_URL not set — build the TS client locally with `cargo build-sbf` or trigger the build-sdk GitHub Action."
	}

	writeJSON(w, http.StatusOK, out)
}

func ToJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
