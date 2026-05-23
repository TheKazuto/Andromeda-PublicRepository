package policy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gagliardetto/solana-go"
	"github.com/go-chi/chi/v5"
)

// TestResolveTenantID verifies that resolveTenantID uses the wired tenantResolver.
// When the resolver is set, it should return the tenant ID from the resolver.
// When the resolver is not set, it should return empty string and false.
func TestResolveTenantID(t *testing.T) {
	tests := []struct {
		name             string
		resolver         func(*http.Request) (string, error)
		expectedTenantID string
		expectedOK       bool
	}{
		{
			name: "resolver returns valid tenant ID",
			resolver: func(r *http.Request) (string, error) {
				return "tenant-123", nil
			},
			expectedTenantID: "tenant-123",
			expectedOK:       true,
		},
		{
			name: "resolver returns empty string",
			resolver: func(r *http.Request) (string, error) {
				return "", nil
			},
			expectedTenantID: "",
			expectedOK:       false,
		},
		{
			name: "resolver returns error",
			resolver: func(r *http.Request) (string, error) {
				return "", fmt.Errorf("auth failed")
			},
			expectedTenantID: "",
			expectedOK:       false,
		},
		{
			name:             "no resolver set",
			resolver:         nil,
			expectedTenantID: "",
			expectedOK:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &Service{
				tenantResolver: tt.resolver,
			}

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			tenantID, ok := svc.resolveTenantID(req)

			if ok != tt.expectedOK {
				t.Errorf("expected ok=%v, got %v", tt.expectedOK, ok)
			}
			if tenantID != tt.expectedTenantID {
				t.Errorf("expected tenantID=%q, got %q", tt.expectedTenantID, tenantID)
			}
		})
	}
}

// TestGetRiskConfigWithTenantResolver verifies that GET /v1/policy/risk/config/{dwalletAddress}
// does not return 401 when a tenantResolver is properly wired.
func TestGetRiskConfigWithTenantResolver(t *testing.T) {
	// Create a mock RiskConfigService that returns nil (config not found).
	mockConfigSvc := &mockRiskConfigService{}

	// Create the Service with a wired tenantResolver.
	svc := NewService(solana.PublicKey{})
	svc.tenantResolver = func(r *http.Request) (string, error) {
		return "tenant-456", nil
	}
	svc.riskConfigService = mockConfigSvc

	// Register the risk routes.
	r := svc.newTestRouter()

	// Make a GET request to the risk config endpoint.
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/risk/config/11111111111111111111111111111112", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Verify that the response is NOT 401.
	if w.Code == http.StatusUnauthorized {
		t.Errorf("expected non-401 response, got %d", w.Code)
	}

	// Should get 404 (config not found) or 200 depending on the mock.
	// The key point is that we don't get 401 due to missing tenantResolver.
	if w.Code != http.StatusNotFound && w.Code != http.StatusOK {
		t.Logf("expected 200 or 404, got %d (acceptable as long as not 401)", w.Code)
	}
}

// TestGetRiskConfigWithoutTenantResolver verifies that GET /v1/policy/risk/config/{dwalletAddress}
// returns 401 when no tenantResolver is wired.
func TestGetRiskConfigWithoutTenantResolver(t *testing.T) {
	// Create a mock RiskConfigService.
	mockConfigSvc := &mockRiskConfigService{}

	// Create the Service WITHOUT a wired tenantResolver.
	svc := NewService(solana.PublicKey{})
	svc.tenantResolver = nil
	svc.riskConfigService = mockConfigSvc

	// Register the risk routes.
	r := svc.newTestRouter()

	// Make a GET request to the risk config endpoint.
	req := httptest.NewRequest(http.MethodGet, "/v1/policy/risk/config/11111111111111111111111111111112", nil)
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Verify that the response IS 401.
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 Unauthorized, got %d", w.Code)
	}
}

// Mock implementation of RiskConfigService for testing.
type mockRiskConfigService struct{}

func (m *mockRiskConfigService) UpsertDWalletConfig(ctx context.Context, dwalletAddress, tenantID, warnLevel string, simulationEnabled bool) (interface{}, error) {
	return nil, nil
}

func (m *mockRiskConfigService) GetDWalletConfig(ctx context.Context, dwalletAddress string) (interface{}, error) {
	return nil, nil
}

func (m *mockRiskConfigService) DeleteDWalletConfig(ctx context.Context, dwalletAddress string) error {
	return nil
}

func (m *mockRiskConfigService) UpsertTenantDefaults(ctx context.Context, tenantID, warnLevel string) (interface{}, error) {
	return nil, nil
}

func (m *mockRiskConfigService) GetTenantDefaults(ctx context.Context, tenantID string) (interface{}, error) {
	return nil, nil
}

func (m *mockRiskConfigService) AddToDenylist(ctx context.Context, tenantID, destination, reason string) error {
	return nil
}

func (m *mockRiskConfigService) RemoveFromDenylist(ctx context.Context, tenantID, destination string) error {
	return nil
}

func (m *mockRiskConfigService) AddToAllowlist(ctx context.Context, tenantID, destination, reason string) error {
	return nil
}

func (m *mockRiskConfigService) RemoveFromAllowlist(ctx context.Context, tenantID, destination string) error {
	return nil
}

// newTestRouter creates a minimal chi router with just the risk routes mounted.
func (s *Service) newTestRouter() chi.Router {
	r := chi.NewRouter()
	subRouter := chi.NewRouter()
	subRouter.Get("/config/{dwalletAddress}", s.getRiskConfig)
	r.Mount("/v1/policy/risk", subRouter)
	return r
}
