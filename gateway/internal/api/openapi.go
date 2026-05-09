package api

import (
	"net/http"
	"sync"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/openapi"
)

// openAPICache holds the rendered document so we don't rebuild on
// every request. The catalogue only changes on config push or new
// deployment, so a 5-minute TTL is plenty.
var openAPICache struct {
	mu        sync.RWMutex
	doc       openapi.Document
	expiresAt time.Time
}

// handleOpenAPI returns the OpenAPI 3.1 document covering every public
// endpoint of the gateway. Public, no auth — SDK generators expect to
// fetch it directly from `/openapi.json`.
func (s *Server) handleOpenAPI(w http.ResponseWriter, r *http.Request) {
	doc := s.openAPIDocument()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, doc)
}

func (s *Server) openAPIDocument() openapi.Document {
	openAPICache.mu.RLock()
	if !openAPICache.expiresAt.Before(time.Now()) && openAPICache.doc != nil {
		doc := openAPICache.doc
		openAPICache.mu.RUnlock()
		return doc
	}
	openAPICache.mu.RUnlock()

	openAPICache.mu.Lock()
	defer openAPICache.mu.Unlock()
	// Re-check after acquiring the write lock — racing fillers should
	// only render once.
	if !openAPICache.expiresAt.Before(time.Now()) && openAPICache.doc != nil {
		return openAPICache.doc
	}

	gen := openapi.Generator{
		ServiceName:    "andromeda-gateway",
		ServiceVersion: "0.1.0",
		BaseURL:        s.cfg.DashboardBaseURL, // overridden by reverse-proxy URL when set
	}
	doc := gen.Build()
	openAPICache.doc = doc
	openAPICache.expiresAt = time.Now().Add(5 * time.Minute)
	return doc
}
