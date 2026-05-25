package httpx

import "net/http"

// ReadinessFunc reports whether the service is ready to serve swaps. It returns
// a short detail map for the response body and a boolean ready flag.
type ReadinessFunc func() (detail map[string]any, ready bool)

// Health is a liveness probe — always 200 once the process is up.
func Health(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// Ready returns 200 only when the injected readiness check passes (e.g. the
// LI.FI /chains cache has loaded and the breaker is not open). Returns 503
// otherwise so the load balancer routes only healthy replicas.
func Ready(check ReadinessFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		detail, ready := check()
		if detail == nil {
			detail = map[string]any{}
		}
		detail["ready"] = ready
		status := http.StatusOK
		if !ready {
			status = http.StatusServiceUnavailable
		}
		WriteJSON(w, status, detail)
	}
}
