package api

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/shinkalabs/andromeda-backend/internal/apikeys"
	"github.com/shinkalabs/andromeda-backend/internal/auth"
	"github.com/shinkalabs/andromeda-backend/internal/store"
)

// ----- Helpers -----

type errorBody struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, errorBody{Error: msg})
}

// writeInternal writes a sanitized 500 to the client with a fixed message, so
// internal error strings (database failures, bcrypt internals, third-party
// errors) never reach the user. Callers should still log err separately when
// debugging is needed.
func writeInternal(w http.ResponseWriter) {
	writeError(w, http.StatusInternalServerError, "internal error")
}

// ----- Auth -----

type signupReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Name     string `json:"name"`
}

type authResp struct {
	Token     string      `json:"token"`
	ExpiresAt time.Time   `json:"expiresAt"`
	User      *store.User `json:"user"`
}

func (s *Server) handleSignup(w http.ResponseWriter, r *http.Request) {
	var req signupReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	if _, err := mail.ParseAddress(req.Email); err != nil {
		writeError(w, http.StatusBadRequest, "invalid email")
		return
	}
	if len(req.Password) < 8 {
		writeError(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}
	if req.Name == "" {
		req.Name = strings.SplitN(req.Email, "@", 2)[0]
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not hash password")
		return
	}

	user := &store.User{
		ID:           uuid.NewString(),
		Email:        req.Email,
		Name:         req.Name,
		PasswordHash: hash,
		Plan:         "explorer",
		CreatedAt:    time.Now().UTC(),
	}
	if err := s.store.CreateUser(r.Context(), user); err != nil {
		if errors.Is(err, store.ErrAlreadyExists) {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}

	// Auto-assign Free plan so the user can mint working API keys without
	// going through admin. Failure here is non-fatal — the signup completes
	// and an operator can attach a plan later.
	if _, err := s.store.AssignPlan(r.Context(), user.ID, "free"); err != nil {
		log.Printf("auto-assign free plan failed for user=%s: %v", user.ID, err)
	}

	tok, exp, err := s.issueSession(r.Context(), w, r, user, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	writeJSON(w, http.StatusCreated, authResp{Token: tok, ExpiresAt: exp, User: user})
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// dummyBcryptHash is fed to VerifyPassword when the email is not
// registered, so the response time of /v1/auth/login does not leak
// whether the email exists (timing-safe enumeration mitigation). The
// hash is generated once at package init with the same cost as live
// user hashes, so the bogus comparison takes the same wall-clock
// time as a real one.
var dummyBcryptHash = mustGenerateDummyHash()

func mustGenerateDummyHash() string {
	h, err := bcryptGenerate("andromeda-dummy-never-a-real-password")
	if err != nil {
		// bcrypt failure at boot is unrecoverable — surface it loudly.
		panic("dummy bcrypt hash init: " + err.Error())
	}
	return h
}

func bcryptGenerate(s string) (string, error) {
	return auth.HashPassword(s)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	user, err := s.store.GetUserByEmail(r.Context(), req.Email)

	// Lockout pre-check: refuse before bcrypt to keep bcrypt CPU off the
	// attacker. We only check the lock when the user actually exists, so
	// invalid emails do not surface a different code path.
	if err == nil && user != nil {
		if locked, until := s.checkLockout(r.Context(), user.ID); locked {
			w.Header().Set("Retry-After", retryAfter(until))
			writeError(w, http.StatusTooManyRequests, "account temporarily locked, please retry later")
			return
		}
	}

	hash := dummyBcryptHash
	if err == nil && user != nil {
		hash = user.PasswordHash
	}
	verifyErr := auth.VerifyPassword(req.Password, hash)
	if verifyErr != nil && !errors.Is(verifyErr, auth.ErrInvalidPassword) {
		log.Printf("login: bcrypt verify failed for hash: %v", verifyErr)
	}
	ok := verifyErr == nil
	if err != nil || user == nil || !ok {
		if err == nil && user != nil {
			s.recordFailedLogin(r.Context(), user.ID)
		}
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.recordSuccessfulLogin(r.Context(), user.ID)

	tok, exp, err := s.issueSession(r.Context(), w, r, user, "")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	writeJSON(w, http.StatusOK, authResp{Token: tok, ExpiresAt: exp, User: user})
}

// retryAfter formats a future time for the Retry-After header. Falls back
// to 60s when the lock has no specific expiry.
func retryAfter(until *time.Time) string {
	if until == nil {
		return "60"
	}
	d := time.Until(*until)
	if d < time.Minute {
		return "60"
	}
	secs := int(d.Seconds())
	if secs < 1 {
		secs = 60
	}
	return strconvItoa(secs)
}

// strconvItoa avoids dragging "strconv" into handlers.go just for one call.
func strconvItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	user, err := s.store.GetUserByID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

type updateProfileReq struct {
	Name string `json:"name"`
}

func (s *Server) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	var req updateProfileReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	user, err := s.store.UpdateUser(r.Context(), uid, func(u *store.User) {
		u.Name = req.Name
	})
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

// ----- API Keys -----

type createKeyReq struct {
	Name           string   `json:"name"`
	Scopes         []string `json:"scopes"`
	IPAllowlist    []string `json:"ipAllowlist,omitempty"`
	AllowedOrigins []string `json:"allowedOrigins,omitempty"`
}

type updateKeyReq struct {
	Name           *string   `json:"name,omitempty"`
	IPAllowlist    *[]string `json:"ipAllowlist,omitempty"`
	AllowedOrigins *[]string `json:"allowedOrigins,omitempty"`
}

type createKeyResp struct {
	Key  string        `json:"key"` // shown once
	Item *store.APIKey `json:"item"`
}

func (s *Server) handleListKeys(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	keys, err := s.store.ListAPIKeysByUser(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not load keys")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": keys})
}

func (s *Server) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	var req createKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		req.Name = "Untitled key"
	}
	if len(req.Scopes) == 0 {
		req.Scopes = append([]string{}, auth.DefaultScopes...)
	}
	if invalid := auth.ValidateScopes(req.Scopes); invalid != "" {
		writeError(w, http.StatusBadRequest, "unknown scope: "+invalid+" - allowed: read, write, admin, *")
		return
	}
	if invalid := auth.ValidateIPAllowlist(req.IPAllowlist); invalid != "" {
		writeError(w, http.StatusBadRequest, "invalid IP allowlist entry: "+invalid)
		return
	}
	if invalid := auth.ValidateOriginAllowlist(req.AllowedOrigins); invalid != "" {
		writeError(w, http.StatusBadRequest, "invalid origin allowlist entry: "+invalid+" — origins must be of the form scheme://host[:port] with no path or query")
		return
	}

	full, prefix, hashed, err := apikeys.Generate()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not generate key")
		return
	}

	item := &store.APIKey{
		ID:             uuid.NewString(),
		UserID:         uid,
		Name:           req.Name,
		Prefix:         prefix,
		HashedKey:      hashed,
		Scopes:         req.Scopes,
		IPAllowlist:    normalizeStringSlice(req.IPAllowlist),
		AllowedOrigins: normalizeOriginSlice(req.AllowedOrigins),
		CreatedAt:      time.Now().UTC(),
	}
	if err := s.store.CreateAPIKey(r.Context(), item); err != nil {
		writeError(w, http.StatusInternalServerError, "could not save key")
		return
	}
	writeJSON(w, http.StatusCreated, createKeyResp{Key: full, Item: item})
}

func (s *Server) handleUpdateKey(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	id := chi.URLParam(r, "id")
	var req updateKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	mut := store.APIKeyMutation{}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			writeError(w, http.StatusBadRequest, "name must not be empty")
			return
		}
		mut.Name = &name
	}
	if req.IPAllowlist != nil {
		if invalid := auth.ValidateIPAllowlist(*req.IPAllowlist); invalid != "" {
			writeError(w, http.StatusBadRequest, "invalid IP allowlist entry: "+invalid)
			return
		}
		normalized := normalizeStringSlice(*req.IPAllowlist)
		mut.IPAllowlist = &normalized
	}
	if req.AllowedOrigins != nil {
		if invalid := auth.ValidateOriginAllowlist(*req.AllowedOrigins); invalid != "" {
			writeError(w, http.StatusBadRequest, "invalid origin allowlist entry: "+invalid+" — origins must be of the form scheme://host[:port] with no path or query")
			return
		}
		normalized := normalizeOriginSlice(*req.AllowedOrigins)
		mut.AllowedOrigins = &normalized
	}
	updated, err := s.store.UpdateAPIKey(r.Context(), uid, id, mut)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "key not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "could not update key")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"item": updated})
}

func (s *Server) handleRevokeKey(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	id := chi.URLParam(r, "id")
	if err := s.store.RevokeAPIKey(r.Context(), uid, id); err != nil {
		writeError(w, http.StatusNotFound, "key not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// normalizeStringSlice trims whitespace and drops empty entries.
func normalizeStringSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// normalizeOriginSlice canonicalises every entry via auth.NormalizeOrigin and
// drops empties. Assumes ValidateOriginAllowlist has already been called.
func normalizeOriginSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if normalized := auth.NormalizeOrigin(s); normalized != "" {
			out = append(out, normalized)
		}
	}
	return out
}

// ----- Billing (mock) -----

type invoice struct {
	ID     string  `json:"id"`
	Date   string  `json:"date"`
	Amount float64 `json:"amount"`
	Status string  `json:"status"`
}

type billingResp struct {
	Plan         string    `json:"plan"`
	NextRenewal  string    `json:"nextRenewal"`
	MonthToDate  float64   `json:"monthToDateUsd"`
	PaymentLast4 string    `json:"paymentLast4"`
	Invoices     []invoice `json:"invoices"`
}

func (s *Server) handleBilling(w http.ResponseWriter, r *http.Request) {
	uid := userIDFrom(r)
	user, err := s.store.GetUserByID(r.Context(), uid)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}
	now := time.Now().UTC()
	writeJSON(w, http.StatusOK, billingResp{
		Plan:         user.Plan,
		NextRenewal:  now.AddDate(0, 1, 0).Format("2006-01-02"),
		MonthToDate:  238.42,
		PaymentLast4: "4242",
		Invoices: []invoice{
			{ID: "in_001", Date: now.AddDate(0, -1, 0).Format("2006-01-02"), Amount: 199.00, Status: "paid"},
			{ID: "in_002", Date: now.AddDate(0, -2, 0).Format("2006-01-02"), Amount: 199.00, Status: "paid"},
			{ID: "in_003", Date: now.AddDate(0, -3, 0).Format("2006-01-02"), Amount: 199.00, Status: "paid"},
		},
	})
}
