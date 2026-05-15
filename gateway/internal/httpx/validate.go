package httpx

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/gagliardetto/solana-go"
	"github.com/go-playground/validator/v10"
)

// Validate is the gateway-wide validator instance. Custom tags
// (`solana_pubkey`, `base64`, `base64_len`, `hex_len`) are registered the
// first time the variable is read; callers never construct their own.
var (
	validateOnce sync.Once
	validateImpl *validator.Validate
)

// V returns the shared validator. Safe to call from `init()` of other
// packages — registration is lazy and idempotent.
func V() *validator.Validate {
	validateOnce.Do(func() {
		validateImpl = newValidator()
	})
	return validateImpl
}

func newValidator() *validator.Validate {
	v := validator.New(validator.WithRequiredStructEnabled())

	// Use the `json` struct tag for field names in error messages so the
	// public response refers to the wire field, not the Go field name.
	v.RegisterTagNameFunc(func(fld reflect.StructField) string {
		tag := fld.Tag.Get("json")
		if tag == "" {
			return fld.Name
		}
		if comma := strings.Index(tag, ","); comma >= 0 {
			tag = tag[:comma]
		}
		if tag == "-" {
			return ""
		}
		return tag
	})

	_ = v.RegisterValidation("solana_pubkey", validateSolanaPubkey)
	_ = v.RegisterValidation("base64", validateBase64)
	_ = v.RegisterValidation("base64_len", validateBase64Len)
	_ = v.RegisterValidation("hex_len", validateHexLen)

	return v
}

// ── Custom validators ───────────────────────────────────────────────

// solana_pubkey: the string field must decode as a base58 Solana pubkey
// (32 bytes). Accepts the empty string only when paired with `omitempty`.
func validateSolanaPubkey(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" {
		return false
	}
	_, err := solana.PublicKeyFromBase58(s)
	return err == nil
}

// base64: the string field must be valid standard base64. Empty fails — pair
// with `omitempty` for optional inputs.
func validateBase64(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" {
		return false
	}
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}

// base64_len=N: valid base64 that decodes to exactly N bytes.
func validateBase64Len(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" {
		return false
	}
	n, err := strconv.Atoi(fl.Param())
	if err != nil || n < 0 {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	return len(raw) == n
}

// hex_len=N: hex string (lower/upper) that decodes to exactly N bytes.
func validateHexLen(fl validator.FieldLevel) bool {
	s := fl.Field().String()
	if s == "" {
		return false
	}
	n, err := strconv.Atoi(fl.Param())
	if err != nil || n < 0 {
		return false
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return false
	}
	return len(raw) == n
}

// ── Bind + validate helper ─────────────────────────────────────────

// BindAndValidate reads up to `maxBytes` from r.Body, JSON-decodes strictly
// (`DisallowUnknownFields`) into `dst`, then runs the package validator on
// the resulting struct. Returns true on success; on failure it has already
// written the canonical {error, code} envelope and the caller MUST return.
//
// `maxBytes <= 0` skips the per-call cap (the global middleware still
// enforces the gateway-wide limit set by `api.limitPayload`).
//
// Error mapping:
//   - body unreadable / decode error      → 400 `invalid_body`
//   - unknown field (strict mode)         → 400 `unknown_field`
//   - body bigger than maxBytes           → 413 `payload_too_large`
//   - validator.Struct fails              → 400 `invalid_field`
func BindAndValidate(w http.ResponseWriter, r *http.Request, dst any, maxBytes int64) bool {
	if r.Body == nil {
		WriteError(w, http.StatusBadRequest, "invalid_body", "request body is required")
		return false
	}
	body := r.Body
	if maxBytes > 0 {
		body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeDecodeError(w, err)
		return false
	}
	// Reject trailing JSON garbage ("{...}{...}" payloads).
	if dec.More() {
		WriteError(w, http.StatusBadRequest, "invalid_body", "request body must contain a single JSON object")
		return false
	}
	if err := V().Struct(dst); err != nil {
		writeValidationError(w, err)
		return false
	}
	return true
}

// writeDecodeError classifies json.Decoder errors into the public envelope.
func writeDecodeError(w http.ResponseWriter, err error) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		WriteError(w, http.StatusRequestEntityTooLarge, "payload_too_large",
			fmt.Sprintf("request body exceeds %d bytes", maxErr.Limit))
		return
	}
	var unknownField *json.UnmarshalTypeError
	if errors.As(err, &unknownField) {
		WriteError(w, http.StatusBadRequest, "invalid_body",
			fmt.Sprintf("field %q has the wrong type", unknownField.Field))
		return
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field ") {
		WriteError(w, http.StatusBadRequest, "unknown_field", msg)
		return
	}
	WriteError(w, http.StatusBadRequest, "invalid_body", "invalid JSON body")
}

// writeValidationError surfaces the first failing field + rule. We do NOT
// echo arbitrary user input or stack frames — the message is built from the
// known field name and a short, fixed rule description.
func writeValidationError(w http.ResponseWriter, err error) {
	var verrs validator.ValidationErrors
	if errors.As(err, &verrs) && len(verrs) > 0 {
		first := verrs[0]
		field := first.Field()
		if field == "" {
			field = first.StructField()
		}
		WriteError(w, http.StatusBadRequest, "invalid_field",
			fmt.Sprintf("%s: %s", field, describeRule(first)))
		return
	}
	WriteError(w, http.StatusBadRequest, "invalid_field", "request failed validation")
}

// describeRule turns a validator tag into a human-readable rule fragment.
// Keep the strings short and deterministic — they appear in API responses.
func describeRule(fe validator.FieldError) string {
	tag := fe.Tag()
	param := fe.Param()
	switch tag {
	case "required":
		return "is required"
	case "required_with":
		return "is required when " + param + " is present"
	case "required_without":
		return "is required when " + param + " is missing"
	case "min":
		return "must be >= " + param
	case "max":
		return "must be <= " + param
	case "len":
		return "length must equal " + param
	case "oneof":
		return "must be one of: " + param
	case "uuid", "uuid4":
		return "must be a UUID"
	case "url":
		return "must be a URL"
	case "email":
		return "must be an email"
	case "solana_pubkey":
		return "must be a base58 Solana pubkey"
	case "base64":
		return "must be valid base64"
	case "base64_len":
		return "must be base64 decoding to " + param + " bytes"
	case "hex_len":
		return "must be hex decoding to " + param + " bytes"
	default:
		return "failed `" + tag + "`"
	}
}

// DrainBody silently consumes the remainder of r.Body so the underlying
// connection can be reused. Useful when a handler decided to short-circuit
// before reading the whole body. Errors are ignored on purpose.
func DrainBody(r *http.Request) {
	if r == nil || r.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, r.Body)
}
