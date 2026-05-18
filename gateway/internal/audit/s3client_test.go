package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestS3Client_PutObject_Signature wires an httptest server that
// receives the PUT and re-derives SigV4 against the request bytes. If
// our PutObject and the test agree on canonical request + signing key
// + string-to-sign, the test passes; any drift makes both sides differ.
//
// This is the same technique AWS' own signing tests use — we don't
// trust our implementation by inspecting headers but by independently
// re-deriving the signature and comparing.
func TestS3Client_PutObject_SignatureRoundTrip(t *testing.T) {
	body := []byte(`{"hello":"world"}`)
	const accessKey = "AKIAIOSFODNN7EXAMPLE"
	const secretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	const region = "auto"
	const bucket = "andromeda-test"
	const key = "audit/2026-05-18-1-100.ndjson.gz"

	var serverErr string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Re-derive: hash the body we actually received, then redo
		// canonical request and signing. Body must match the client's
		// X-Amz-Content-Sha256 declared hash.
		got, err := io.ReadAll(r.Body)
		if err != nil {
			serverErr = "read body: " + err.Error()
			w.WriteHeader(500)
			return
		}
		declaredHash := r.Header.Get("X-Amz-Content-Sha256")
		actualHash := sha256Hex(got)
		if declaredHash != actualHash {
			serverErr = "payload hash mismatch: declared=" + declaredHash + " actual=" + actualHash
			w.WriteHeader(400)
			return
		}
		// Parse the Authorization header.
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 ") {
			serverErr = "auth header not SigV4: " + auth
			w.WriteHeader(401)
			return
		}
		// Extract Credential/SignedHeaders/Signature components.
		fields := map[string]string{}
		for _, part := range strings.Split(strings.TrimPrefix(auth, "AWS4-HMAC-SHA256 "), ", ") {
			kv := strings.SplitN(part, "=", 2)
			if len(kv) == 2 {
				fields[kv[0]] = kv[1]
			}
		}
		credParts := strings.Split(fields["Credential"], "/")
		if len(credParts) != 5 {
			serverErr = "bad credential: " + fields["Credential"]
			w.WriteHeader(400)
			return
		}
		gotAccess, dateStamp, gotRegion, gotService, gotTerminator := credParts[0], credParts[1], credParts[2], credParts[3], credParts[4]
		if gotAccess != accessKey || gotRegion != region || gotService != "s3" || gotTerminator != "aws4_request" {
			serverErr = "credential mismatch: " + fields["Credential"]
			w.WriteHeader(401)
			return
		}
		signedHeaders := strings.Split(fields["SignedHeaders"], ";")
		// Recompute the signature with the same algorithm.
		amzDate := r.Header.Get("X-Amz-Date")
		var canonicalHeaders strings.Builder
		for _, h := range signedHeaders {
			canonicalHeaders.WriteString(h)
			canonicalHeaders.WriteString(":")
			canonicalHeaders.WriteString(strings.TrimSpace(r.Header.Get(h)))
			canonicalHeaders.WriteString("\n")
		}
		// Go's HTTP server lifts the Host header into r.Host and removes
		// it from r.Header. Re-inject it before reading canonical
		// headers so the value matches what the client signed.
		canonicalHeadersStr := strings.ReplaceAll(canonicalHeaders.String(), "host:\n", "host:"+r.Host+"\n")
		canonicalRequest := strings.Join([]string{
			r.Method,
			r.URL.EscapedPath(),
			r.URL.RawQuery,
			canonicalHeadersStr,
			fields["SignedHeaders"],
			actualHash,
		}, "\n")
		credentialScope := strings.Join([]string{dateStamp, region, "s3", "aws4_request"}, "/")
		stringToSign := strings.Join([]string{
			"AWS4-HMAC-SHA256",
			amzDate,
			credentialScope,
			sha256Hex([]byte(canonicalRequest)),
		}, "\n")
		kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
		kRegion := hmacSHA256(kDate, []byte(region))
		kService := hmacSHA256(kRegion, []byte("s3"))
		kSigning := hmacSHA256(kService, []byte("aws4_request"))
		wantSig := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
		if wantSig != fields["Signature"] {
			serverErr = "signature mismatch: got=" + fields["Signature"] + " want=" + wantSig +
				"\ncanonicalRequest=" + canonicalRequest +
				"\nstringToSign=" + stringToSign
			w.WriteHeader(403)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	client := NewS3Client(srv.URL, bucket, region, accessKey, secretKey)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.PutObject(ctx, key, body, "application/gzip"); err != nil {
		t.Fatalf("PutObject failed: %v (server: %s)", err, serverErr)
	}
	if serverErr != "" {
		t.Fatalf("server-side validation failed: %s", serverErr)
	}
}

func TestS3Client_PutObject_PropagatesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("<Error><Code>AccessDenied</Code></Error>"))
	}))
	defer srv.Close()
	c := NewS3Client(srv.URL, "b", "auto", "ak", "sk")
	err := c.PutObject(context.Background(), "k.txt", []byte("x"), "")
	if err == nil {
		t.Fatal("expected error on 403, got nil")
	}
	if !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestS3Client_PutObject_RejectsMissingEndpoint(t *testing.T) {
	c := NewS3Client("", "b", "auto", "ak", "sk")
	err := c.PutObject(context.Background(), "k", []byte("x"), "")
	if err == nil || !strings.Contains(err.Error(), "endpoint is empty") {
		t.Errorf("expected endpoint-empty error, got: %v", err)
	}
}

func TestS3Client_PutObject_RejectsMissingBucket(t *testing.T) {
	c := NewS3Client("http://example", "", "auto", "ak", "sk")
	err := c.PutObject(context.Background(), "k", []byte("x"), "")
	if err == nil || !strings.Contains(err.Error(), "bucket is empty") {
		t.Errorf("expected bucket-empty error, got: %v", err)
	}
}

func TestEscapeS3Key_PreservesSlashes(t *testing.T) {
	got := escapeS3Key("audit/2026-05-18/file with space.ndjson.gz")
	want := "audit/2026-05-18/file%20with%20space.ndjson.gz"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestEscapeS3Key_HandlesEmpty(t *testing.T) {
	if escapeS3Key("") != "" {
		t.Error("empty key should stay empty")
	}
}

func TestSHA256Hex_KnownVector(t *testing.T) {
	// "abc" → ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
	got := sha256Hex([]byte("abc"))
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	// Empty bytes → e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	empty := sha256.Sum256(nil)
	if hex.EncodeToString(empty[:]) != sha256Hex(nil) {
		t.Error("sha256Hex(nil) mismatch")
	}
}

func TestHMACSHA256_KnownVector(t *testing.T) {
	// RFC 4231 test case 1: key="0b"x20, data="Hi There" → expected.
	key := make([]byte, 20)
	for i := range key {
		key[i] = 0x0b
	}
	got := hex.EncodeToString(hmacSHA256(key, []byte("Hi There")))
	want := "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
