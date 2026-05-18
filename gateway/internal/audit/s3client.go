package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// S3Client is the minimal S3 PUT client used by the audit snapshotter.
// Only PutObject is implemented because that's the only operation the
// snapshot worker needs. Implementing SigV4 ourselves keeps us off the
// 50+ transitive deps of aws-sdk-go-v2 — the trade-off is reasonable for
// a single endpoint touched daily.
//
// Works against any S3-compatible storage that accepts AWS SigV4:
// AWS S3, Cloudflare R2, MinIO, Backblaze B2.
//
// Cloudflare R2 setup:
//   - Endpoint: https://<account-id>.r2.cloudflarestorage.com
//   - Region:   auto
//   - Credentials: R2 API token (access key id + secret access key)
type S3Client struct {
	Endpoint  string // full URL, no path, no trailing slash
	Bucket    string
	Region    string // "auto" for R2, e.g. "us-east-1" for AWS
	AccessKey string
	SecretKey string
	HTTP      *http.Client
}

// NewS3Client builds an S3Client with a 30s HTTP timeout.
func NewS3Client(endpoint, bucket, region, accessKey, secretKey string) *S3Client {
	return &S3Client{
		Endpoint:  strings.TrimRight(endpoint, "/"),
		Bucket:    bucket,
		Region:    region,
		AccessKey: accessKey,
		SecretKey: secretKey,
		HTTP:      &http.Client{Timeout: 30 * time.Second},
	}
}

// PutObject uploads `body` to `<endpoint>/<bucket>/<key>` with AWS SigV4
// authentication. Returns an error when the response is non-2xx.
//
// The body is consumed twice: once for the payload hash, once for the
// network write. Caller passes a []byte (not an io.Reader) so we can do
// this without buffering twice.
func (c *S3Client) PutObject(ctx context.Context, key string, body []byte, contentType string) error {
	if c.Endpoint == "" {
		return fmt.Errorf("s3: endpoint is empty")
	}
	if c.Bucket == "" {
		return fmt.Errorf("s3: bucket is empty")
	}
	key = strings.TrimLeft(key, "/")
	rawURL := c.Endpoint + "/" + c.Bucket + "/" + escapeS3Key(key)
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("s3: parse url: %w", err)
	}

	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	payloadHash := sha256Hex(body)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u.String(), bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("s3: build request: %w", err)
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Host", u.Host)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.ContentLength = int64(len(body))

	authHeader := c.buildAuthHeader(req, payloadHash, amzDate, dateStamp)
	req.Header.Set("Authorization", authHeader)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("s3 put status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// escapeS3Key URL-encodes each path segment but keeps slashes verbatim
// — AWS expects path segments encoded individually.
func escapeS3Key(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = url.PathEscape(p)
	}
	return strings.Join(parts, "/")
}

func (c *S3Client) buildAuthHeader(req *http.Request, payloadHash, amzDate, dateStamp string) string {
	// Step 1: canonical request
	signedHeaderNames := []string{"content-type", "host", "x-amz-content-sha256", "x-amz-date"}
	sort.Strings(signedHeaderNames)
	var canonicalHeaders strings.Builder
	for _, h := range signedHeaderNames {
		canonicalHeaders.WriteString(h)
		canonicalHeaders.WriteString(":")
		canonicalHeaders.WriteString(strings.TrimSpace(req.Header.Get(h)))
		canonicalHeaders.WriteString("\n")
	}
	signedHeaders := strings.Join(signedHeaderNames, ";")

	canonicalRequest := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		req.URL.RawQuery,
		canonicalHeaders.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	// Step 2: string to sign
	credentialScope := strings.Join([]string{dateStamp, c.Region, "s3", "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	// Step 3: signing key (derived per (date, region, service)). The
	// derivation chain is the AWS SigV4 spec.
	kDate := hmacSHA256([]byte("AWS4"+c.SecretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(c.Region))
	kService := hmacSHA256(kRegion, []byte("s3"))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))

	return fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		c.AccessKey, credentialScope, signedHeaders, signature,
	)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}
