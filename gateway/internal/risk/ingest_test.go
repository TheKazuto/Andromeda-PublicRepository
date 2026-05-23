package risk

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/shinkalabs/andromeda-gateway/internal/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeAddress(t *testing.T) {
	tests := []struct {
		input       string
		expected    string
		expectError bool
	}{
		{"0x1234567890abcdef", "1234567890abcdef", false},
		{"1234567890ABCDEF", "1234567890abcdef", false},
		{"0x", "", true},
		{"", "", true},
		{"  0xAbCd  ", "abcd", false},
		{"Eby8vqorxEXiAA2XVQnNCLXBp98", "Eby8vqorxEXiAA2XVQnNCLXBp98", false}, // base58 (Solana) preserves case
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := store.NormalizeAddress(tt.input)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestParseFeed(t *testing.T) {
	feedCfg := &FeedSource{
		URL:      "https://example.com/phishing.json",
		Source:   "test-feed",
		Category: "phishing",
		License:  "MIT",
	}

	content := `0x1234567890abcdef
0xAAAABBBBCCCCDDDD
# Comment line
  0xEEEEFFFF0000
`

	ingestor := NewIngestor(IngestorOptions{
		Feeds: []FeedSource{*feedCfg},
	})

	addresses, err := ingestor.parseFeed(feedCfg, content)
	require.NoError(t, err)

	expected := []string{
		"1234567890abcdef",
		"aaaabbbbccccdddd",
		"eeeeffff0000",
	}
	assert.Equal(t, expected, addresses)
}

func TestParseFeedEmpty(t *testing.T) {
	feedCfg := &FeedSource{
		URL:      "https://example.com/phishing.json",
		Source:   "test-feed",
		Category: "phishing",
		License:  "MIT",
	}

	content := `# Only comments
# More comments

`

	ingestor := NewIngestor(IngestorOptions{
		Feeds: []FeedSource{*feedCfg},
	})

	addresses, err := ingestor.parseFeed(feedCfg, content)
	require.NoError(t, err)
	assert.Empty(t, addresses)
}

func TestContentHashGeneration(t *testing.T) {
	content := "test content for hashing"
	hash := sha256.Sum256([]byte(content))
	hashHex := hex.EncodeToString(hash[:])

	// Verify hash is 64 chars (256 bits / 4 bits per hex char)
	assert.Len(t, hashHex, 64)

	// Verify hash is stable
	hash2 := sha256.Sum256([]byte(content))
	hashHex2 := hex.EncodeToString(hash2[:])
	assert.Equal(t, hashHex, hashHex2)
}

func TestIngestorOptions(t *testing.T) {
	opts := IngestorOptions{
		Feeds:        []FeedSource{{URL: "https://example.com"}},
		TickInterval: 0,
		HTTPTimeout:  0,
	}

	ingestor := NewIngestor(opts)
	assert.NotNil(t, ingestor)
	assert.Equal(t, 3600*time.Second, ingestor.opts.TickInterval)
	assert.Equal(t, 30*time.Second, ingestor.opts.HTTPTimeout)
	assert.Equal(t, float64(30), ingestor.opts.VariationThresholdPercent)
}

// TestLeaseIDGeneration is tested implicitly via ClaimDueFeedRuns in integration tests.
// The ingest.go function uses uuid.NewString() internally; unit testing would
// require exposing the function, which is not necessary since it's a standard UUID v4.
