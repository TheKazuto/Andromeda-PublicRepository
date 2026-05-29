package netguard

import "testing"

func TestValidateRPCURL(t *testing.T) {
	cases := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"public hostname", "https://api.mainnet-beta.solana.com", false},
		{"public ip", "https://1.2.3.4:8545", false},
		{"public hostname with path", "https://rpc.example.com/v1/key", false},
		{"loopback v4", "http://127.0.0.1:8545", true},
		{"loopback v6", "http://[::1]:8545", true},
		{"metadata endpoint", "http://169.254.169.254/latest/meta-data", true},
		{"private 10", "http://10.0.0.1:8545", true},
		{"private 192.168", "http://192.168.1.1", true},
		{"private 172.16", "http://172.16.5.5", true},
		{"unspecified", "http://0.0.0.0:8545", true},
		{"link-local", "http://169.254.10.10", true},
		{"bad scheme", "ftp://1.2.3.4", true},
		{"no scheme", "1.2.3.4:8545", true},
		{"empty", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRPCURL(tc.url)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateRPCURL(%q) err=%v, wantErr=%v", tc.url, err, tc.wantErr)
			}
		})
	}
}

// ValidateURLFormat only checks shape — loopback/private hosts pass because
// operator overrides legitimately point at local/private RPC nodes.
func TestValidateURLFormat(t *testing.T) {
	ok := []string{
		"http://127.0.0.1:8899",
		"https://rpc.example.com",
		"http://10.0.0.1:8545",
	}
	for _, u := range ok {
		if err := ValidateURLFormat(u); err != nil {
			t.Errorf("ValidateURLFormat(%q) unexpected err: %v", u, err)
		}
	}
	bad := []string{"", "ftp://host", "not a url", "://nohost"}
	for _, u := range bad {
		if err := ValidateURLFormat(u); err == nil {
			t.Errorf("ValidateURLFormat(%q) expected err, got nil", u)
		}
	}
}
