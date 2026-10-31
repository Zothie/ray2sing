package ray2sing_test

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/hiddify/ray2sing/ray2sing"
	singjson "github.com/sagernet/sing/common/json"
)

// marshalOutbound serializes a single outbound with the context-aware encoder.
// std encoding/json would collapse option.Outbound to {"type","tag"} because
// it only implements MarshalJSONContext.
func marshalOutbound(t *testing.T, out any) map[string]any {
	t.Helper()
	raw, err := singjson.MarshalContext(context.Background(), out)
	if err != nil {
		t.Fatalf("marshal outbound: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal marshalled outbound %s: %v", raw, err)
	}
	return m
}

func TestHydra(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			// userinfo pubkey, port 443 → TLS implied, default path
			name: "minimal userinfo",
			url:  "hydra://YWJjZA==@relay.example.com#my relay",
			want: `{
				"type": "hydra",
				"tag": "my relay",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "YWJjZA==",
				"path": "/hydra",
				"tls": {"enabled": true, "insecure": true}
			}`,
		},
		{
			// query pubkey wins, custom port, explicit TLS, SNI, custom path
			name: "full query form",
			url:  "hydra://relay.example.com:8443/myws?pub=YWJjZA==&tls=1&sni=real.example.com#node",
			want: `{
				"type": "hydra",
				"tag": "node",
				"server": "relay.example.com",
				"server_port": 8443,
				"pubkey": "YWJjZA==",
				"path": "/myws",
				"tls": {"enabled": true, "insecure": true, "server_name": "real.example.com"}
			}`,
		},
		{
			// non-443 port without a tls flag → plaintext ws
			name: "no tls on custom port",
			url:  "hydra://relay.example.com:8443?pub=YWJjZA==#plain",
			want: `{
				"type": "hydra",
				"tag": "plain",
				"server": "relay.example.com",
				"server_port": 8443,
				"pubkey": "YWJjZA==",
				"path": "/hydra"
			}`,
		},
		{
			// explicit tls=0 beats the port-443 default
			name: "tls=0 on port 443",
			url:  "hydra://relay.example.com?pub=YWJjZA==&tls=0#notls",
			want: `{
				"type": "hydra",
				"tag": "notls",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "YWJjZA==",
				"path": "/hydra"
			}`,
		},
		{
			// URL-safe unpadded base64 is normalized to padded standard
			name: "b64url unpadded pubkey",
			url:  "hydra://YWJjZA@relay.example.com:443#b64url",
			want: `{
				"type": "hydra",
				"tag": "b64url",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "YWJjZA==",
				"path": "/hydra",
				"tls": {"enabled": true, "insecure": true}
			}`,
		},
		{
			// URL-safe alphabet characters map back onto the standard one
			name: "url-safe alphabet normalized",
			url:  "hydra://relay.example.com?pub=-_8=#plus",
			want: `{
				"type": "hydra",
				"tag": "plus",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "+/8=",
				"path": "/hydra",
				"tls": {"enabled": true, "insecure": true}
			}`,
		},
		{
			// '+' in a query is a form-encoded space; it must be repaired
			name: "query plus repaired",
			url:  "hydra://relay.example.com?pub=YWJjZA==&tls=1&sni=s.example.com#q",
			want: `{
				"type": "hydra",
				"tag": "q",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "YWJjZA==",
				"path": "/hydra",
				"tls": {"enabled": true, "insecure": true, "server_name": "s.example.com"}
			}`,
		},
		{
			name: "ipv6 host",
			url:  "hydra://YWJjZA==@[2001:db8::1]:443?sni=v6.example.com#v6",
			want: `{
				"type": "hydra",
				"tag": "v6",
				"server": "2001:db8::1",
				"server_port": 443,
				"pubkey": "YWJjZA==",
				"path": "/hydra",
				"tls": {"enabled": true, "insecure": true, "server_name": "v6.example.com"}
			}`,
		},
		{
			// both present → query pubkey wins
			name: "query pub overrides userinfo",
			url:  "hydra://YWJj@relay.example.com?pub=YWJjZA==#querywins",
			want: `{
				"type": "hydra",
				"tag": "querywins",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "YWJjZA==",
				"path": "/hydra",
				"tls": {"enabled": true, "insecure": true}
			}`,
		},
		{
			// the escaped form of the path is kept byte-faithful
			name: "escaped path kept",
			url:  "hydra://relay.example.com/a%2Fb?pub=YWJjZA==#p",
			want: `{
				"type": "hydra",
				"tag": "p",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "YWJjZA==",
				"path": "/a%2Fb",
				"tls": {"enabled": true, "insecure": true}
			}`,
		},
		{
			// a raw '+' in the query reaches the parser as a space and must be
			// repaired before decoding
			name: "query space repaired to plus",
			url:  "hydra://relay.example.com?pub=+/8=#rawplus",
			want: `{
				"type": "hydra",
				"tag": "rawplus",
				"server": "relay.example.com",
				"server_port": 443,
				"pubkey": "+/8=",
				"path": "/hydra",
				"tls": {"enabled": true, "insecure": true}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := ray2sing.HydraSingbox(tt.url)
			if err != nil {
				t.Fatalf("HydraSingbox(%q): %v", tt.url, err)
			}
			got := marshalOutbound(t, out)
			var want map[string]any
			if err := json.Unmarshal([]byte(tt.want), &want); err != nil {
				t.Fatalf("bad want JSON: %v", err)
			}
			if !reflect.DeepEqual(got, want) {
				gotRaw, _ := json.Marshal(got)
				t.Errorf("mismatch\n got: %s\nwant: %s", gotRaw, tt.want)
			}
		})
	}
}

func TestHydraErrors(t *testing.T) {
	for _, url := range []string{
		"hydra://relay.example.com:443#no-key",        // no pubkey anywhere
		"hydra://relay.example.com:443?pub=#empty",    // empty pub value
		"hydra://relay.example.com:443?pub=!!!bad!!!", // not base64
		"hydra://relay.example.com:443?pub=YWJj&tls=maybe", // invalid flag
		"hydra://relay.example.com:20000-40000?pub=YWJj",   // port range
		"hydra://relay.example.com:0?pub=YWJj",             // port zero
		"hydra://?pub=YWJj",                                // no host
	} {
		if out, err := ray2sing.HydraSingbox(url); err == nil {
			t.Errorf("HydraSingbox(%q) = %+v, want error", url, out)
		}
	}
}

// TestHydraFullPipeline proves the convert.go dispatch and the GenerateConfigLite
// tag suffix survive the whole marshal path for a hydra link.
func TestHydraFullPipeline(t *testing.T) {
	raw, err := ray2sing.Ray2Singbox(context.Background(),
		"hydra://YWJjZA==@relay.example.com#my relay", false)
	if err != nil {
		t.Fatalf("Ray2Singbox: %v", err)
	}
	var got struct {
		Outbounds []map[string]any `json:"outbounds"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}
	if len(got.Outbounds) != 1 {
		t.Fatalf("want 1 outbound, got %d: %s", len(got.Outbounds), raw)
	}
	out := got.Outbounds[0]
	if out["type"] != "hydra" {
		t.Errorf("type = %v, want hydra", out["type"])
	}
	if out["tag"] != "my relay § 0" {
		t.Errorf("tag = %v, want %q", out["tag"], "my relay § 0")
	}
	if out["pubkey"] != "YWJjZA==" {
		t.Errorf("pubkey = %v, want YWJjZA==", out["pubkey"])
	}
}
