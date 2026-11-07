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
		"hydra://relay.example.com:443#no-key",             // no pubkey anywhere
		"hydra://relay.example.com:443?pub=#empty",         // empty pub value
		"hydra://relay.example.com:443?pub=!!!bad!!!",      // not base64
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

// TestHydraAxes proves every tuning-axis query param lands on the outbound
// (TUNING.md sweep): the full vocabulary ffmin/ffmax/frmin/frmax/fsd/dis/
// disd/pbk/mp/bpm/rcc/rcw/rtomin/rtomax/rbc/rka/tlsfrag/tlsmin/tlsmax/
// tlsalpn, all in one link.
func TestHydraAxes(t *testing.T) {
	url := "hydra://relay.example.com?pub=YWJjZA==" +
		"&ffmin=16&ffmax=48&frmin=24&frmax=64&fsd=5" +
		"&dis=1&disd=25" +
		"&pbk=512,2048,65536&mp=32&bpm=1024" +
		"&rcc=900&rcw=64&rtomin=120&rtomax=4000&rbc=256&rka=3000" +
		"&tlsfrag=1&tlsmin=1.2&tlsmax=1.3&tlsalpn=h2,http/1.1#tuned"
	out, err := ray2sing.HydraSingbox(url)
	if err != nil {
		t.Fatalf("HydraSingbox(%q): %v", url, err)
	}
	got := marshalOutbound(t, out)
	want := map[string]any{
		"type": "hydra", "tag": "tuned",
		"server": "relay.example.com", "server_port": 443.0,
		"pubkey": "YWJjZA==", "path": "/hydra",
		"tls":            map[string]any{"enabled": true, "insecure": true},
		"frag_first_min": 16.0, "frag_first_max": 48.0,
		"frag_rest_min": 24.0, "frag_rest_max": 64.0,
		"split_delay_ms": 5.0,
		"disorder":       true, "disorder_delay_ms": 25.0,
		"pad_buckets": []any{512.0, 2048.0, 65536.0},
		"max_pad":     32.0, "big_pad_max": 1024.0,
		"rtc_chunk": 900.0, "rtc_window": 64.0,
		"rto_min": 120.0, "rto_max": 4000.0,
		"buffer_cap": 256.0, "keepalive_every": 3000.0,
		"tls_fragment": true, "tls_min_version": "1.2", "tls_max_version": "1.3",
		"tls_alpn": []any{"h2", "http/1.1"},
	}
	if !reflect.DeepEqual(got, want) {
		gotRaw, _ := json.Marshal(got)
		t.Errorf("axes mismatch\n got: %s", gotRaw)
	}
	// A plain link marshals without any axis field (omitempty everywhere).
	plain, err := ray2sing.HydraSingbox("hydra://YWJjZA==@relay.example.com#plain")
	if err != nil {
		t.Fatalf("plain link: %v", err)
	}
	plainMap := marshalOutbound(t, plain)
	for _, axisKey := range []string{"frag_first_min", "disorder", "pad_buckets", "rtc_chunk", "tls_fragment"} {
		if _, present := plainMap[axisKey]; present {
			t.Errorf("plain link must not carry axis key %q", axisKey)
		}
	}
}

func TestHydraAxisErrors(t *testing.T) {
	const base = "hydra://relay.example.com?pub=YWJjZA=="
	for name, qs := range map[string]string{
		"ffmin junk":       "&ffmin=abc",
		"ffmax high":       "&ffmax=65",
		"frmax high":       "&frmax=97",
		"fsd high":         "&fsd=51",
		"disd high":        "&disd=101",
		"dis flag":         "&dis=maybe",
		"pbk descending":   "&pbk=1024,512",
		"pbk low member":   "&pbk=100",
		"pbk high member":  "&pbk=65537",
		"pbk nine entries": "&pbk=256,512,1024,2048,4096,8192,16384,32768,65536",
		"mp high":          "&mp=65",
		"bpm high":         "&bpm=4097",
		"rcc low":          "&rcc=255",
		"rcc high":         "&rcc=1181",
		"rcw low":          "&rcw=15",
		"rcw high":         "&rcw=1025",
		"rtomin high":      "&rtomin=501",
		"rtomax low":       "&rtomax=999",
		"rbc low":          "&rbc=127",
		"rka high":         "&rka=15001",
		"tlsfrag flag":     "&tlsfrag=yes-please",
	} {
		t.Run(name, func(t *testing.T) {
			if out, err := ray2sing.HydraSingbox(base + qs); err == nil {
				t.Errorf("HydraSingbox(%q) = %+v, want error", qs, out)
			}
		})
	}
	// Zero values are legal and mean "fork default" for every numeric axis;
	// they stay omitted on the marshalled outbound.
	if out, err := ray2sing.HydraSingbox(base + "&fsd=0&disd=0&mp=0&bpm=0"); err != nil {
		t.Errorf("zero-valued numeric axes must parse: %v", err)
	} else {
		got := marshalOutbound(t, out)
		if _, present := got["split_delay_ms"]; present {
			t.Errorf("zero axis must stay omitted, got %+v", got)
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
