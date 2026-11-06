package ray2sing

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	T "github.com/sagernet/sing-box/option"
)

// Golden: kvm-hop relay (stLqUvj6... = std b64, padded) on 443 → tls auto-on.
func TestHydraSingboxFull(t *testing.T) {
	ob, err := HydraSingbox("hydra://stLqUvj6Rr+Ps5gbewpszBZq8g7mlZi3KgZdBy507mA@103.71.20.24:443/hydra?tls=1&sni=hydra#yandex-hydra")
	if err != nil {
		t.Fatal(err)
	}
	if ob.Type != "hydra" || ob.Tag != "yandex-hydra" {
		t.Fatalf("type/tag: %s/%s", ob.Type, ob.Tag)
	}
	h := ob.Options.(*T.HydraOutboundOptions)
	if h.Server != "103.71.20.24" || h.ServerPort != 443 {
		t.Fatalf("server: %s:%v", h.Server, h.ServerPort)
	}
	// "+" in userinfo path is literal here; query form would need %2B
	if h.Pubkey != "stLqUvj6Rr+Ps5gbewpszBZq8g7mlZi3KgZdBy507mA=" {
		t.Fatalf("pubkey: %s", h.Pubkey)
	}
	if h.Path != "/hydra" {
		t.Fatalf("path: %s", h.Path)
	}
	if h.TLS == nil || !h.TLS.Enabled || !h.TLS.Insecure || h.TLS.ServerName != "hydra" {
		t.Fatalf("tls: %+v", h.TLS)
	}
}

// Query-form pub with URL-safe b64 and no padding must normalize to padded std.
func TestHydraSingboxQueryPubURLSafe(t *testing.T) {
	raw := "6pGGpf8hLPcl3o4Yrxq3gfPn8e6SU8NbonbXDEVUDyQ" // 43 chars, unpadded (real relay pub)
	ob, err := HydraSingbox("hydra://201.50.116.132?pub=" + strings.ReplaceAll(raw, "+", "%2B"))
	if err != nil {
		t.Fatal(err)
	}
	h := ob.Options.(*T.HydraOutboundOptions)
	want := raw + strings.Repeat("=", (4-len(raw)%4)%4)
	if h.Pubkey != want {
		t.Fatalf("pubkey normalize: %s != %s", h.Pubkey, want)
	}
	if h.TLS == nil || !h.TLS.Enabled {
		t.Fatalf("tls must default on for 443")
	}
}

// Port != 443 without explicit tls → plaintext ws.
func TestHydraSingboxNoTLSNonStandardPort(t *testing.T) {
	ob, err := HydraSingbox("hydra://103.71.20.24:44300?pub=AAAA#rtl")
	if err != nil {
		t.Fatal(err)
	}
	h := ob.Options.(*T.HydraOutboundOptions)
	if h.TLS != nil {
		t.Fatalf("tls must be absent for 44300 without flag")
	}
	if h.ServerPort != 44300 {
		t.Fatalf("port: %v", h.ServerPort)
	}
}

// Audit-locked rejects: port ranges, port 0, missing pubkey, bad tls flag.
func TestHydraSingboxRejects(t *testing.T) {
	for _, link := range []string{
		"hydra://host:20000-40000?pub=AAAA",
		"hydra://host:0?pub=AAAA",
		"hydra://host:443",
		"hydra://host:443?pub=AAAA&tls=maybe",
	} {
		if _, err := HydraSingbox(link); err == nil {
			t.Fatalf("must reject: %s", link)
		}
	}
}

// IPv6 literal host must land in Server without brackets.
func TestHydraSingboxIPv6(t *testing.T) {
	ob, err := HydraSingbox("hydra://[2001:db8::1]:443?pub=AAAA#v6")
	if err != nil {
		t.Fatal(err)
	}
	h := ob.Options.(*T.HydraOutboundOptions)
	if h.Server != "2001:db8::1" {
		t.Fatalf("server: %s", h.Server)
	}
}

// Adaptive-group params must ride through the real parse path onto the fork
// options, alongside the untouched static fields.
func TestHydraSingboxAdaptiveParams(t *testing.T) {
	link := "hydra://stLqUvj6Rr+Ps5gbewpszBZq8g7mlZi3KgZdBy507mA@103.71.20.24:443/hydra?tls=1&sni=x&ag=ru-1&pa=https://p.example/proof&pb=131072&pi=wlan0&pd=9.9.9.9:53,[2001:db8::1]:53&at=rtc#hydra-a"
	ob, err := HydraSingbox(link)
	if err != nil {
		t.Fatal(err)
	}
	h := ob.Options.(*T.HydraOutboundOptions)
	if h.AdaptiveGroup != "ru-1" {
		t.Fatalf("adaptive group: %q", h.AdaptiveGroup)
	}
	if h.AdaptiveProof != "https://p.example/proof" {
		t.Fatalf("adaptive proof: %q", h.AdaptiveProof)
	}
	if h.AdaptiveProofBytes != 131072 {
		t.Fatalf("adaptive proof bytes: %d", h.AdaptiveProofBytes)
	}
	if h.AdaptiveInterface != "wlan0" {
		t.Fatalf("adaptive interface: %q", h.AdaptiveInterface)
	}
	if want := []string{"9.9.9.9:53", "[2001:db8::1]:53"}; !slices.Equal(h.AdaptiveDNS, want) {
		t.Fatalf("adaptive dns: %v, want %v", h.AdaptiveDNS, want)
	}
	if h.Transport != "rtc" {
		t.Fatalf("transport: %q", h.Transport)
	}
	// Static fields must be untouched by the adaptive params.
	if h.Server != "103.71.20.24" || h.ServerPort != 443 || h.Path != "/hydra" {
		t.Fatalf("server fields: %s:%v %s", h.Server, h.ServerPort, h.Path)
	}
	if h.TLS == nil || !h.TLS.Enabled || h.TLS.ServerName != "x" {
		t.Fatalf("tls: %+v", h.TLS)
	}
}

// Absent adaptive params parse to zero values: a plain link must produce the
// exact same options object (and the same JSON) as before the feature.
func TestHydraSingboxNoAdaptiveParams(t *testing.T) {
	ob, err := HydraSingbox("hydra://103.71.20.24:44300?pub=AAAA#rtl")
	if err != nil {
		t.Fatal(err)
	}
	h := ob.Options.(*T.HydraOutboundOptions)
	if h.AdaptiveGroup != "" || h.AdaptiveProof != "" || h.AdaptiveProofBytes != 0 ||
		h.AdaptiveInterface != "" || h.AdaptiveDNS != nil || h.Transport != "" {
		t.Fatalf("adaptive fields not zero: %+v", h)
	}
	b, err := json.Marshal(h)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"adaptive_group", "adaptive_proof", "adaptive_dns", "adaptive_interface", "transport"} {
		if bytes.Contains(b, []byte(key)) {
			t.Fatalf("plain link JSON gained key %q: %s", key, b)
		}
	}
}

// at= is a transport override, independent of group membership.
func TestHydraSingboxTransportOverrideSolo(t *testing.T) {
	ob, err := HydraSingbox("hydra://103.71.20.24:44300?pub=AAAA&at=rtc#t")
	if err != nil {
		t.Fatal(err)
	}
	h := ob.Options.(*T.HydraOutboundOptions)
	if h.Transport != "rtc" || h.AdaptiveGroup != "" {
		t.Fatalf("transport/group: %q/%q", h.Transport, h.AdaptiveGroup)
	}
}

// Invalid adaptive values must FAIL the link parse (fail-closed), never
// silently degrade into a half-configured member.
func TestHydraSingboxAdaptiveRejects(t *testing.T) {
	for _, link := range []string{
		"hydra://host:443?pub=AAAA&ag=",                             // empty group id
		"hydra://host:443?pub=AAAA&ag=g1&pa=http://p.example/proof", // not https
		"hydra://host:443?pub=AAAA&ag=g1&pa=not-a-url",              // not a url
		"hydra://host:443?pub=AAAA&ag=g1&pb=1023",                   // below floor
		"hydra://host:443?pub=AAAA&ag=g1&pb=1048577",                // above ceiling
		"hydra://host:443?pub=AAAA&ag=g1&pb=abc",                    // not a number
		"hydra://host:443?pub=AAAA&ag=g1&pi=",                       // empty interface
		"hydra://host:443?pub=AAAA&ag=g1&pd=dns.example.com:53",     // hostname, not ip
		"hydra://host:443?pub=AAAA&ag=g1&pd=9.9.9.9",                // missing port
		"hydra://host:443?pub=AAAA&ag=g1&pd=9.9.9.9:53,",            // empty entry
		"hydra://host:443?pub=AAAA&ag=g1&pd=1.1.1.1:53,1.1.1.2:53,1.1.1.3:53,1.1.1.4:53,1.1.1.5:53,1.1.1.6:53,1.1.1.7:53,1.1.1.8:53,1.1.1.9:53", // 9 entries
		"hydra://host:443?pub=AAAA&at=quic", // unknown transport
		"hydra://host:443?pub=AAAA&at=",     // empty transport
	} {
		if _, err := HydraSingbox(link); err == nil {
			t.Fatalf("must reject: %s", link)
		}
	}
}
