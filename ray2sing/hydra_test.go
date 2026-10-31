package ray2sing

import (
	"strings"
	"testing"
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
	h := ob.Options.(*HydraOutboundOptions)
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
	h := ob.Options.(*HydraOutboundOptions)
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
	h := ob.Options.(*HydraOutboundOptions)
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
	h := ob.Options.(*HydraOutboundOptions)
	if h.Server != "2001:db8::1" {
		t.Fatalf("server: %s", h.Server)
	}
}
