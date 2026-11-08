package ray2sing

import (
	"encoding/base64"
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// defaultHydraPath is the ws path a hydra relay serves when the share link
// carries none.
const defaultHydraPath = "/hydra"

const (
	// hydraProofBytesMin/Max bound the adaptive proof size (pb=) carried by
	// an adaptive-group member link: big enough to measure real throughput,
	// small enough not to cost a mobile plan.
	hydraProofBytesMin = 1024
	hydraProofBytesMax = 1048576
	// hydraMaxPhysDNS caps the physical resolver list (pd=) so one malformed
	// link cannot balloon the physical dialer.
	hydraMaxPhysDNS = 8
)

// HydraOutboundOptions mirrors option.HydraOutboundOptions in the
// hiddify-sing-box fork (branch feat/hydra). It is declared here, field for
// field, because ray2sing must marshal a hydra outbound even when the sing-box
// it compiles against predates the fork type: option.Outbound's marshal path
// merges Type/Tag with whatever Options marshals to and never consults the
// outbound type registry (only unmarshalling does). The embedded DialerOptions
// keep detour chaining and the core's outbound patching working exactly as for
// the fork type.
type HydraOutboundOptions struct {
	T.DialerOptions
	T.ServerOptions
	Pubkey string                `json:"pubkey"`         // server static pubkey, std base64 with padding
	Path   string                `json:"path,omitempty"` // ws path, defaults to defaultHydraPath
	TLS    *T.OutboundTLSOptions `json:"tls,omitempty"`
	// Adaptive-group plumbing, kept in sync with the fork type. See
	// option.HydraOutboundOptions there for the full contract.
	AdaptiveGroup      string   `json:"adaptive_group,omitempty"`
	AdaptiveProof      string   `json:"adaptive_proof,omitempty"`
	AdaptiveProofBytes int      `json:"adaptive_proof_bytes,omitempty"`
	AdaptiveInterface  string   `json:"adaptive_interface,omitempty"`
	AdaptiveDNS        []string `json:"adaptive_dns,omitempty"`
	AdaptiveASN        string   `json:"adaptive_asn,omitempty"`
	Transport          string   `json:"transport,omitempty"`
	// Tuning-axis passthrough, kept in sync with the fork type (same JSON
	// names). Zero value = fork defaults = legacy behavior.
	FragFirstMin        uint32   `json:"frag_first_min,omitempty"`
	FragFirstMax        uint32   `json:"frag_first_max,omitempty"`
	FragRestMin         uint32   `json:"frag_rest_min,omitempty"`
	FragRestMax         uint32   `json:"frag_rest_max,omitempty"`
	FragSplitDelayMs    uint32   `json:"split_delay_ms,omitempty"`
	Disorder            bool     `json:"disorder,omitempty"`
	DisorderDelayMs     uint32   `json:"disorder_delay_ms,omitempty"`
	PadBuckets          []uint32 `json:"pad_buckets,omitempty"`
	MaxPad              uint32   `json:"max_pad,omitempty"`
	BigPadMax           uint32   `json:"big_pad_max,omitempty"`
	RTCChunk            uint32   `json:"rtc_chunk,omitempty"`
	RTCWindow           uint32   `json:"rtc_window,omitempty"`
	RTORtoMinMs         uint32   `json:"rto_min,omitempty"`
	RTORtoMaxMs         uint32   `json:"rto_max,omitempty"`
	RTCBufferCap        uint32   `json:"buffer_cap,omitempty"`
	RTCKeepaliveEveryMs uint32   `json:"keepalive_every,omitempty"`
	TLSFragment         bool     `json:"tls_fragment,omitempty"`
	TLSMinVersion       string   `json:"tls_min_version,omitempty"`
	TLSMaxVersion       string   `json:"tls_max_version,omitempty"`
	TLSALPN             []string `json:"tls_alpn,omitempty"`
}

// HydraSingbox parses a `hydra://` share link into a sing-box hydra outbound.
//
// Link shape:
//
//	hydra://[pubkey@]host[:port][/path]?pub=<base64>&tls=1|0&sni=<sni>#<name>
//
// The pubkey may ride in the query ("pub", takes precedence) or in the
// userinfo. It is accepted as standard or URL-safe base64, padded or not, and
// normalized to padded standard base64. TLS defaults to on for port 443 and
// can be forced with tls=1 / tls=0 (true/false also accepted). The SNI is only
// read from the query — the pub@sni@host userinfo form is deliberately not
// supported. A relay authenticates by its pubkey-bound handshake, so an
// enabled TLS block always carries insecure=true (mirrors the Rust client,
// which never verifies certificates).
//
// Adaptive-group params (all optional, see hydraAdaptiveParams):
//
//	ag=<group-id>&pa=<https-url>&pb=<bytes>&pi=<iface>&pd=<ip:port,...>&at=<wss|rtc>
//
// Tuning-axis params (all optional, see hydraAxisParams; absent/0 = fork
// defaults):
//
//	ffmin/ffmax/frmin/frmax/fsd/dis/disd/pbk/mp/bpm/rcc/rcw/rtomin/rtomax/
//	rbc/rka/tlsfrag/tlsmin/tlsmax/tlsalpn
//
// A link carrying ag= is a candidate member of an adaptive group; the core
// builder merges all members of one group into a single adaptive outbound.
func HydraSingbox(hydraURL string) (*T.Outbound, error) {
	u, err := ParseUrl(hydraURL, 443)
	if err != nil {
		return nil, err
	}
	if u.Hostname == "" {
		return nil, E.New("hydra: missing server host")
	}
	if u.Port == 0 {
		return nil, E.New("hydra: invalid server port")
	}
	if u.PortRange != "" {
		return nil, E.New("hydra: port ranges are not supported")
	}

	// UrlSchema keeps only the decoded basics; the escaped path and the raw
	// userinfo live on the net/url form, so re-parse the raw link once.
	parsedRaw, parseErr := url.Parse(hydraURL)

	pub, err := hydraPubkey(parsedRaw, u)
	if err != nil {
		return nil, err
	}

	tlsOn := u.Port == 443
	if v, ok := u.Params["tls"]; ok {
		switch strings.ToLower(v) {
		case "1", "true":
			tlsOn = true
		case "0", "false":
			tlsOn = false
		default:
			return nil, E.New("hydra: invalid tls flag: ", v)
		}
	}

	var tls *T.OutboundTLSOptions
	if tlsOn {
		tls = &T.OutboundTLSOptions{
			Enabled:    true,
			ServerName: u.Params["sni"],
			Insecure:   true,
		}
	}

	path := defaultHydraPath
	if parseErr == nil && parsedRaw != nil {
		if p := parsedRaw.EscapedPath(); p != "" {
			path = p
			if !strings.HasPrefix(path, "/") {
				path = "/" + path
			}
		}
	}

	group, proof, proofBytes, iface, physDNS, asn, transport, err := hydraAdaptiveParams(u)
	if err != nil {
		return nil, err
	}
	axes, err := hydraAxisParams(u)
	if err != nil {
		return nil, err
	}

	return &T.Outbound{
		Type: "hydra",
		Tag:  u.Name,
		// Use the fork's option type (go.mod replaces sing-box with the
		// hiddify-sing-box fork that defines HydraOutboundOptions). The
		// local mirror type marshals identically, but sing-box's outbound
		// registry type-asserts Options to *option.HydraOutboundOptions
		// when the config is validated/built - a mirror value panics with
		// "interface conversion" and kills the whole subscription parse.
		Options: &T.HydraOutboundOptions{
			ServerOptions:      u.GetServerOption(),
			Pubkey:             pub,
			Path:               path,
			TLS:                tls,
			AdaptiveGroup:      group,
			AdaptiveProof:      proof,
			AdaptiveProofBytes: proofBytes,
			AdaptiveInterface:  iface,
			AdaptiveDNS:        physDNS,
			AdaptiveASN:        asn,
			Transport:          transport,
			// Tuning axes (TUNING.md sweep); zero fields keep the fork's
			// legacy behavior byte-identical.
			FragFirstMin:        axes.firstMin,
			FragFirstMax:        axes.firstMax,
			FragRestMin:         axes.restMin,
			FragRestMax:         axes.restMax,
			FragSplitDelayMs:    axes.splitDelayMs,
			Disorder:            axes.disorder,
			DisorderDelayMs:     axes.disorderDelayMs,
			PadBuckets:          axes.padBuckets,
			MaxPad:              axes.maxPad,
			BigPadMax:           axes.bigPadMax,
			RTCChunk:            axes.rtcChunk,
			RTCWindow:           axes.rtcWindow,
			RTORtoMinMs:         axes.rtoMinMs,
			RTORtoMaxMs:         axes.rtoMaxMs,
			RTCBufferCap:        axes.bufferCap,
			RTCKeepaliveEveryMs: axes.keepaliveEveryMs,
			TLSFragment:         axes.tlsFragment,
			TLSMinVersion:       axes.tlsMinVersion,
			TLSMaxVersion:       axes.tlsMaxVersion,
			TLSALPN:             axes.tlsALPN,
		},
	}, nil
}

// hydraAdaptiveParams parses the OPTIONAL adaptive-group query params of a
// hydra:// link. Every param is independent: absent means unset (zero value),
// but present-and-invalid FAILS the whole link parse (fail-closed) so a
// malformed member can never silently join a group. The settings are carried
// identically on every member link; the core builder rejects a group whose
// members disagree.
//
//	ag=<group-id>   marks the link as a member of an adaptive group
//	pa=<https-url>  group proof URL; must be https with a host
//	pb=<bytes>      group proof size; 1024..1048576 inclusive
//	pi=<name>       physical probe interface name
//	pd=<ip:port,…>  physical resolvers; comma-separated ip:port, max 8
//	asn=<decimal>   provider ASN ordering hint for catalogue recipe expansion
//	at=<wss|rtc>    wire transport override; absent defaults to wss
func hydraAdaptiveParams(u *UrlSchema) (group, proof string, proofBytes int, iface string, physDNS []string, asn string, transport string, err error) {
	if v, ok := u.Params["ag"]; ok {
		group = strings.TrimSpace(v)
		if group == "" {
			return "", "", 0, "", nil, "", "", E.New("hydra: empty adaptive group id (ag)")
		}
	}
	if v, ok := u.Params["pa"]; ok {
		proof = strings.TrimSpace(v)
		pu, perr := url.Parse(proof)
		if perr != nil || pu.Scheme != "https" || pu.Host == "" {
			return "", "", 0, "", nil, "", "", E.New("hydra: adaptive proof url (pa) is not an https url: ", proof)
		}
	}
	if v, ok := u.Params["pb"]; ok {
		n, aerr := strconv.Atoi(strings.TrimSpace(v))
		if aerr != nil || n < hydraProofBytesMin || n > hydraProofBytesMax {
			return "", "", 0, "", nil, "", "", E.New("hydra: adaptive proof bytes (pb) out of range ",
				hydraProofBytesMin, "..", hydraProofBytesMax, ": ", v)
		}
		proofBytes = n
	}
	if v, ok := u.Params["pi"]; ok {
		iface = strings.TrimSpace(v)
		if iface == "" {
			return "", "", 0, "", nil, "", "", E.New("hydra: empty adaptive interface (pi)")
		}
	}
	if v, ok := u.Params["pd"]; ok {
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if _, perr := netip.ParseAddrPort(item); perr != nil {
				return "", "", 0, "", nil, "", "", E.New("hydra: adaptive dns (pd) entry is not ip:port: ", item)
			}
			physDNS = append(physDNS, item)
		}
		if len(physDNS) > hydraMaxPhysDNS {
			return "", "", 0, "", nil, "", "", E.New("hydra: adaptive dns (pd) has more than ",
				hydraMaxPhysDNS, " entries")
		}
	}
	// asn=<decimal AS number> orders catalogue recipe hints for the group.
	// Deliberately permissive (an ordering hint, not security): any value is
	// accepted verbatim; an unknown value simply never matches catalogue
	// hints and expansion falls back to document order.
	if v, ok := u.Params["asn"]; ok {
		asn = strings.TrimSpace(v)
	}
	if v, ok := u.Params["at"]; ok {
		transport = strings.ToLower(strings.TrimSpace(v))
		switch transport {
		case "wss", "rtc":
		default:
			return "", "", 0, "", nil, "", "", E.New("hydra: invalid transport (at): ", v)
		}
	}
	return group, proof, proofBytes, iface, physDNS, asn, transport, nil
}

// hydraAxisParams parses the OPTIONAL tuning-axis query params (TUNING.md
// sweep) of a hydra:// link into the fork's parent passthrough fields. Every
// param is independent: absent or 0 means the fork's default behavior, but
// present-and-invalid FAILS the whole link parse (fail-closed, the same
// contract as hydraAdaptiveParams). Numeric domains mirror the fork's
// catalogue clamps; a link carries operator-approved values, so out-of-range
// numbers are rejected, not clamped.
//
//	ffmin/ffmax   ClientHello first-segment range, 1..64 (bytes)
//	frmin/frmax   following-piece range, 1..96 (bytes)
//	fsd           split pacing, 0..50 (ms; 0 = fork default)
//	dis           disorder trick flag (1/0/true/false)
//	disd          disorder pacing, 0..100 (ms; 0 = fork default 10ms)
//	pbk           pad bucket ladder, comma-separated, each 256..65536,
//	              strictly ascending, max 8 entries (pb= is taken by the
//	              adaptive proof size)
//	mp            per-bucket pad cap, 0..64
//	bpm           big-frame pad bound, 0..4096
//	rcc/rcw       rtc chunk 256..1180 / window 16..1024
//	rtomin/rtomax rtc rto floor 50..500 / ceiling 1000..10000 (ms)
//	rbc           rtc reassembly buffer cap 128..2048
//	rka           rtc keepalive cadence 2000..15000 (ms)
//	tlsfrag       sing-box TLS fragment flag (1/0/true/false)
//	tlsmin/tlsmax TLS version strings (e.g. 1.2, 1.3)
//	tlsalpn       comma-separated ALPN list
func hydraAxisParams(u *UrlSchema) (ax hydraLinkAxes, err error) {
	u32 := func(key string, lo, hi uint64) (uint32, bool, error) {
		v, ok := u.Params[key]
		if !ok {
			return 0, false, nil
		}
		n, aerr := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
		if aerr != nil {
			return 0, false, E.New("hydra: axis ", key, " is not an integer: ", v)
		}
		if n != 0 && (n < lo || n > hi) {
			return 0, false, E.New("hydra: axis ", key, " out of range ", lo, "..", hi, ": ", v)
		}
		return uint32(n), true, nil
	}
	set := func(dst *uint32, key string, lo, hi uint64) error {
		v, _, aerr := u32(key, lo, hi)
		if aerr != nil {
			return aerr
		}
		*dst = v
		return nil
	}
	if err = set(&ax.firstMin, "ffmin", 1, 64); err != nil {
		return
	}
	if err = set(&ax.firstMax, "ffmax", 1, 64); err != nil {
		return
	}
	if err = set(&ax.restMin, "frmin", 1, 96); err != nil {
		return
	}
	if err = set(&ax.restMax, "frmax", 1, 96); err != nil {
		return
	}
	if err = set(&ax.splitDelayMs, "fsd", 0, 50); err != nil {
		return
	}
	if err = set(&ax.disorderDelayMs, "disd", 0, 100); err != nil {
		return
	}
	if err = set(&ax.maxPad, "mp", 0, 64); err != nil {
		return
	}
	if err = set(&ax.bigPadMax, "bpm", 0, 4096); err != nil {
		return
	}
	if err = set(&ax.rtcChunk, "rcc", 256, 1180); err != nil {
		return
	}
	if err = set(&ax.rtcWindow, "rcw", 16, 1024); err != nil {
		return
	}
	if err = set(&ax.rtoMinMs, "rtomin", 50, 500); err != nil {
		return
	}
	if err = set(&ax.rtoMaxMs, "rtomax", 1000, 10000); err != nil {
		return
	}
	if err = set(&ax.bufferCap, "rbc", 128, 2048); err != nil {
		return
	}
	if err = set(&ax.keepaliveEveryMs, "rka", 2000, 15000); err != nil {
		return
	}
	if ax.disorder, err = linkBoolParam(u, "dis"); err != nil {
		return
	}
	if ax.tlsFragment, err = linkBoolParam(u, "tlsfrag"); err != nil {
		return
	}
	if v, ok := u.Params["tlsmin"]; ok {
		ax.tlsMinVersion = strings.TrimSpace(v)
	}
	if v, ok := u.Params["tlsmax"]; ok {
		ax.tlsMaxVersion = strings.TrimSpace(v)
	}
	if v, ok := u.Params["pbk"]; ok {
		var buckets []uint32
		buckets, err = linkPadBuckets(v)
		if err != nil {
			return
		}
		ax.padBuckets = buckets
	}
	if v, ok := u.Params["tlsalpn"]; ok {
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if item != "" {
				ax.tlsALPN = append(ax.tlsALPN, item)
			}
		}
	}
	return
}

// hydraLinkAxes is the parsed tuning-axis payload of one link.
type hydraLinkAxes struct {
	firstMin, firstMax  uint32
	restMin, restMax    uint32
	splitDelayMs        uint32
	disorder            bool
	disorderDelayMs     uint32
	padBuckets          []uint32
	maxPad, bigPadMax   uint32
	rtcChunk, rtcWindow uint32
	rtoMinMs, rtoMaxMs  uint32
	bufferCap           uint32
	keepaliveEveryMs    uint32
	tlsFragment         bool
	tlsMinVersion       string
	tlsMaxVersion       string
	tlsALPN             []string
}

// linkBoolParam parses a boolean flag param (1/0/true/false, case-insensitive).
func linkBoolParam(u *UrlSchema, key string) (bool, error) {
	v, ok := u.Params[key]
	if !ok {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true":
		return true, nil
	case "0", "false":
		return false, nil
	}
	return false, E.New("hydra: axis ", key, " must be 1/0/true/false: ", v)
}

// linkPadBuckets parses the pbk= ladder: comma-separated integers, each
// 256..65536, strictly ascending, at most 8 entries (amplification bound).
func linkPadBuckets(v string) ([]uint32, error) {
	var buckets []uint32
	prev := uint64(0)
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		n, aerr := strconv.ParseUint(item, 10, 32)
		if aerr != nil {
			return nil, E.New("hydra: axis pbk entry is not an integer: ", item)
		}
		if n < 256 || n > 65536 {
			return nil, E.New("hydra: axis pbk entry out of range 256..65536: ", item)
		}
		if n <= prev {
			return nil, E.New("hydra: axis pbk must be strictly ascending at: ", item)
		}
		prev = n
		buckets = append(buckets, uint32(n))
	}
	if len(buckets) > 8 {
		return nil, E.New("hydra: axis pbk has more than 8 entries")
	}
	return buckets, nil
}

// hydraPubkey extracts and normalizes the relay pubkey.
func hydraPubkey(parsedRaw *url.URL, u *UrlSchema) (string, error) {
	pub := u.Params["pub"]
	if pub == "" && parsedRaw != nil {
		// Do NOT read u.Username: ParseUrl rewrites a base64-looking username
		// that decodes to "a:b" into user+password, which would silently
		// corrupt a pubkey. Re-read the userinfo from the raw link instead.
		if parsedRaw.User != nil {
			pub = parsedRaw.User.Username()
		}
	}
	// A '+' in the query arrives percent-decoded as a space (url.ParseQuery
	// treats '+' as form-encoding), and spaces never occur in base64. Repair
	// BEFORE trimming: TrimSpace would eat a leading space that used to be a
	// '+' (e.g. "pub=+/8=" -> " /8=" -> "/8=", corrupting the key).
	pub = strings.ReplaceAll(pub, " ", "+")
	pub = strings.TrimSpace(pub)
	if pub == "" {
		return "", E.New("hydra: missing pubkey")
	}
	decoded, err := decodeBase64FaultTolerant(pub)
	if err != nil {
		return "", E.New("hydra: pubkey is not valid base64: ", pub)
	}
	return base64.StdEncoding.EncodeToString([]byte(decoded)), nil
}
