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
	Transport          string   `json:"transport,omitempty"`
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

	group, proof, proofBytes, iface, physDNS, transport, err := hydraAdaptiveParams(u)
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
			Transport:          transport,
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
//	at=<wss|rtc>    wire transport override; absent defaults to wss
func hydraAdaptiveParams(u *UrlSchema) (group, proof string, proofBytes int, iface string, physDNS []string, transport string, err error) {
	if v, ok := u.Params["ag"]; ok {
		group = strings.TrimSpace(v)
		if group == "" {
			return "", "", 0, "", nil, "", E.New("hydra: empty adaptive group id (ag)")
		}
	}
	if v, ok := u.Params["pa"]; ok {
		proof = strings.TrimSpace(v)
		pu, perr := url.Parse(proof)
		if perr != nil || pu.Scheme != "https" || pu.Host == "" {
			return "", "", 0, "", nil, "", E.New("hydra: adaptive proof url (pa) is not an https url: ", proof)
		}
	}
	if v, ok := u.Params["pb"]; ok {
		n, aerr := strconv.Atoi(strings.TrimSpace(v))
		if aerr != nil || n < hydraProofBytesMin || n > hydraProofBytesMax {
			return "", "", 0, "", nil, "", E.New("hydra: adaptive proof bytes (pb) out of range ",
				hydraProofBytesMin, "..", hydraProofBytesMax, ": ", v)
		}
		proofBytes = n
	}
	if v, ok := u.Params["pi"]; ok {
		iface = strings.TrimSpace(v)
		if iface == "" {
			return "", "", 0, "", nil, "", E.New("hydra: empty adaptive interface (pi)")
		}
	}
	if v, ok := u.Params["pd"]; ok {
		for _, item := range strings.Split(v, ",") {
			item = strings.TrimSpace(item)
			if _, perr := netip.ParseAddrPort(item); perr != nil {
				return "", "", 0, "", nil, "", E.New("hydra: adaptive dns (pd) entry is not ip:port: ", item)
			}
			physDNS = append(physDNS, item)
		}
		if len(physDNS) > hydraMaxPhysDNS {
			return "", "", 0, "", nil, "", E.New("hydra: adaptive dns (pd) has more than ",
				hydraMaxPhysDNS, " entries")
		}
	}
	if v, ok := u.Params["at"]; ok {
		transport = strings.ToLower(strings.TrimSpace(v))
		switch transport {
		case "wss", "rtc":
		default:
			return "", "", 0, "", nil, "", E.New("hydra: invalid transport (at): ", v)
		}
	}
	return group, proof, proofBytes, iface, physDNS, transport, nil
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
	pub = strings.TrimSpace(pub)
	if pub == "" {
		return "", E.New("hydra: missing pubkey")
	}
	// A '+' in the query arrives percent-decoded as a space (url.ParseQuery
	// treats '+' as form-encoding), and spaces never occur in base64.
	pub = strings.ReplaceAll(pub, " ", "+")
	decoded, err := decodeBase64FaultTolerant(pub)
	if err != nil {
		return "", E.New("hydra: pubkey is not valid base64: ", pub)
	}
	return base64.StdEncoding.EncodeToString([]byte(decoded)), nil
}
