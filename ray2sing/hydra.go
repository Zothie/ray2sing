package ray2sing

import (
	"encoding/base64"
	"net/url"
	"strings"

	T "github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

// defaultHydraPath is the ws path a hydra relay serves when the share link
// carries none.
const defaultHydraPath = "/hydra"

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
	Pubkey string                `json:"pubkey"`          // server static pubkey, std base64 with padding
	Path   string                `json:"path,omitempty"`  // ws path, defaults to defaultHydraPath
	TLS    *T.OutboundTLSOptions `json:"tls,omitempty"`
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

	return &T.Outbound{
		Type: "hydra",
		Tag:  u.Name,
		Options: &HydraOutboundOptions{
			ServerOptions: u.GetServerOption(),
			Pubkey:        pub,
			Path:          path,
			TLS:           tls,
		},
	}, nil
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
