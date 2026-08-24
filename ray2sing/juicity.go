package ray2sing

import (
	T "github.com/sagernet/sing-box/option"
)

// JuicitySingbox parses a `juicity://` share link into a sing-box juicity
// outbound.
//
// WHY juicity is supported at all: it is a third QUIC transport alongside
// TUIC and Hysteria2. DPI that fingerprints those two individually does not
// take juicity down with them, so subscriptions can carry a juicity fallback.
// The outbound type itself is fork-local (upstream sing-box issue #788 was
// never merged) — see protocol/juicity in the hiddify-sing-box fork.
//
// Link shape (from juicity's own `generate-sharelink`):
//
//	juicity://uuid:password@host:port?congestion_control=bbr&sni=www.example.com
//	    &allow_insecure=0&pinned_certchain_sha256=<base64>
func JuicitySingbox(juicityUrl string) (*T.Outbound, error) {
	u, err := ParseUrl(juicityUrl, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params

	// ParseUrl normalizes query keys: lowercased, with "_" and "-" turned into
	// spaces. So `congestion_control` arrives as "congestion control".
	congestion := decoded["congestion control"]
	if congestion == "" {
		congestion = "bbr" // juicity's own default
	}

	// A private relay almost always uses a self-signed certificate. juicity
	// handles that with a certificate-chain pin rather than by disabling
	// verification, so honour the pin when the link carries one.
	pin := decoded["pinned certchain sha256"]

	result := T.Outbound{
		Type: "juicity",
		Tag:  u.Name,
		Options: &T.JuicityOutboundOptions{
			ServerOptions:         u.GetServerOption(),
			UUID:                  u.Username,
			Password:              u.Password,
			CongestionControl:     congestion,
			PinnedCertchainSha256: pin,
			OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
				TLS: &T.OutboundTLSOptions{
					Enabled:    true,
					DisableSNI: decoded["sni"] == "",
					ServerName: decoded["sni"],
					// A pinned chain implies the stdlib verifier must stand
					// down; juicity verifies the pin itself.
					Insecure: pin != "" ||
						decoded["allow insecure"] == "1" ||
						decoded["insecure"] == "1",
					ALPN: []string{"h3"},
				},
			},
		},
	}

	return &result, nil
}
