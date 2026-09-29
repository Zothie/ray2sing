package ray2sing

import (
	"strconv"
	"strings"
	"time"

	T "github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
)

func Hysteria2Singbox(hysteria2Url string) (*T.Outbound, error) {
	u, err := ParseUrl(hysteria2Url, 443)
	if err != nil {
		return nil, err
	}
	decoded := u.Params
	var ObfsOpts *T.Hysteria2Obfs
	ObfsOpts = nil
	if obfs, ok := decoded["obfs"]; ok && obfs != "" {
		ObfsOpts = &T.Hysteria2Obfs{
			Type:     obfs,
			// ParseUrl normalises "-" and "_" in query keys to a space, so the
			// standard "obfs-password" arrives as "obfs password". Reading only
			// the dashed key left the salamander password empty and the core
			// refused the outbound ("missing obfs password").
			Password: firstNonEmpty(decoded["obfs password"], decoded["obfs-password"], decoded["obfspassword"]),
		}
	}

	valECH, hasECH := decoded["ech"]
	hasECH = hasECH && (valECH != "0")
	var ECHOpts *T.OutboundECHOptions
	ECHOpts = nil
	if hasECH {
		ECHOpts = &T.OutboundECHOptions{
			Enabled: hasECH,
		}
	}

	var hopPorts badoption.Listable[string]
	var hopInterval badoption.Duration
	if u.PortRange != "" {
		// sing-quic's ParsePorts requires a COLON separator ("20000:40000");
		// a dash makes NewClient fail and the outbound never constructs — worse
		// than the silent single-port fallback this replaced. Links in the wild
		// use a dash, so translate it here.
		hopPorts = badoption.Listable[string]{strings.Replace(u.PortRange, "-", ":", 1)}
		// Default to 30s when the link does not say; matches common practice.
		secs := 30
		if v, ok := decoded["hopinterval"]; ok && v != "" {
			if n, err := strconv.Atoi(strings.TrimSuffix(v, "s")); err == nil && n > 0 {
				secs = n
			}
		}
		hopInterval = badoption.Duration(time.Duration(secs) * time.Second)
	}

	SNI := decoded["sni"]
	if SNI == "" {
		SNI = decoded["hostname"]
	}
	// turnRelay, err := u.GetRelayOptions()
	// if err != nil {
	// 	return nil, err
	// }
	pass := u.Username
	if u.Password != "" {
		pass += ":" + u.Password
	}
	result := T.Outbound{
		Type: "hysteria2",
		Tag:  u.Name,
		Options: &T.Hysteria2OutboundOptions{
			ServerOptions: u.GetServerOption(),
			// Carry port hopping through. Without this the range in the link is
			// discarded and the client pins one port — losing the entire point
			// of hopping, which is that a per-port block cannot catch a client
			// spread across thousands of them.
			ServerPorts: hopPorts,
			HopInterval: hopInterval,
			Obfs:        ObfsOpts,
			Password:    pass,
			// The relay's uplink goes silent for ~30 s at a time (measured:
			// 28 s inbound-UDP blackouts every 20-60 min, hitting every client
			// at once). sing-quic's default 30 s idle timeout is exactly the
			// length of such a hole, so the session died on every one of them
			// while the server, at 120 s, would have kept it. Match the server
			// and probe often enough that a single lost keepalive is not fatal.
			QUICOptions: T.QUICOptions{
				HTTP2Options: T.HTTP2Options{
					IdleTimeout:     badoption.Duration(120 * time.Second),
					KeepAlivePeriod: badoption.Duration(8 * time.Second),
				},
			},
			OutboundTLSOptionsContainer: T.OutboundTLSOptionsContainer{
				TLS: &T.OutboundTLSOptions{
					Enabled:    true,
					Insecure:   decoded["insecure"] == "1",
					DisableSNI: isIPOnly(SNI),
					ServerName: SNI,
					ECH:        ECHOpts,
				},
			},
			// TurnRelay: turnRelay,
		},
	}

	return &result, nil
}
