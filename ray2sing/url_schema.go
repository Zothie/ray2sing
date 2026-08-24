package ray2sing

import (
	"net/url"
	"regexp"
	"strings"

	T "github.com/sagernet/sing-box/option"
)

// HysteriaURLData holds the parsed data from a Hysteria URL.
type UrlSchema struct {
	Scheme    string
	Username  string
	Password  string
	Hostname  string
	Port      uint16
	PortRange string
	Name      string
	Params    map[string]string
}

func (u UrlSchema) GetServerOption() T.ServerOptions {
	return T.ServerOptions{
		Server:     u.Hostname,
		ServerPort: u.Port,
	}
}

// func (u UrlSchema) GetRelayOptions() (*T.TurnRelayOptions, error) {
// 	return ParseTurnURL(u.Params["relay"])
// }

// parseHysteria2 parses a given URL and returns a HysteriaURLData struct.

// liftPortRange rewrites "host:20000-40000" to "host:20000" so url.Parse
// accepts it, returning the original range separately. Ports are the only
// place a dash can appear between the last colon and the following delimiter,
// so this cannot corrupt a hostname or a password.
func liftPortRange(raw string) (string, string) {
	schemeEnd := strings.Index(raw, "://")
	if schemeEnd < 0 {
		return raw, ""
	}
	rest := raw[schemeEnd+3:]
	authEnd := len(rest)
	for _, sep := range []string{"/", "?", "#"} {
		if i := strings.Index(rest, sep); i >= 0 && i < authEnd {
			authEnd = i
		}
	}
	authority := rest[:authEnd]
	host := authority
	if at := strings.LastIndex(authority, "@"); at >= 0 {
		host = authority[at+1:]
	}
	colon := strings.LastIndex(host, ":")
	if colon < 0 {
		return raw, ""
	}
	port := host[colon+1:]
	dash := strings.Index(port, "-")
	if dash <= 0 {
		return raw, ""
	}
	first := port[:dash]
	fixed := raw[:schemeEnd+3] + strings.Replace(authority, ":"+port, ":"+first, 1) + rest[authEnd:]
	return fixed, port
}

func ParseUrl(inputURL string, defaultPort uint16) (*UrlSchema, error) {
	// url.Parse rejects a port RANGE outright ("invalid port"), so the range
	// must be lifted out BEFORE parsing — otherwise a Hysteria2 port-hopping
	// link is dropped from the subscription entirely and the user silently
	// loses the profile.
	inputURL, liftedRange := liftPortRange(inputURL)

	parsedURL, err := url.Parse(inputURL)
	if err != nil {
		return nil, err
	}
	// A port RANGE like 20000-40000 is how Hysteria2 expresses port hopping.
	// url.Port() returns it verbatim and the numeric parse fails, silently
	// falling back to the default port — which drops the profile's whole reason
	// for existing. Keep the range and use its first port as the dial target.
	rawPort := parsedURL.Port()
	portRange := liftedRange
	if i := strings.Index(rawPort, "-"); i > 0 {
		portRange = rawPort
		rawPort = rawPort[:i]
	}
	port := toUInt16(rawPort, defaultPort)

	data := &UrlSchema{
		Scheme:    parsedURL.Scheme,
		Username:  parsedURL.User.Username(),
		Password:  getPassword(parsedURL),
		Hostname:  parsedURL.Hostname(),
		Port:      port,
		PortRange: portRange,
		Name:      parsedURL.Fragment,
		Params:    make(map[string]string),
	}
	if isBase64CharsOnly(data.Username) {
		userInfo, err := decodeBase64IfNeeded(data.Username)

		// fmt.Print(userInfo)
		if err == nil && isValidChar(userInfo) {
			// If decoding is successful, use the decoded string
			userDetails := strings.Split(userInfo, ":")
			if len(userDetails) == 2 {
				data.Username = userDetails[0]
				data.Password = userDetails[1]
			}
		}
	}

	for key, values := range parsedURL.Query() {
		data.Params[normalizeStr(key)] = strings.Join(values, ",")
	}

	return data, nil
}

func normalizeStr(ss string) string {
	s := strings.ToLower(strings.TrimSpace(ss))
	for _, r := range []string{"_", "-"} {
		s = strings.ReplaceAll(s, r, " ")

	}
	return s
}

func getPassword(u *url.URL) string {
	if password, ok := u.User.Password(); ok {
		return password
	}
	return ""
}

var base64CharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=]+$`)

func isBase64CharsOnly(s string) bool {
	return base64CharRegex.MatchString(s)
}

var validCharRegex = regexp.MustCompile(`^[A-Za-z0-9+/=_)(: !~@#$%^&*-]+$`)

func isValidChar(s string) bool {

	return validCharRegex.MatchString(s)
}
