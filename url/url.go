package url

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

var schemeDefaultPorts = map[string]int{
	"http":   80,
	"https":  443,
	"socks5": 1080,
	"ws":     80,
	"wss":    443,
}

// SchemeDefaultPorts returns the default port for scheme s.
// If no default port is defined for scheme s then returns -1.
func SchemeDefaultPorts(s string) int {
	defaultPort, ok := schemeDefaultPorts[s]
	if !ok {
		return -1
	}
	return defaultPort
}

// NewBool returns a pointer to a boolean with value b.
func NewBool(b bool) *bool {
	return &b
}

// NormalizePort normalizes the port of u.
// If u's port is the default port for scheme u.Scheme and preferExplicitPort is false then u's port is removed.
// If u does not have a port and preferExplicitPort is true then u's port is set to the default port for scheme u.Scheme.
// The default port for scheme x is defined by schemeDefaultPorts(x).
// If schemeDefaultPorts does not define a port of scheme x then it should return -1.
// If schemeDefaultPorts(u.Scheme) < 0 then NormalizePort returns an error (because the default port is undefined).
// If schemeDefaultPorts is nil then NormalizePort behaves as if schemeDefaultPorts is set to SchemeDefaultPorts.
// If u is not absolute then NormalizePort does not modify u.
func NormalizePort(u *url.URL, preferExplicitPort bool, schemeDefaultPorts func(scheme string) int) error {
	if u == nil {
		return fmt.Errorf("u must not be nil")
	}
	if schemeDefaultPorts == nil {
		schemeDefaultPorts = SchemeDefaultPorts
	}
	if !u.IsAbs() {
		return nil
	}
	portStr := u.Port()
	if portStr == "" {
		if !preferExplicitPort {
			return nil
		}
		defaultPort := schemeDefaultPorts(u.Scheme)
		if defaultPort < 0 {
			return fmt.Errorf("no default port is defined for scheme %#v", u.Scheme)
		}
		u.Host += fmt.Sprintf(":%d", defaultPort)
		return nil
	}
	portInt64, err := strconv.ParseInt(portStr, 10, 32)
	if err != nil {
		return fmt.Errorf("error parsing port %#v as int32: %w", portStr, err)
	}
	// portInt64 must be >= 0 by definition of u.Port()
	portInt := int(portInt64)
	defaultPort := schemeDefaultPorts(u.Scheme)
	if defaultPort < 0 {
		return fmt.Errorf("no default port is defined for scheme %#v", u.Scheme)
	}
	i := strings.LastIndexByte(u.Host, ':')
	// i must be >= 0 otherwise portStr would have been ""
	if defaultPort == portInt {
		if !preferExplicitPort {
			// Remove port...
			u.Host = u.Host[:i]
			// NOTE: we cannot do u.Host = u.Hostname() because this would remove square brackets around IPv6 addresses.
			return nil
		}
	}
	// Remove leading zeros from port
	u.Host = fmt.Sprintf("%s:%d", u.Host[:i], portInt)
	return nil
}

// ValidateURLOptions represents a set of URL validation options accepted by ValidateURL.
type ValidateURLOptions struct {
	Abs                                      *bool
	AllowedSchemes                           []string
	NormalizePort                            *bool
	SchemeDefaultPorts                       func(scheme string) int
	StripFragment                            bool
	StripQuery                               bool
	StripPathTrailingSlashes                 bool
	StripPathTrailingSlashesNoPercentEncoded bool
	StripUser                                bool
	StripUserPassword                        bool
	User                                     *bool
	UserPassword                             *bool
}

// ValidateURL parses and validates a URI/URL.
// Let u be the *url.URL as defined by url.Parse(s).
// ValidateURL returns u if and only if no error occurs.
// If opts.Abs != nil and u.IsAbs() != *opts.Abs then an error is returned.
// If len(opts.AllowedSchemes) > 0 and !u.IsAbs() and u.Scheme is not in opts.AllowedSchemes then an error is returned.
// If opts.NormalizePort != nil then ValidateURL calls NormalizePort(u, *opts.NormalizePort, opts.SchemeDefaultPorts).
// If opts.StripPathTrailingSlashes then the longest trailing sequence of forward slashes is trimmed from u.Path and u.RawPath.
// 		Unless opts.StripPathTrailingSlashesNoPercentEncoded is true, percent encoded forward slashes are also included in this sequence.
// For other options see source code.
func ValidateURL(s string, opts ValidateURLOptions) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	if u.IsAbs() {
		if opts.Abs != nil && !*opts.Abs {
			return nil, fmt.Errorf("value (%#v) must be a relative URI", toStringMaskPassword(u))
		}
		if len(opts.AllowedSchemes) > 0 {
			found := false
			for _, scheme := range opts.AllowedSchemes {
				if scheme == u.Scheme {
					found = true
					break
				}
			}
			if !found {
				var sb strings.Builder
				n := len(opts.AllowedSchemes)
				if n > 1 {
					_, _ = fmt.Fprintf(&sb, "one of %#v", opts.AllowedSchemes[0])
					for i := 1; i < n-1; i++ {
						_, _ = fmt.Fprintf(&sb, ", %#v", opts.AllowedSchemes[i])
					}
					_, _ = fmt.Fprintf(&sb, " and %#v", opts.AllowedSchemes[n-1])
				} else {
					_, _ = fmt.Fprintf(&sb, "%#v", opts.AllowedSchemes[0])
				}
				return nil, fmt.Errorf("URL's scheme must be %s but got %#v", sb.String(), u.Scheme)
			}
		}
		if opts.NormalizePort != nil {
			if err := NormalizePort(u, *opts.NormalizePort, opts.SchemeDefaultPorts); err != nil {
				return nil, err
			}
		}
		if opts.User != nil {
			if *opts.User {
				if u.User == nil {
					return nil, fmt.Errorf("value (%#v) is a valid URL but it must have a userinfo component", toStringMaskPassword(u))
				}
			} else if u.User != nil {
				return nil, fmt.Errorf("value (%#v) is a valid URL but it must NOT have a userinfo component", toStringMaskPassword(u))
			}
		}
		if opts.UserPassword != nil {
			hasPassword := false
			if u.User != nil {
				_, hasPassword = u.User.Password()
			}
			if *opts.UserPassword {
				if !hasPassword {
					return nil, fmt.Errorf("value (%#v) is a valid URL but it must have a userinfo component with a password", toStringMaskPassword(u))
				}
			} else if hasPassword {
				return nil, fmt.Errorf("value (%#v) is a valid URL but it must NOT have a userinfo component with a password", toStringMaskPassword(u))
			}
		}
	} else {
		if opts.Abs != nil && *opts.Abs {
			return nil, fmt.Errorf("value (%#v) is a valid URI but is not absolute", toStringMaskPassword(u))
		}
	}
	if opts.StripPathTrailingSlashes {
		if u.RawPath != "" {
			n2 := len(u.Path)
			n3 := len(u.RawPath)
			for n2 > 0 && u.Path[n2-1] == '/' {
				if n3 >= 3 {
					percentEncodedSeq := u.RawPath[n3-3 : n3]
					if percentEncodedSeq == "%2F" || percentEncodedSeq == "%2f" {
						if opts.StripPathTrailingSlashesNoPercentEncoded {
							break
						}
						n2--
						n3 -= 3
						continue
					}
					// RawPath[n3 - 1:n3] == "/"
				}
				n2--
				n3--
			}
			u.Path = u.Path[:n2]
			u.RawPath = u.RawPath[:n3]
		} else {
			n := len(u.Path)
			for n > 0 && u.Path[n-1] == '/' {
				n--
			}
			u.Path = u.Path[:n]
		}
	}
	if opts.StripFragment {
		u.Fragment = ""
	}
	if opts.StripQuery {
		u.ForceQuery = false
		u.RawQuery = ""
	}
	if opts.StripUser {
		u.User = nil
	}
	if opts.StripUserPassword {
		if u.User != nil {
			_, hasPassword := u.User.Password()
			if hasPassword {
				u.User = url.User(u.User.Username())
			}
		}
	}
	return u, nil
}

func toStringMaskPassword(u *url.URL) string {
	uClone := *u
	if uClone.User != nil {
		_, hasPassword := uClone.User.Password()
		if hasPassword {
			uClone.User = url.UserPassword(uClone.User.Username(), "********")
		}
	}
	return uClone.String()
}
