package http

import (
	"net/http"
	"strings"
)

const (
	// HeaderNameAuthorization is the name of the Authorization header
	HeaderNameAuthorization = "Authorization"
	// HeaderNameWWWAuthenticate is the name of the WWW-Authenticate header
	HeaderNameWWWAuthenticate = "WWW-Authenticate"
)

var authentiationSchemes = map[string]string{
	strings.ToLower(AuthenticationSchemeBearer): AuthenticationSchemeBearer,
}

// AuthenticationSchemes returns all known authentication schemes.
func AuthenticationSchemes() []string {
	s := make([]string, len(authentiationSchemes))
	i := 0
	for _, v := range authentiationSchemes {
		s[i] = v
		i++
	}
	return s
}

// Authorizer is a service that authorizes requests.
type Authorizer interface {
	// data is nil if and only if a response has been written to w.
	// If data is nil then typically the response has status code 401, 403 or 407.
	// data is an unspecified representation of permissions associated with the request.
	Authorize(w http.ResponseWriter, req *http.Request) (data interface{})
}
