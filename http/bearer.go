package http

import (
	"fmt"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// AuthenticationSchemeBearer is the Bearer authentication scheme as defined by https://tools.ietf.org/html/rfc6750.
	AuthenticationSchemeBearer = "Bearer"
)

// BearerTokenAuthorizer is a function that authorizes a token.
// If err is nil then data must not be nil.
// data is an unspecified representation of a permissions that is passed along opaquely by the Authorizer returned by NewBearerAuthorizer.
// To set the WWW-Authenticate response header, err should be a *WWWAuthenticateError.
type BearerTokenAuthorizer = func(bearerToken string) (data interface{}, err error)

type bearerAuthorizer struct {
	bearerTokenAuthorizer BearerTokenAuthorizer
}

// NewBearerAuthorizer is an Authorizer that accepts and challenges with the Bearer authentication scheme defined in
// https://tools.ietf.org/html/rfc6750.
// See BearerTokenAuthorizer.
func NewBearerAuthorizer(bearerTokenAuthorizer BearerTokenAuthorizer) (Authorizer, error) {
	if bearerTokenAuthorizer == nil {
		return nil, fmt.Errorf("bearerTokenAuthorizer must not be nil")
	}
	b := &bearerAuthorizer{
		bearerTokenAuthorizer: bearerTokenAuthorizer,
	}
	return b, nil
}

func (b *bearerAuthorizer) Authorize(w http.ResponseWriter, req *http.Request) interface{} {
	authorizationHeaderValues := req.Header[HeaderNameAuthorization]
	if len(authorizationHeaderValues) == 0 {
		bearerWWWAuthenticateResponse(w, fmt.Sprintf("Request is missing required header named %s", HeaderNameAuthorization), "")
		return nil
	}
	if len(authorizationHeaderValues) > 1 {
		bearerWWWAuthenticateResponse(w, fmt.Sprintf("Request must have exactly one header named %s, but got %d", HeaderNameAuthorization,
			len(authorizationHeaderValues)), "")
		return nil
	}
	authorizationHeaderValue := authorizationHeaderValues[0]
	i := strings.IndexByte(authorizationHeaderValue, ' ')
	if i < 0 {
		bearerWWWAuthenticateResponse(w, fmt.Sprintf("Request's %s header must contain a space", HeaderNameAuthorization), "")
		return nil
	}
	authScheme := authorizationHeaderValue[:i]
	if strings.ToLower(authScheme) != strings.ToLower(AuthenticationSchemeBearer) {
		bearerWWWAuthenticateResponse(w,
			fmt.Sprintf("Request's %s header sets unsupported authentication scheme %#v", HeaderNameAuthorization, authScheme),
			"Request's %s header sets an unsupported authentication scheme")
		return nil
	}
	bearerToken := strings.TrimLeft(authorizationHeaderValue[i+1:], " ")
	data, err := b.bearerTokenAuthorizer(bearerToken)
	if err != nil {
		if wwwAuthenticateErr, ok := err.(*WWWAuthenticateError); ok {
			bearerWWWAuthenticateResponseCommon(w, wwwAuthenticateErr)
			return nil
		}
		log.Errorf("error authorizing bearer token: %v", err)
		internalServerError(w)
		return nil
	}
	if data == nil {
		log.Error("BearerTokenAuthorizer illegaly returned nil and a nil error")
		internalServerError(w)
		return nil
	}
	return data
}

func bearerWWWAuthenticateResponse(w http.ResponseWriter, body string, errorDescription string, params ...*Param) {
	if errorDescription == "" {
		errorDescription = body
	}
	params = append(params, &Param{
		Attribute: "error_description",
		Value:     errorDescription,
	})
	wwwAuthenticateErr, err := NewWWWAuthenticateError(body, []*Challenge{
		{
			Scheme: AuthenticationSchemeBearer,
			Params: params,
		},
	})
	if err != nil {
		log.Errorf("error formatting %s response header: %v", HeaderNameWWWAuthenticate, err)
		internalServerError(w)
		return
	}
	bearerWWWAuthenticateResponseCommon(w, wwwAuthenticateErr)
	return
}

func bearerWWWAuthenticateResponseCommon(w http.ResponseWriter, wwwAuthenticateErr *WWWAuthenticateError) {
	if err := ValidateBearerChallenge(wwwAuthenticateErr); err != nil {
		log.Errorf("error formatting %s %s response header: %v", HeaderNameWWWAuthenticate, AuthenticationSchemeBearer, err)
		internalServerError(w)
		return
	}
	w.Header().Add(HeaderNameWWWAuthenticate, wwwAuthenticateErr.headerValue)
	http.Error(w, wwwAuthenticateErr.Error(), http.StatusUnauthorized)
}

// ValidateBearerChallenge validates a challenge as per https://tools.ietf.org/html/rfc6750.
func ValidateBearerChallenge(w *WWWAuthenticateError) error {
	if w.challenges == nil {
		return fmt.Errorf("w must be created through NewWWWAuthenticateError")
	}
	for i, challenge := range w.challenges {
		if strings.ToLower(challenge.Scheme) != strings.ToLower(AuthenticationSchemeBearer) {
			return fmt.Errorf("w.challenges[%d].Scheme (%#v) must be case-insensitive equal to %#v", i, challenge.Scheme,
				AuthenticationSchemeBearer)
		}
		realmCount := 0
		scopeCount := 0
		errorCount := 0
		errorDescriptionCount := 0
		errorURICount := 0
		for j, param := range challenge.Params {
			switch {
			// The realm directive is case-insensitive: https://tools.ietf.org/html/rfc2617#section-1.2
			case strings.ToLower(param.Attribute) == "realm":
				realmCount++
			// scope is case-sensitive
			// https://tools.ietf.org/html/rfc6750#section-1.1
			// > Unless otherwise noted, all the protocol parameter names and values are case sensitive.
			// https://tools.ietf.org/html/rfc6750#section-3
			// does not explicitly say the scope attribute is case-insensitive (but it's values are case-sensitive).
			case param.Attribute == "scope":
				scopeCount++
				// Validate scope as per https://tools.ietf.org/html/rfc6749#section-3.3
				for _, scopeValue := range strings.Split(param.Value, " ") {
					if len(scopeValue) == 0 {
						return fmt.Errorf("w.challenges[%d].Params[%d].Value (%#v) must not be empty and must not contain a substring of two "+
							"space characters", i, j, param.Value)
					}
					if WriteQuotedPairWouldWriteBackslashes(scopeValue) {
						return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: the scope value %#v has non-visible ASCII `+
							`characters or contains a double quote or backslash`, i, j, scopeValue)
					}
				}
			// the remaining attributes are case-sensitive for the same reason as the scope attribute
			case param.Attribute == "error":
				errorCount++
				if WriteQuotedPairWouldWriteBackslashes(param.Value) {
					return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: attribute "error" has a value %#v that has non-visible ASCII `+
						`characters or contains a double quote or backslash`, i, j, param.Value)
				}
			case param.Attribute == "error_description":
				errorDescriptionCount++
				if WriteQuotedPairWouldWriteBackslashes(param.Value) {
					return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: attribute "error_description" has a value %#v that has non-visible ASCII `+
						`characters or contains a double quote or backslash`, i, j, param.Value)
				}
			case param.Attribute == "error_uri":
				errorURICount++
				if strings.Contains(param.Value, ` "\`) {
					return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: attribute "error_uri" has a value %#v that has non-visible ASCII `+
						`characters or contains a space, double quote or backslash`, i, j, param.Value)
				}
			}
		}
		if realmCount > 1 {
			// The realm directive must not appear more than once: https://tools.ietf.org/html/rfc6750#section-3
			return fmt.Errorf(`w.challenges[%d].Params has multiple params with an Attribute case-insensitive equal to "realm"`, i)
		}
		if scopeCount > 1 {
			// The scope attribute must not appear more than once: https://tools.ietf.org/html/rfc6750#section-3
			return fmt.Errorf(`w.challenges[%d].Params has multiple params with Attribute "scope"`, i)
		}
		if errorCount > 1 {
			// The error attribute must not appear more than once: https://tools.ietf.org/html/rfc6750#section-3
			return fmt.Errorf(`w.challenges[%d].Params has multiple params with Attribute "error"`, i)
		}
		if errorDescriptionCount > 1 {
			// The error_description attribute must not appear more than once: https://tools.ietf.org/html/rfc6750#section-3
			return fmt.Errorf(`w.challenges[%d].Params has multiple params with Attribute "error_description"`, i)
		}
		if errorURICount > 1 {
			// The error_uri attribute must not appear more than once: https://tools.ietf.org/html/rfc6750#section-3
			return fmt.Errorf(`w.challenges[%d].Params has multiple params with Attribute "error_uri"`, i)
		}
	}
	return nil
}
