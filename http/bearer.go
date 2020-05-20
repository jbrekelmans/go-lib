package http

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	// AuthenticationSchemeBearer is the Bearer authentication scheme as defined by https://tools.ietf.org/html/rfc6750.
	AuthenticationSchemeBearer = "Bearer"
)

// Matches any ASCII control characters, the double quote and the backslash.
// This regexp matches all invalid characters of the "error" and "error_description" parameters (https://tools.ietf.org/html/rfc6750#section-3).
var regexpCleanRFC26750ErrorDescription = regexp.MustCompile("[\\x00-\\x1F\x22\x5C\\x7F]")

// BearerTokenAuthorizer is a function that authorizes a token.
// If err is nil then data must not be nil.
// Most use-cases where a failed authentication is successfully computed should return an error returned from ErrorInvalidBearerToken.
// data is an unspecified representation of a permissions. See also NewBearerAuthorizer.
type BearerTokenAuthorizer = func(bearerToken string) (data interface{}, err error)

type bearerAuthorizer struct {
	bearerTokenAuthorizer         BearerTokenAuthorizer
	realm                         string
	wwwAuthenticateErrorRealmOnly *WWWAuthenticateError
}

// NewBearerAuthorizer is an Authorizer for the Bearer authentication scheme defined in
// https://tools.ietf.org/html/rfc6750 and defines the authorization of a single realm (https://tools.ietf.org/html/rfc2617).
// See also BearerTokenAuthorizer.
// The returned Authorizer will set the WWW-Authenticate response header if bearerTokenAuthorizer returns an error that is a valid
// *WWWAuthenticateError. Otherwise, an Internal Server Error is written.
func NewBearerAuthorizer(realm string, bearerTokenAuthorizer BearerTokenAuthorizer) (Authorizer, error) {
	if err := ValidateFormattableAsQuotedPair(realm); err != nil {
		return nil, fmt.Errorf("invalid realm: %w", err)
	}
	if bearerTokenAuthorizer == nil {
		return nil, fmt.Errorf("bearerTokenAuthorizer must not be nil")
	}
	b := &bearerAuthorizer{
		bearerTokenAuthorizer: bearerTokenAuthorizer,
		realm:                 realm,
	}
	return b, nil
}

func (b *bearerAuthorizer) Authorize(w http.ResponseWriter, req *http.Request) interface{} {
	authorizationHeaderValues := req.Header[HeaderNameAuthorization]
	if len(authorizationHeaderValues) == 0 {
		bearerWWWAuthenticateResponse(w, "", &Param{Attribute: "realm", Value: b.realm})
		return nil
	}
	if len(authorizationHeaderValues) > 1 {
		error := fmt.Sprintf("request must have exactly one header named %s, but got %d", HeaderNameAuthorization,
			len(authorizationHeaderValues)) // This must comply with https://tools.ietf.org/html/rfc6750#section-3 (i.e. no double quotes)
		bearerWWWAuthenticateResponse(w, error,
			&Param{
				Attribute: "realm",
				Value:     b.realm,
			},
			&Param{
				Attribute: "error_description",
				Value:     error,
			})
		return nil
	}
	authorizationHeaderValue := authorizationHeaderValues[0]
	i := strings.IndexByte(authorizationHeaderValue, ' ')
	if i < 0 {
		bearerWWWAuthenticateResponse(w, "", &Param{Attribute: "realm", Value: b.realm})
		return nil
	}
	authScheme := authorizationHeaderValue[:i]
	// The authentication scheme is case-insensitive: https://tools.ietf.org/html/rfc2617#section-1.2
	if strings.ToLower(authScheme) != strings.ToLower(AuthenticationSchemeBearer) {
		bearerWWWAuthenticateResponse(w, "", &Param{Attribute: "realm", Value: b.realm})
		return nil
	}
	bearerToken := strings.TrimLeft(authorizationHeaderValue[i+1:], " ")
	data, err := b.bearerTokenAuthorizer(bearerToken)
	if err != nil {
		if wwwAuthenticateErr, ok := err.(*WWWAuthenticateError); ok {
			bearerWWWAuthenticateResponseCommon(w, wwwAuthenticateErr, b.realm)
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

func bearerWWWAuthenticateResponse(w http.ResponseWriter, body string, params ...*Param) {
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
	bearerWWWAuthenticateResponseCommon(w, wwwAuthenticateErr, "")
	return
}

func bearerWWWAuthenticateResponseCommon(w http.ResponseWriter, wwwAuthenticateErr *WWWAuthenticateError, defaultRealm string) {
	if err := ValidateBearerChallenge(wwwAuthenticateErr); err != nil {
		log.Errorf("error formatting %s %s response header: %v", HeaderNameWWWAuthenticate, AuthenticationSchemeBearer, err)
		internalServerError(w)
		return
	}
	headerValue, err := wwwAuthenticateErr.HeaderValue(defaultRealm)
	if err != nil {
		log.Errorf("error formatting %s %s response header: %v", HeaderNameWWWAuthenticate, AuthenticationSchemeBearer, err)
		internalServerError(w)
		return
	}
	w.Header().Add(HeaderNameWWWAuthenticate, headerValue)
	http.Error(w, wwwAuthenticateErr.Error(), http.StatusUnauthorized)
}

// ValidateBearerChallenge validates a challenge as per https://tools.ietf.org/html/rfc6750.
func ValidateBearerChallenge(w *WWWAuthenticateError) error {
	if w.challenges == nil {
		return fmt.Errorf(`w must be created through NewWWWAuthenticateError`)
	}
	for i, challenge := range w.challenges {
		if challenge.Scheme != AuthenticationSchemeBearer {
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
					if strings.Contains(scopeValue, "\\\"\t") {
						return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: the scope value %#v has non-visible ASCII `+
							`characters or contains a double quote or backslash`, i, j, scopeValue)
					}
				}
			// the remaining attributes are case-sensitive for the same reason as the scope attribute
			case param.Attribute == "error":
				errorCount++
				if strings.Contains(param.Value, "\\\"\t") {
					return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: attribute "error" has a value %#v that has non-visible ASCII `+
						`characters (except space) or contains a double quote or backslash`, i, j, param.Value)
				}
			case param.Attribute == "error_description":
				errorDescriptionCount++
				if strings.Contains(param.Value, "\\\"\t") {
					return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: attribute "error_description" has a value %#v that has non-visible ASCII `+
						`characters (except space) or contains a double quote or backslash`, i, j, param.Value)
				}
			case param.Attribute == "error_uri":
				errorURICount++
				if strings.Contains(param.Value, "\\\"\t ") {
					return fmt.Errorf(`w.challenges[%d].Params[%d].Value is invalid: attribute "error_uri" has a value %#v that has non-visible ASCII `+
						`characters or contains a double quote or backslash`, i, j, param.Value)
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

func internalServerError(w http.ResponseWriter) {
	code := http.StatusInternalServerError
	http.Error(w, http.StatusText(code), code)
}

// ErrorInvalidBearerToken is convenient wrapper around NewWWWAuthenticateError that is not prone to errors.
func ErrorInvalidBearerToken(error string) *WWWAuthenticateError {
	errorCleaned := regexpCleanRFC26750ErrorDescription.ReplaceAllString(error, "")
	wwwAuthenticateErr, err := NewWWWAuthenticateError(error, []*Challenge{
		{
			Scheme: AuthenticationSchemeBearer,
			Params: []*Param{
				{
					Attribute: "error",
					Value:     "invalid_token",
				},
				{
					Attribute: "error_description",
					Value:     errorCleaned,
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}
	return wwwAuthenticateErr
}
