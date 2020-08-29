package http

import (
	"fmt"
	"strings"
)

// WWWAuthenticateError is an error used to control WWW-Authenticate response headers.
type WWWAuthenticateError struct {
	challenges []*Challenge
	error      string
}

// NewWWWAuthenticateError returns an error that can be used to control WWW-Authenticate response headers.
// challenges must not be modified after being supplied to this function.
// Most developers will want to use ErrorInvalidBearerToken instead of this function.
func NewWWWAuthenticateError(error string, challenges []*Challenge) (w *WWWAuthenticateError, err error) {
	if len(challenges) == 0 {
		return nil, fmt.Errorf("challenges must not be nil or empty")
	}
	for i, challenge := range challenges {
		if challenge == nil {
			return nil, fmt.Errorf("challenges[%d] must not be nil", i)
		}
		if !IsToken(challenge.Scheme) {
			return nil, fmt.Errorf("challenges[%d].Scheme (%#v) is not a valid token", i, challenge.Scheme)
		}
		if challenge.Token68 == "" && len(challenge.Params) == 0 {
			return nil, fmt.Errorf("challenges[%d] is invalid: .Token68 must not be empty or .Params must not be nil or empty", i)
		} else if challenge.Token68 != "" && len(challenge.Params) > 0 {
			return nil, fmt.Errorf("challenges[%d] is invalid: either .Token68 must be empty or .Params must not be empty", i)
		}
		if challenge.Token68 != "" && !IsToken68(challenge.Token68) {
			return nil, fmt.Errorf("challenges[%d].Token68 is invalid", i)
		}
		for j, param := range challenge.Params {
			if param == nil {
				return nil, fmt.Errorf("challenges[%d].Params[%d] must not be nil", i, j)
			}
			if !IsToken(param.Attribute) {
				return nil, fmt.Errorf("challenges[%d].Params[%d].Attribute (%#v) is not a valid token", i, j, param.Attribute)
			}
			if ValidateFormattableAsQuotedPair(param.Value); err != nil {
				return nil, fmt.Errorf("challenges[%d].Params[%d].Value (%#v) is invalid: %w", i, j, param.Value, err)
			}
		}
	}
	return &WWWAuthenticateError{
		challenges: challenges,
		error:      error,
	}, nil
}

func (w *WWWAuthenticateError) Error() string {
	return w.error
}

// HeaderValue formts the challenges represented by w into a single header value.
// If a challenge does not have a realm then a realm is added and set to defaultRealm (even if defaultRealm is an empty string).
func (w *WWWAuthenticateError) HeaderValue(defaultRealm string) (string, error) {
	if w.challenges == nil {
		return "", fmt.Errorf(`w must be created through NewWWWAuthenticateError`)
	}
	if err := ValidateFormattableAsQuotedPair(defaultRealm); err != nil {
		return "", fmt.Errorf("invalid defaultRealm: %w", err)
	}
	var headerValue strings.Builder
	for i, challenge := range w.challenges {
		if i > 0 {
			headerValue.WriteByte(',')
		}
		headerValue.WriteString(challenge.Scheme)
		headerValue.WriteByte(' ')
		if challenge.Token68 != "" {
			headerValue.WriteString(challenge.Token68)
		} else {
			hasRealm := false
			for _, param := range challenge.Params {
				if strings.EqualFold(param.Attribute, "realm") {
					hasRealm = true
					break
				}
			}
			if !hasRealm {
				headerValue.WriteString("realm=")
				_ = WriteQuotedPair(&headerValue, defaultRealm)
			}
			for j, param := range challenge.Params {
				if j > 0 || !hasRealm {
					headerValue.WriteByte(',')
				}
				headerValue.WriteString(param.Attribute)
				headerValue.WriteByte('=')
				// NewWWWAuthenticateError ensures this cannot error.
				_ = WriteQuotedPair(&headerValue, param.Value)
			}
		}
	}
	return headerValue.String(), nil
}

// Challenge is part of a WWWAuthenticate error. See NewWWWAuthenticateError.
type Challenge struct {
	Scheme  string
	Params  []*Param
	Token68 string
}
