package http

import (
	"fmt"
	"net/http"
	"strings"
)

// WWWAuthenticateError is an error used to control WWW-Authenticate response headers.
type WWWAuthenticateError struct {
	challenges  []*Challenge
	headerValue string
	error       string
}

// NewWWWAuthenticateError returns an error that can be used to control WWW-Authenticate response headers.
// challenges must not be modified after being supplied to this function.
func NewWWWAuthenticateError(error string, challenges []*Challenge) (w *WWWAuthenticateError, err error) {
	if len(challenges) == 0 {
		return nil, fmt.Errorf("challenges must not be nil or empty")
	}
	var headerValue strings.Builder
	for i, challenge := range challenges {
		if challenge == nil {
			return nil, fmt.Errorf("challenges[%d] must not be nil", i)
		}
		scheme, ok := authentiationSchemes[strings.ToLower(challenge.Scheme)]
		if !ok {
			return nil, fmt.Errorf("challenges[%d].Scheme (%#v) is not recognized", i, challenge.Scheme)
		}
		if len(challenge.Params) == 0 {
			return nil, fmt.Errorf("challenges[%d].Params must not be nil or empty", i)
		}
		if i > 0 {
			headerValue.WriteByte(',')
		}
		headerValue.WriteString(scheme)
		headerValue.WriteByte(' ')
		for j, param := range challenge.Params {
			if param == nil {
				return nil, fmt.Errorf("challenges[%d].Params[%d] must not be nil", i, j)
			}
			if j > 0 {
				headerValue.WriteByte(',')
			}
			if !IsToken(param.Attribute) {
				return nil, fmt.Errorf("challenges[%d].Params[%d].Attribute (%#v) is not a valid token", i, j, param.Attribute)
			}
			headerValue.WriteString(param.Attribute)
			headerValue.WriteByte('=')
			if err := WriteQuotedPair(&headerValue, param.Value); err != nil {
				return nil, fmt.Errorf("challenges[%d].Params[%d].Value (%#v) is invalid: %v", i, j, param.Value, err)
			}
		}
	}
	return &WWWAuthenticateError{
		challenges:  challenges,
		headerValue: headerValue.String(),
		error:       error,
	}, nil
}

func (w *WWWAuthenticateError) Error() string {
	return w.error
}

// Challenge is part of a WWWAuthenticate error. See NewWWWAuthenticateError.
type Challenge struct {
	Scheme string
	Params []*Param
}

func internalServerError(w http.ResponseWriter) {
	code := http.StatusInternalServerError
	http.Error(w, http.StatusText(code), code)
}
