package http

import (
	"net/http"
)

// Authorizer is a service that authorizes requests.
type Authorizer interface {
	// data is nil if and only if a response has been written to w.
	// If data is nil then typically the response has status code 401, 403 or 407.
	// data is an unspecified representation of permissions associated with the request.
	Authorize(w http.ResponseWriter, req *http.Request) (data interface{})
}
