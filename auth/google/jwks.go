package google

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-cleanhttp"
	"google.golang.org/api/googleapi"

	"github.com/jbrekelmans/go-lib/auth"
	"github.com/jbrekelmans/go-lib/auth/jose"
)

const (
	// JWKSURL is URL of Google's JWKS.
	JWKSURL = "https://www.googleapis.com/oauth2/v1/certs"
)

type httpsJWKSProvider struct {
	httpClient *http.Client
}

// HTTPSJWKSProvider gets keys from Google's JWKS endpoint (see JWKSURL).
func HTTPSJWKSProvider(httpClient *http.Client) jose.JWKSProvider {
	if httpClient == nil {
		httpClient = cleanhttp.DefaultClient()
	}
	h := &httpsJWKSProvider{
		httpClient: httpClient,
	}
	return h
}

// Get implements jose.JWKSProvider.
func (h *httpsJWKSProvider) Get(ctx context.Context, keyID string) (*x509.Certificate, error) {
	url := JWKSURL
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request GET %s: %w", url, err)
	}
	res, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error doing GET %s: %w", url, err)
	}
	defer res.Body.Close()
	if err := googleapi.CheckResponse(res); err != nil {
		return nil, fmt.Errorf("GET %s gave unexpected response: %w", url, err)
	}
	jwks := map[string]string{}
	if err := json.NewDecoder(res.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("GET %s gave response with unexpected JSON: %w", url, err)
	}
	certificatePEMString, ok := jwks[keyID]
	if !ok {
		return nil, fmt.Errorf("GET %s's response body is a JSON object but the object does not have an entry with key %#v", url, keyID)
	}
	certificate, err := auth.ParseCertificate(certificatePEMString)
	if err != nil {
		return nil, fmt.Errorf("GET %s's response body is a JSON object with an entry with key %#v that has a string value, but no PEM "+
			"X509 certificate could be parsed from the value: %w", url, keyID, err)
	}
	return certificate, nil
}
