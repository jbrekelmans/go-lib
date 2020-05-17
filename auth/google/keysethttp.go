package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/hashicorp/go-cleanhttp"
	"google.golang.org/api/googleapi"

	"github.com/jbrekelmans/go-lib/auth"
)

const (
	// KeySetURL is URL of Google's Key Set.
	KeySetURL = "https://www.googleapis.com/oauth2/v1/certs"
)

type httpsKeySetProvider struct {
	httpClient *http.Client
}

// HTTPSKeySetProvider gets keys from Google's Key Set endpoint (see KeySetURL).
func HTTPSKeySetProvider(httpClient *http.Client) KeySetProvider {
	if httpClient == nil {
		httpClient = cleanhttp.DefaultClient()
	}
	h := &httpsKeySetProvider{
		httpClient: httpClient,
	}
	return h
}

// Get implements KeySetProvider.
func (h *httpsKeySetProvider) Get(ctx context.Context) (KeySet, error) {
	url := KeySetURL
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
	keySetRaw := map[string]string{}
	if err := json.NewDecoder(res.Body).Decode(&keySetRaw); err != nil {
		return nil, fmt.Errorf("GET %s gave response with unexpected JSON: %w", url, err)
	}
	keySet := KeySet{}
	for keyID, certificatePEMString := range keySetRaw {
		certificate, err := auth.ParseCertificate(certificatePEMString)
		if err != nil {
			return nil, fmt.Errorf("GET %s's response body is a JSON object with an entry with key %#v that has a string value, but no PEM "+
				"X509 certificate could be parsed from the value: %w", url, keyID, err)
		}
		keySet[keyID] = certificate
	}
	return keySet, nil
}
