package jose

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jbrekelmans/go-lib/auth"
)

const (
	// DefaultJWTClaimsLeeway is a common default for JWT claims leeway.
	// Leeway is defined by https://godoc.org/gopkg.in/square/go-jose.v2/jwt#Claims.ValidateWithLeeway.
	DefaultJWTClaimsLeeway = time.Second * 60
	// DefaultMaximumJWTNotExpiredPeriod is a common default for the maximum allowed period that a JWT is not expired.
	DefaultMaximumJWTNotExpiredPeriod = time.Minute * 60
)

// JWKSProvider is an interface for getting a key from Google's JWKS.
type JWKSProvider interface {
	Get(ctx context.Context, keyID string) (*x509.Certificate, error)
}

type staticJWKSProvider struct {
	jwks map[string]*x509.Certificate
}

// StaticJWKSProvider returns a JWKSProvider that gets certificates from a map.
// The values of the jwks parameter should be PEM encoded X509 certificates.
func StaticJWKSProvider(jwks map[string]string) (JWKSProvider, error) {
	s := &staticJWKSProvider{
		jwks: map[string]*x509.Certificate{},
	}
	for keyID, certificatePEM := range jwks {
		certificate, err := auth.ParseCertificate(certificatePEM)
		if err != nil {
			return nil, fmt.Errorf("jwks[%#v] is invalid: %w", keyID, err)
		}
		s.jwks[keyID] = certificate
	}
	return s, nil
}

// Get implements JWKSProvider.
func (s *staticJWKSProvider) Get(ctx context.Context, keyID string) (*x509.Certificate, error) {
	certificate, ok := s.jwks[keyID]
	if !ok {
		return nil, fmt.Errorf("could not find certificate with key identifier %#v", keyID)
	}
	return certificate, nil
}
