package auth

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"
)

const (
	// DefaultJWTClaimsLeeway is a common default for JWT claims leeway.
	// Leeway is defined by https://godoc.org/gopkg.in/square/go-jose.v2/jwt#Claims.ValidateWithLeeway.
	DefaultJWTClaimsLeeway = time.Second * 60
	// DefaultMaximumJWTNotExpiredPeriod is a common default for the maximum allowed period that a JWT is not expired.
	DefaultMaximumJWTNotExpiredPeriod = time.Minute * 60
)

const pemBlockTypeCertificate = "CERTIFICATE"

// ParseCertificate parses a single X509 certificate from the PEM-encoded data. If the data has multiple X509 certificates then an error is
// returned.
func ParseCertificate(pemString string) (*x509.Certificate, error) {
	pemBytes := []byte(pemString)
	var certificate1 *x509.Certificate
	for {
		var block *pem.Block
		block, pemBytes = pem.Decode(pemBytes)
		if block == nil {
			break
		}
		if block.Type == pemBlockTypeCertificate {
			certificate2, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("got error while parsing certificate PEM block: %w", err)
			}
			if certificate1 != nil {
				return nil, fmt.Errorf("data has multiple certificates")
			}
			certificate1 = certificate2
		}
	}
	if certificate1 != nil {
		return certificate1, nil
	}
	return nil, fmt.Errorf("data has no certificate PEM blocks")
}
