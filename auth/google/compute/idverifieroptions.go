package compute

import (
	"fmt"
	"time"

	"github.com/jbrekelmans/go-lib/auth/jose"
)

// InstanceIdentityVerifierOption is an option that can be passed to NewInstanceIdentityVerifier.
type InstanceIdentityVerifierOption = func(a *InstanceIdentityVerifier)

// WithInstanceGetter returns an option for NewInstanceIdentityVerifier that sets the compute instance getter.
func WithInstanceGetter(v InstanceGetter) InstanceIdentityVerifierOption {
	return func(a *InstanceIdentityVerifier) {
		a.computeIntanceGetter = v
	}
}

// WithJWTClaimsLeeway returns an option for NewInstanceIdentityVerifier that sets the leeway when validating JWT claims.
// See https://godoc.org/gopkg.in/square/go-jose.v2/jwt#Claims.ValidateWithLeeway
func WithJWTClaimsLeeway(v time.Duration) InstanceIdentityVerifierOption {
	if v < 0 {
		panic(fmt.Errorf("v must be non-negative"))
	}
	return func(a *InstanceIdentityVerifier) {
		a.jwtClaimsLeeway = v
	}
}

// WithJWKSProvider returns an option for NewInstanceIdentityVerifier that sets the google.OAuth2CertificateGetter.
func WithJWKSProvider(v jose.JWKSProvider) InstanceIdentityVerifierOption {
	return func(a *InstanceIdentityVerifier) {
		a.jwksProvider = v
	}
}

// WithMaximumJWTNotExpiredPeriod returns an option for NewInstanceIdentityVerifier that sets the maximum allowed period that a JWT does not expire.
func WithMaximumJWTNotExpiredPeriod(v time.Duration) InstanceIdentityVerifierOption {
	if v < 0 {
		panic(fmt.Errorf("v must be non-negative"))
	}
	return func(a *InstanceIdentityVerifier) {
		a.maximumJWTNotExpiredPeriod = v
	}
}

// WithTimeSource returns an option for NewInstanceIdentityVerifier that sets the time source. This is useful for unit testing.
func WithTimeSource(v func() time.Time) InstanceIdentityVerifierOption {
	return func(a *InstanceIdentityVerifier) {
		a.timeSource = v
	}
}
