package compute

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/jbrekelmans/go-lib/auth/google"
	"github.com/jbrekelmans/go-lib/auth/jose"
)

const (
	// InstanceStatusRunning indicates the running compute instance life cycle state. See https://cloud.google.com/compute/docs/instances/instance-life-cycle
	InstanceStatusRunning = "RUNNING"
	// InstanceStatusStopping indicates the stopping compute instance life cycle state. See https://cloud.google.com/compute/docs/instances/instance-life-cycle
	InstanceStatusStopping = "STOPPING"
)

// InstanceGetter is an abstraction for Go's compute engine service for the purpose of unit testing.
type InstanceGetter = func(ctx context.Context, projectID, zone, instanceName string) (*compute.Instance, error)

// InstanceIdentityJWTClaims is part of InstanceIdentityJWTClaims.
type InstanceIdentityJWTClaims struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber int64  `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceID    string `json:"instance_id"`
	InstanceName  string `json:"instance_name"`
	// InstanceCreationTimestamp is a unix timestamp.
	InstanceCreationTimestamp int64    `json:"instance_creation_timestamp"`
	LicenseID                 []string `json:"license_id"`
}

// InstanceIdentity contains information obtained during verification of an instance's identity. See (*InstanceIdentityVerifier).Verify.
type InstanceIdentity struct {
	GoogleJWTClaims *InstanceIdentityJWTClaims
	Instance        *compute.Instance
	RFCJWTClaims    *jwt.Claims
}

// InstanceIdentityVerifier is type that verifies instance identities. See NewInstanceIdentityVerifier and https://cloud.google.com/compute/docs/instances/verifying-instance-identity.
type InstanceIdentityVerifier struct {
	audience                   string
	ctx                        context.Context
	computeIntanceGetter       InstanceGetter
	jwtClaimsLeeway            time.Duration
	maximumJWTNotExpiredPeriod time.Duration
	jwksProvider               jose.JWKSProvider
	timeSource                 func() time.Time
}

// NewInstanceIdentityVerifier is the constructor for InstanceIdentityVerifier. See https://cloud.google.com/compute/docs/instances/verifying-instance-identity.
func NewInstanceIdentityVerifier(ctx context.Context, audience string, opts ...InstanceIdentityVerifierOption) (*InstanceIdentityVerifier, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ctx must not be nil")
	}
	a := &InstanceIdentityVerifier{
		audience:                   audience,
		ctx:                        ctx,
		jwtClaimsLeeway:            jose.DefaultJWTClaimsLeeway,
		maximumJWTNotExpiredPeriod: jose.DefaultMaximumJWTNotExpiredPeriod,
	}
	for _, opt := range opts {
		opt(a)
	}
	var defaultHTTPClient *http.Client
	if a.jwksProvider == nil {
		defaultHTTPClient = cleanhttp.DefaultPooledClient()
		a.jwksProvider = google.HTTPSJWKSProvider(defaultHTTPClient)
	}
	var computeService *compute.Service
	if a.computeIntanceGetter == nil {
		var computeServiceOptions []option.ClientOption
		if defaultHTTPClient != nil {
			computeServiceOptions = append(computeServiceOptions, option.WithHTTPClient(defaultHTTPClient))
		}
		var err error
		computeService, err = compute.NewService(ctx, computeServiceOptions...)
		if err != nil {
			return nil, fmt.Errorf("error creating compute service: %w", err)
		}
		a.computeIntanceGetter = func(ctx context.Context, project, zone, instance string) (*compute.Instance, error) {
			return computeService.Instances.Get(project, zone, instance).Context(ctx).Do()
		}
	}
	if a.timeSource == nil {
		a.timeSource = time.Now
	}
	return a, nil
}

func (a *InstanceIdentityVerifier) validateComputeEngineClaims(c *InstanceIdentityJWTClaims) (*compute.Instance, error) {
	instance, err := a.computeIntanceGetter(a.ctx, c.ProjectID, c.Zone, c.InstanceName)
	if err != nil {
		return nil, fmt.Errorf("error during get API call: %w", err)
	}
	// Only Running and Stopping are valid, see https://cloud.google.com/compute/docs/instances/instance-life-cycle
	if instance.Status != InstanceStatusRunning && instance.Status != InstanceStatusStopping {
		return nil, fmt.Errorf("instance has illegal status %#v", instance.Status)
	}
	creationTime, err := time.Parse(time.RFC3339Nano, instance.CreationTimestamp)
	if err != nil {
		return nil, fmt.Errorf("error parsing instance's creation timestamp: %w", err)
	}
	if creationTime.Unix() != c.InstanceCreationTimestamp {
		return nil, fmt.Errorf("JWT claims instance creation timestamp is %d, but it is actually %d (in unix timestamps)",
			c.InstanceCreationTimestamp,
			creationTime.Unix())
	}
	return instance, nil
}

func (a *InstanceIdentityVerifier) validateRFCClaims(c *jwt.Claims) error {
	now := a.timeSource()
	err := c.ValidateWithLeeway(jwt.Expected{
		Audience: []string{
			a.audience,
		},
		Issuer: google.JWTIssuer,
		Time:   now,
	}, a.jwtClaimsLeeway)
	if err != nil {
		return err
	}
	if c.Expiry == nil {
		return fmt.Errorf(`JWT does not have required claim "exp"`)
	}
	expiry := c.Expiry.Time()
	notExpiredPeriod := expiry.Sub(now)
	if notExpiredPeriod-a.jwtClaimsLeeway > a.maximumJWTNotExpiredPeriod {
		return fmt.Errorf(`JWT must expire after at most %v, but it expires after %v`, a.maximumJWTNotExpiredPeriod, notExpiredPeriod-a.jwtClaimsLeeway)
	}
	return nil
}

// Verify authenticates a GCE identity JWT token (see https://cloud.google.com/compute/docs/instances/verifying-instance-identity).
// Inspired by https://github.com/hashicorp/vault-plugin-auth-gcp/blob/8450f263d8d262b6c4871ff2576373c17dbe1687/plugin/path_login.go#L145
func (a *InstanceIdentityVerifier) Verify(jwtString string) (*InstanceIdentity, error) {
	if a.jwksProvider == nil {
		return nil, fmt.Errorf("a must be created via NewInstanceIdentityVerifier")
	}
	jwtParsed, err := jwt.ParseSigned(jwtString)
	if err != nil {
		return nil, fmt.Errorf("error jwtString as signed JWT: %w", err)
	}
	if len(jwtParsed.Headers) != 1 {
		return nil, fmt.Errorf("jwtString must encode a JWT with exactly one header")
	}
	kid := jwtParsed.Headers[0].KeyID
	key, err := a.jwksProvider.Get(a.ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("error getting public key used forJWT signature verification: %w", err)
	}
	rfcClaims := &jwt.Claims{}
	googleClaims := &struct {
		Google *struct {
			ComputeEngine *InstanceIdentityJWTClaims `json:"compute_engine"`
		} `json:"google"`
	}{}
	if err := jwtParsed.Claims(key.PublicKey, rfcClaims, googleClaims); err != nil {
		return nil, fmt.Errorf("error verifying JWT signature or decoding claims: %w", err)
	}
	if err := a.validateRFCClaims(rfcClaims); err != nil {
		return nil, err
	}
	if googleClaims.Google == nil {
		return nil, fmt.Errorf(`JWT does not have required claim "google"`)
	}
	if googleClaims.Google.ComputeEngine == nil {
		return nil, fmt.Errorf(`JWT has claim "google" with an object value, but the object does not have a required entry with key ` +
			`"compute_engine"`)
	}
	log.Tracef("RFC claims: %+v", rfcClaims)
	log.Tracef("Google claims: %+v", googleClaims.Google.ComputeEngine)
	instance, err := a.validateComputeEngineClaims(googleClaims.Google.ComputeEngine)
	if err != nil {
		project := googleClaims.Google.ComputeEngine.ProjectID
		zone := googleClaims.Google.ComputeEngine.Zone
		instance := googleClaims.Google.ComputeEngine.InstanceName
		return nil, fmt.Errorf("error validating JWT with respect to compute engine claim (instance %s/%s/%s): %w", project, zone, instance,
			err)
	}
	return &InstanceIdentity{
		Instance:        instance,
		GoogleJWTClaims: googleClaims.Google.ComputeEngine,
		RFCJWTClaims:    rfcClaims,
	}, nil
}
