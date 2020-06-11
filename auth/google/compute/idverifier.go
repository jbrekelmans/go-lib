package compute

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/go-cleanhttp"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/jbrekelmans/go-lib/auth"
	"github.com/jbrekelmans/go-lib/auth/google"
	jaspersync "github.com/jbrekelmans/go-lib/sync"
)

const (
	// InstanceStatusRunning indicates the running compute instance life cycle state. See https://cloud.google.com/compute/docs/instances/instance-life-cycle
	InstanceStatusRunning = "RUNNING"
	// InstanceStatusStopping indicates the stopping compute instance life cycle state. See https://cloud.google.com/compute/docs/instances/instance-life-cycle
	InstanceStatusStopping = "STOPPING"
)

// InstanceGetter is an abstraction for Google's Golang compute engine service for the purpose of unit testing.
type InstanceGetter = func(ctx context.Context, projectID, zone, instanceName string) (*compute.Instance, error)

// InstanceIdentityJWTClaims has holds the claims of an instance identity JWT token that are not in "gopkg.in/square/go-jose.v2/jwt".Claims.
type InstanceIdentityJWTClaims struct {
	AuthorizedParty string `json:"azp"`
	Email           string `json:"email"`
	Google          *struct {
		ComputeEngine *InstanceIdentityGCEJWTClaims `json:"compute_engine"`
	} `json:"google"`
}

// InstanceIdentityGCEJWTClaims is part of InstanceIdentityJWTClaims.
type InstanceIdentityGCEJWTClaims struct {
	ProjectID     string `json:"project_id"`
	ProjectNumber int64  `json:"project_number"`
	Zone          string `json:"zone"`
	InstanceID    string `json:"instance_id"`
	InstanceName  string `json:"instance_name"`
	// InstanceCreationTimestamp is a unix timestamp.
	InstanceCreationTimestamp int64    `json:"instance_creation_timestamp"`
	LicenseID                 []string `json:"license_id"`
}

// InstanceIdentity contains claims of an instance identity JWT token. See InstanceIdentityVerifier.Verify.
type InstanceIdentity struct {
	Claims1 *jwt.Claims
	Claims2 *InstanceIdentityJWTClaims
}

// InstanceIdentityVerifier is type that verifies instance identities. See NewInstanceIdentityVerifier and https://cloud.google.com/compute/docs/instances/verifying-instance-identity.
type InstanceIdentityVerifier struct {
	allowNonUserManagedServiceAccounts bool
	audience                           string
	ctx                                context.Context
	computeIntanceGetter               InstanceGetter
	jwtClaimsLeeway                    time.Duration
	keySetProvider                     google.KeySetProvider
	maximumJWTNotExpiredPeriod         time.Duration
	serviceAccountGetter               google.ServiceAccountGetter
	timeSource                         func() time.Time
}

// NewInstanceIdentityVerifier is the constructor for InstanceIdentityVerifier. See https://cloud.google.com/compute/docs/instances/verifying-instance-identity.
func NewInstanceIdentityVerifier(ctx context.Context, audience string, opts ...InstanceIdentityVerifierOption) (*InstanceIdentityVerifier, error) {
	if ctx == nil {
		return nil, fmt.Errorf("ctx must not be nil")
	}
	a := &InstanceIdentityVerifier{
		audience:                   audience,
		ctx:                        ctx,
		jwtClaimsLeeway:            auth.DefaultJWTClaimsLeeway,
		maximumJWTNotExpiredPeriod: auth.DefaultMaximumJWTNotExpiredPeriod,
	}
	for _, opt := range opts {
		opt(a)
	}
	var defaultHTTPClient *http.Client
	if a.keySetProvider == nil {
		defaultHTTPClient = cleanhttp.DefaultPooledClient()
		a.keySetProvider = google.CachingKeySetProvider(
			google.DefaultCachingKeySetProviderTimeToLive,
			google.HTTPSKeySetProvider(defaultHTTPClient),
		)
	}
	var computeService *compute.Service
	if a.computeIntanceGetter == nil {
		if defaultHTTPClient == nil {
			defaultHTTPClient = cleanhttp.DefaultPooledClient()
		}
		var err error
		computeService, err = compute.NewService(ctx, option.WithHTTPClient(defaultHTTPClient))
		if err != nil {
			return nil, fmt.Errorf("error creating compute service: %w", err)
		}
		a.computeIntanceGetter = func(ctx context.Context, project, zone, instance string) (*compute.Instance, error) {
			return computeService.Instances.Get(project, zone, instance).Context(ctx).Do()
		}
	}
	var iamService *iam.Service
	if a.serviceAccountGetter == nil {
		if defaultHTTPClient == nil {
			defaultHTTPClient = cleanhttp.DefaultPooledClient()
		}
		var err error
		iamService, err = iam.NewService(ctx, option.WithHTTPClient(defaultHTTPClient))
		if err != nil {
			return nil, fmt.Errorf("error creating iam service: %w", err)
		}
		a.serviceAccountGetter = func(ctx context.Context, name string) (*iam.ServiceAccount, error) {
			return iamService.Projects.ServiceAccounts.Get(name).Context(ctx).Do()
		}
	}
	if a.timeSource == nil {
		a.timeSource = time.Now
	}
	return a, nil
}

func (a *InstanceIdentityVerifier) validateClaims1(c *jwt.Claims) error {
	log.Tracef("Claims1: %+v", c)
	now := a.timeSource()
	err := c.ValidateWithLeeway(jwt.Expected{
		Audience: []string{
			a.audience,
		},
		Issuer: google.JWTIssuer,
		Time:   now,
	}, a.jwtClaimsLeeway)
	if err != nil {
		return &VerifyError{e: err.Error()}
	}
	if c.Expiry == nil {
		return &VerifyError{e: `JWT does not have required claim "exp"`}
	}
	expiry := c.Expiry.Time()
	notExpiredPeriod := expiry.Sub(now)
	if notExpiredPeriod-a.jwtClaimsLeeway > a.maximumJWTNotExpiredPeriod {
		return &VerifyError{e: fmt.Sprintf(`JWT must expire after at most %v, but it expires after %v`, a.maximumJWTNotExpiredPeriod, notExpiredPeriod-a.jwtClaimsLeeway)}
	}
	return nil
}

func (a *InstanceIdentityVerifier) validateClaims2(ctx context.Context, c *InstanceIdentityJWTClaims) error {
	project := c.Google.ComputeEngine.ProjectID
	zone := c.Google.ComputeEngine.Zone
	instance, err := a.computeIntanceGetter(ctx, project, zone, c.Google.ComputeEngine.InstanceName)
	if err != nil {
		if googleErr, ok := err.(*googleapi.Error); ok && googleErr.Code >= 500 {
			return err
		}
		return &VerifyError{e: fmt.Sprintf("error during get call: %v", err)}
	}
	// Only Running and Stopping are valid, see https://cloud.google.com/compute/docs/instances/instance-life-cycle
	if instance.Status != InstanceStatusRunning && instance.Status != InstanceStatusStopping {
		return &VerifyError{e: fmt.Sprintf("instance has illegal status %#v", instance.Status)}
	}
	creationTime, err := time.Parse(time.RFC3339Nano, instance.CreationTimestamp)
	if err != nil {
		return &VerifyError{e: fmt.Sprintf("error parsing instance's creation timestamp: %v", err)}
	}
	if creationTime.Unix() != c.Google.ComputeEngine.InstanceCreationTimestamp {
		return &VerifyError{e: fmt.Sprintf("JWT claims instance creation timestamp is %d, but it is actually %d (in unix timestamps)",
			c.Google.ComputeEngine.InstanceCreationTimestamp,
			creationTime.Unix())}
	}
	found := false
	for _, serviceAccount := range instance.ServiceAccounts {
		if serviceAccount.Email == c.Email {
			found = true
			break
		}
	}
	if !found {
		return &VerifyError{e: fmt.Sprintf("JWT claims email %#v, but the instance has no service account with that email", c.Email)}
	}
	return nil
}

func (a *InstanceIdentityVerifier) validateServiceAccountClaims(ctx context.Context, email, uniqueID string) error {
	serviceAccount, err := a.serviceAccountGetter(ctx, fmt.Sprintf("projects/*/serviceAccounts/%s", uniqueID))
	if err != nil {
		return fmt.Errorf("error during get call: %w", err)
	}
	// We expect the subject claim to be a uniqueID and not an email address.
	// And we know that email != uniqueID here.
	// BUT: if the subject claim is an email with a query string (e.g. x@gmail.com?a=2) then we may end up getting the service account
	// x@gmail.com (assuming the Google API does not give an error).
	// To deal with this case we add the following error check.
	if serviceAccount.UniqueId != uniqueID {
		return fmt.Errorf(`JWT claim "sub" (%#v) must be a unique ID`, uniqueID)
	}
	if serviceAccount.Email != email {
		return fmt.Errorf("JWT claims email %#v, but it is actually %#v", email, serviceAccount.Email)
	}
	if serviceAccount.Disabled {
		return fmt.Errorf("service account is disabled")
	}
	return nil
}

// Verify authenticates a GCE identity JWT token (see https://cloud.google.com/compute/docs/instances/verifying-instance-identity).
// If the returned error is a *VerifyError then jwtString was successfully determined to be invalid.
// Otherwise, if an error is returned, the verification attempt failed.
func (a *InstanceIdentityVerifier) Verify(jwtString string) (*InstanceIdentity, error) {
	if a.keySetProvider == nil {
		return nil, fmt.Errorf("a must be created via NewInstanceIdentityVerifier")
	}
	jwtParsed, err := jwt.ParseSigned(jwtString)
	if err != nil {
		return nil, &VerifyError{e: fmt.Sprintf("error jwtString as signed JWT: %v", err)}
	}
	if len(jwtParsed.Headers) != 1 {
		return nil, &VerifyError{e: "jwtString must encode a JWT with exactly one header"}
	}
	keySet, err := a.keySetProvider.Get(a.ctx)
	if err != nil {
		return nil, fmt.Errorf("error getting public key used for JWT signature verification: %w", err)
	}
	keyID := jwtParsed.Headers[0].KeyID
	key, ok := keySet[keyID]
	if !ok {
		return nil, &VerifyError{e: fmt.Sprintf("no key with identifier %#v exists", keyID)}
	}
	claims1 := &jwt.Claims{}
	claims2 := &InstanceIdentityJWTClaims{}
	if err := jwtParsed.Claims(key.PublicKey, claims1, claims2); err != nil {
		return nil, &VerifyError{e: fmt.Sprintf("error verifying JWT signature or decoding claims: %v", err)}
	}
	if err := a.validateClaims1(claims1); err != nil {
		return nil, err
	}
	log.Tracef("Claims2: %+v", claims2)
	if claims2.Google == nil {
		return nil, &VerifyError{e: `JWT does not have required claim "google"`}
	}
	if claims2.Google.ComputeEngine == nil {
		return nil, &VerifyError{e: `JWT has claim "google" with an object value, but the object does not have a required entry with key ` +
			`"compute_engine"`}
	}
	log.Tracef("Claims2.Google.ComputeEngine: %+v", claims2.Google.ComputeEngine)
	if claims1.Subject != claims2.AuthorizedParty {
		return nil, &VerifyError{e: fmt.Sprintf(`JWT claims "azp" and "sub" must be equal, but got %#v and %#v`, claims2.AuthorizedParty,
			claims1.Subject)}
	}
	if claims1.Subject == claims2.Email {
		return nil, &VerifyError{e: fmt.Sprintf(`JWT claims "email" and "sub" must not be equal, but they are (%#v)`, claims2.Email)}
	}
	_, err = google.ParseUserManagedServiceAccountFromEmail(claims2.Email)
	if err != nil && !a.allowNonUserManagedServiceAccounts {
		return nil, &VerifyError{e: fmt.Sprintf(`JWT claim "email" (%#v) is not a vallid email or it illegally is not a user-managed `+
			`service account email`, claims2.Email)}
	}
	err = jaspersync.CallInParallelReturnWhenAnyError(a.ctx, func(ctx context.Context) error {
		err := a.validateClaims2(ctx, claims2)
		if err != nil {
			project := claims2.Google.ComputeEngine.ProjectID
			zone := claims2.Google.ComputeEngine.Zone
			instance := claims2.Google.ComputeEngine.InstanceName
			if _, ok := err.(*VerifyError); ok {
				return &VerifyError{e: fmt.Sprintf("error validating JWT claims against compute engine API (instance %s/%s/%s): %v", project, zone, instance,
					err)}
			}
			return fmt.Errorf("error validating JWT claims against compute engine API (instance %s/%s/%s): %w", project, zone, instance,
				err)
		}
		return nil
	}, func(ctx context.Context) error {
		err := a.validateServiceAccountClaims(ctx, claims2.Email, claims1.Subject)
		if err != nil {
			var googleErr *googleapi.Error
			if errors.As(err, &googleErr) && googleErr.Code >= 500 {
				return fmt.Errorf("error validating JWT claims against IAM API (service account %s): %w", claims1.Subject, err)
			}
			return &VerifyError{e: fmt.Sprintf("error validating JWT claims against IAM API (service account %s): %v", claims1.Subject, err)}
		}
		return nil
	})
	return &InstanceIdentity{
		Claims1: claims1,
		Claims2: claims2,
	}, nil
}

// VerifyError communicates that a successful verification attempt resulted in a negative response.
type VerifyError struct {
	e string
}

func (v *VerifyError) Error() string {
	return v.e
}
