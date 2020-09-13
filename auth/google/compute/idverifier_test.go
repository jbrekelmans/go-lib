package compute

import (
	"context"
	"testing"
	"time"

	"github.com/jbrekelmans/go-lib/auth/google"
	"github.com/jbrekelmans/go-lib/test"
	log "github.com/sirupsen/logrus"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
)

var testAudience = "https://example.com/"
var testInstance = &compute.Instance{
	CreationTimestamp: "2020-05-16T15:57:44.999999999+10:00",
	Name:              "instance-1",
	Status:            InstanceStatusRunning,
	Zone:              "australia-southeast1-b",
}
var testJWTToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImMxNzcxODE0YmE2YTcwNjkzZmI5NDEyZGEzYzZlOTBjMmJmNWI5MjciLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJo" +
	"dHRwczovL2V4YW1wbGUuY29tLyIsImF6cCI6IjExNTU4NjE3NDA5MDY2MDcxNzQ3NSIsImVtYWlsIjoiMTk4Mjg1NjE2NjgxLWNvbXB1dGVAZGV2ZWx" +
	"vcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNTg5NjEyNzYwLCJnb29nbGUiOnsiY29tcHV0ZV9lbm" +
	"dpbmUiOnsiaW5zdGFuY2VfY3JlYXRpb25fdGltZXN0YW1wIjoxNTg5NjA4NjY0LCJpbnN0YW5jZV9pZCI6Ijc0ODM5Mjc5MTQ5NjQyMDUxMTIiLCJpb" +
	"nN0YW5jZV9uYW1lIjoiaW5zdGFuY2UtMSIsInByb2plY3RfaWQiOiJzY3JhdGNoLXBsYXlncm91bmQiLCJwcm9qZWN0X251bWJlciI6MTk4Mjg1NjE2" +
	"NjgxLCJ6b25lIjoiYXVzdHJhbGlhLXNvdXRoZWFzdDEtYiJ9fSwiaWF0IjoxNTg5NjA5MTYwLCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5" +
	"jb20iLCJzdWIiOiIxMTU1ODYxNzQwOTA2NjA3MTc0NzUifQ.vi_t0cX_BnVtTMyjrUKcCBZ5suOUMnCRCDmgb2jrS9r1n9K-Q0K_BFoneolmrVN8LjB" +
	"tfgTSyWHhMF8rkkOd8w4C4RNliCakrRMXip7XqSt0eqn1G381TNMLpmgKzfKFZ4IOpNTKnNus-CYo1Mm712kRGzT4saglT3W54r7jKU7sdVeisfpJoK" +
	"MGaBGh2-JXmlYM5Cmu-IiG4D1CppcS3Gh7-lAFWCZ6GjQs1z2QnDjiTpFuwBVTa8gJ1H91ETKbe005PuQnpY65OBq8G3KdnUq2FwQ9sMZsaDGVE8cAZ" +
	"-lK-AY7rGi2_WbkR30ANOxH6ZQGhfTh1-uZ9rFr27fWZg"
var testKeySetProvider google.KeySetProvider
var testServiceAccount = &iam.ServiceAccount{
	Email:    "198285616681-compute@developer.gserviceaccount.com",
	UniqueId: "115586174090660717475",
}
var testTimeNow time.Time

func init() {
	var err error
	testKeySetProvider, err = google.StaticKeySetProvider(map[string]string{
		"c1771814ba6a70693fb9412da3c6e90c2bf5b927": "-----BEGIN CERTIFICATE-----\nMIIDJjCCAg6gAwIBAgIINA9D6ntD6UwwDQYJKoZIhvcNAQEFBQAwNjE0MDIGA1UE\nAxMrZmVkZXJhdGVkLXNpZ25vbi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTAe\nFw0yMDA1MDgwNDI5MzJaFw0yMDA1MjQxNjQ0MzJaMDYxNDAyBgNVBAMTK2ZlZGVy\nYXRlZC1zaWdub24uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wggEiMA0GCSqG\nSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEcofKwYd9lvL3ay0DILheSnu3YhvpMSFr\nUbXVTAaCau/umCmMoEmQ7Ve2+9PYvekTKWFwqEuA7x/HlH6spx57Nn9ilPK5PW8c\nexZgnF6hxXmbRXvT82+B/KyXqVL+B299Prx0w2TUQvxsiT26IIwii1WlyrgUh4gP\nvkN6d2r+hO5c5lV4KLWvyrSp4xY3ucVkQkKfHNrI05MTv54LwVExGK757e062Su6\nBrcLPraeSSsa1DIBpC1Se2sNNDGMTZM2EG9YFYNU5+8b64J7YmSF8MLsJmUTq2kG\nj5WTIgYZmNHmoGVhMrHpkmNZ5ALXeWnB3tYHW8q0FIoYfa8q4FutAgMBAAGjODA2\nMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsG\nAQUFBwMCMA0GCSqGSIb3DQEBBQUAA4IBAQCDmHmX0May2yvcY/YEKMZIleBzIJrZ\nIs2COueb5KwUy13aORB2vCsIA6xZh9onhOlDaf7Hd5ZziMQsn4+mo1ta3nxKInXC\nYvf3YnNOThTEgZY3ZOfI5wDs4sGVEkiF+VHdMOj4AFrB2Fapyh2NwyiSiXR+yFcW\nishQj9Lh9h1dBdz2C3ZcVzP0f9Fjfqj27N6h5PA7ooBSgXmXR2zCbT5n9+LykT3G\nyMGS0j7XL+EmO8LiLAbxW6Zxyvjd6NFD3VA2+FtgT+rVzOIIiDTDttStC3PqhbwT\n87QGg8tCjnYVAuXPrBWfoxPBNUAAWSgVdh1gsJ7sehDEofBiKJ5oU9cH\n-----END CERTIFICATE-----\n",
	})
	if err != nil {
		panic(err)
	}
	testTimeNow, err = time.Parse(time.RFC3339, "2020-05-16T17:00:00+10:00")
	if err != nil {
		panic(err)
	}
	log.SetLevel(log.TraceLevel)
}

func setup(t *testing.T, opts ...InstanceIdentityVerifierOption) (ctx context.Context, i *InstanceIdentityVerifier, teardown func()) {
	disposable := test.RedirectLogs(t)
	timeSource := func() time.Time {
		return testTimeNow
	}
	ctx, cancel := context.WithCancel(context.Background())
	opts = append([]InstanceIdentityVerifierOption{
		WithAllowNonUserManagedServiceAccounts(true),
		WithKeySetProvider(testKeySetProvider),
		WithInstanceGetter(func(ctx context.Context, project, instance, name string) (*compute.Instance, error) {
			return testInstance, nil
		}),
		WithServiceAccountGetter(func(ctx context.Context, name string) (*iam.ServiceAccount, error) {
			return testServiceAccount, nil
		}),
		WithTimeSource(timeSource),
	}, opts...)
	var err error
	i, err = NewInstanceIdentityVerifier(testAudience, opts...)
	if err != nil {
		t.Fatal(err)
	}
	teardown = func() {
		cancel()
		disposable.Dispose()
	}
	return
}

func Test_InstanceIdentityVerifier_Verify_Success(t *testing.T) {
	ctx, a, teardown := setup(t)
	defer teardown()

	i, err := a.Verify(ctx, testJWTToken)
	if err != nil {
		t.Fatal(err)
	}

	if i.Claims1 != nil {
		if i.Claims1.Subject != "115586174090660717475" {
			t.Logf("unexpected subject: %s", i.Claims1.Subject)
			t.Fail()
		}
		if i.Claims2.Google.ComputeEngine.ProjectID != "scratch-playground" || i.Claims2.Google.ComputeEngine.Zone != "australia-southeast1-b" ||
			i.Claims2.Google.ComputeEngine.InstanceName != "instance-1" {
			t.Logf("unexpected Claims2.Google.ComputeEngine: %+v", i.Claims2.Google.ComputeEngine)
			t.Fail()
		}
	} else {
		t.Logf("missing Claims1")
		t.Fail()
	}
}
