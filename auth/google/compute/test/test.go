package main

import (
	"context"
	"net/http"
	"os"

	log "github.com/sirupsen/logrus"
	oauth2 "golang.org/x/oauth2"
	oauth2google "golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/iam/v1"
	"google.golang.org/api/option"

	jaspergoogle "github.com/jbrekelmans/go-lib/auth/google"
	jaspercompute "github.com/jbrekelmans/go-lib/auth/google/compute"
)

var jwtToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImMxNzcxODE0YmE2YTcwNjkzZmI5NDEyZGEzYzZlOTBjMmJmNWI5MjciLCJ0eXAiOiJKV1QifQ.eyJhdWQiOiJo" +
	"dHRwczovL2V4YW1wbGUuY29tLyIsImF6cCI6IjExNTU4NjE3NDA5MDY2MDcxNzQ3NSIsImVtYWlsIjoiMTk4Mjg1NjE2NjgxLWNvbXB1dGVAZGV2ZWx" +
	"vcGVyLmdzZXJ2aWNlYWNjb3VudC5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiZXhwIjoxNTg5NzE3Mjk4LCJnb29nbGUiOnsiY29tcHV0ZV9lbm" +
	"dpbmUiOnsiaW5zdGFuY2VfY3JlYXRpb25fdGltZXN0YW1wIjoxNTg5NjA4NjY0LCJpbnN0YW5jZV9pZCI6Ijc0ODM5Mjc5MTQ5NjQyMDUxMTIiLCJpb" +
	"nN0YW5jZV9uYW1lIjoiaW5zdGFuY2UtMSIsInByb2plY3RfaWQiOiJzY3JhdGNoLXBsYXlncm91bmQiLCJwcm9qZWN0X251bWJlciI6MTk4Mjg1NjE2" +
	"NjgxLCJ6b25lIjoiYXVzdHJhbGlhLXNvdXRoZWFzdDEtYiJ9fSwiaWF0IjoxNTg5NzEzNjk4LCJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5" +
	"jb20iLCJzdWIiOiIxMTU1ODYxNzQwOTA2NjA3MTc0NzUifQ.hZU05LXG2YR-ggXwvLy1by4MXFh2dJD6oXSRtrkGcxhmpuvDbjnOSIH4-rfjAlQJ0Ku" +
	"Cbdb3HEvRVYiQXHNgny5ZbptFGbvHDl8UITvgQBKJR31wDFSNXXW2Lk1s2_siufcjDLbkL5PadWCXp5KBYqVg-BBv19Phn7oI5dDaCvaJI_6NHc3zXI" +
	"5l8uouDVxsvZmruQKqVPYfK3n6m7-cUZ_dm64FKguAAXpwdSLrLe4ccOuxHXd3QNeom1dnodF0rREexk6qZEkwE_493xgAPzVEyWLa3jyVhjwmcu9hB" +
	"XTfzVsVRRqF0yxtEqpHVPicluBqzSEhaIL94qahv67LEw"

func main() {
	log.SetLevel(log.TraceLevel)
	log.SetOutput(os.Stdout)
	if err := mainCore(); err != nil {
		log.Fatal(err)
	}
}

func mainCore() error {
	ctx := context.Background()
	httpClient := http.DefaultClient
	credentials, err := oauth2google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return err
	}
	googleHTTPClient := oauth2.NewClient(ctx, credentials.TokenSource)
	computeService, err := compute.NewService(ctx, option.WithHTTPClient(googleHTTPClient))
	if err != nil {
		return err
	}
	iamService, err := iam.NewService(ctx, option.WithHTTPClient(googleHTTPClient))
	if err != nil {
		return err
	}
	keySetProvider := jaspergoogle.CachingKeySetProvider(
		jaspergoogle.DefaultCachingKeySetProviderTimeToLive,
		jaspergoogle.HTTPSKeySetProvider(httpClient),
	)
	idVerifier, err := jaspercompute.NewInstanceIdentityVerifier(
		ctx,
		"https://example.com/",
		jaspercompute.WithAllowNonUserManagedServiceAccounts(true),
		jaspercompute.WithInstanceGetter(func(ctx context.Context, project, zone, name string) (*compute.Instance, error) {
			return computeService.Instances.Get(project, zone, name).Context(ctx).Do()
		}),
		jaspercompute.WithKeySetProvider(keySetProvider),
		jaspercompute.WithServiceAccountGetter(func(ctx context.Context, name string) (*iam.ServiceAccount, error) {
			return iamService.Projects.ServiceAccounts.Get(name).Context(ctx).Do()
		}),
	)
	if err != nil {
		return err
	}
	ret, err := idVerifier.Verify(jwtToken)
	if err != nil {
		return err
	}
	log.Infof("%+v", ret)
	return nil
}
