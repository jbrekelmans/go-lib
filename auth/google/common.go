package google

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/api/iam/v1"
)

// JWTIssuer is a constant for Google's JWT issuer
const JWTIssuer = "https://accounts.google.com"

// UserManagedServiceAccountEmailSuffix asdf
const UserManagedServiceAccountEmailSuffix = ".iam.gserviceaccount.com"

// ServiceAccountGetter is an abstraction for Google's Golang IAM service for the purpose of unit testing.
// name must be of the shape projects/x/serviceAccounts/y where x is * or the project ID and y is the email address or unique identifier
// of the service account. See https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts/get
type ServiceAccountGetter = func(ctx context.Context, name string) (*iam.ServiceAccount, error)

// UserManagedServiceAccount represents a user-managed service account. See https://cloud.google.com/iam/docs/service-accounts#user-managed
type UserManagedServiceAccount struct {
	Name    string
	Project string
}

// ParseUserManagedServiceAccountFromEmail parses v as a user-managed service account email.
// See https://cloud.google.com/iam/docs/service-accounts#user-managed
func ParseUserManagedServiceAccountFromEmail(v string) (*UserManagedServiceAccount, error) {
	if !strings.HasSuffix(v, UserManagedServiceAccountEmailSuffix) {
		return nil, fmt.Errorf(`value %#v does not have required suffix %#v`, v, UserManagedServiceAccountEmailSuffix)
	}
	nameAtProject := v[:len(v)-len(UserManagedServiceAccountEmailSuffix)]
	i := strings.IndexByte(nameAtProject, '@')
	if i < 0 {
		return nil, fmt.Errorf(`value %#v does not contain "@"`, v)
	}
	return &UserManagedServiceAccount{
		Name:    nameAtProject[:i],
		Project: nameAtProject[i+1:],
	}, nil
}
