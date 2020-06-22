package http

import (
	"reflect"
	"testing"
)

func Test_ParseWwwAuthenticateHeaderValue_Success(t *testing.T) {
	headerValue := `Bearer realm="https://gcr.io/v2/token",service="gcr.io",scope="repository:scratch-playground/demo-app:pull"`
	challenges, err := ParseWwwAuthenticateHeaderValue(nil, headerValue)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(challenges, []*Challenge{
		{
			Scheme: "Bearer",
			Params: []*Param{
				{
					Attribute: "realm",
					Value:     "https://gcr.io/v2/token",
				},
				{
					Attribute: "service",
					Value:     "gcr.io",
				},
				{
					Attribute: "scope",
					Value:     "repository:scratch-playground/demo-app:pull",
				},
			},
		},
	}) {
		t.Fail()
	}
}
