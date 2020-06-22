package http

import (
	"reflect"
	"testing"
)

func Test_ParseWwwAuthenticateHeaderValue_Success(t *testing.T) {
	headerValue := `Bearer realm="bla",param1=value1,param2="value2"`
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
					Value:     "bla",
				},
				{
					Attribute: "param1",
					Value:     "value1",
				},
				{
					Attribute: "param2",
					Value:     "value2",
				},
			},
		},
	}) {
		t.Fail()
	}
}
