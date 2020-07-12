package url

import (
	"testing"

	"net/url"
)

func Test_SchemeDefaultPorts_UndefinedPort(t *testing.T) {
	x := SchemeDefaultPorts("HTTPS")
	if x >= 0 {
		t.Fatal(x)
	}
}

func Test_NormalizePort_ErrorURLNil(t *testing.T) {
	err := NormalizePort(nil, false, nil)
	if err == nil {
		t.Fatal()
	}
}

func Test_NormalizePort_ErrorPortTooLarge(t *testing.T) {
	err := NormalizePort(&url.URL{
		Scheme: "https",
		Host:   "example.com:12341234123412341234",
	}, false, nil)
	if err == nil {
		t.Fatal()
	}
}

func Test_NormalizePort_ErrorDefaultPortUndefined(t *testing.T) {
	err := NormalizePort(&url.URL{
		Scheme: "https",
		Host:   "example.com:443",
	}, false, func(scheme string) int {
		return -1
	})
	if err == nil {
		t.Fatal()
	}
}

func Test_NormalizePort_SuccessRelativeURI(t *testing.T) {
	u, err := url.Parse("relative/uri")
	if err != nil {
		t.Fatal(err)
	}
	err = NormalizePort(u, false, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_NormalizePort_SuccessURL(t *testing.T) {
	u := &url.URL{
		Scheme: "https",
		Host:   "example.com:443",
	}
	err := NormalizePort(u, false, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://example.com" {
		t.Fail()
	}
}

func Test_NormalizePort_SuccessURLWithoutPort(t *testing.T) {
	u, err := url.Parse("https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	err = NormalizePort(u, false, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func Test_NormalizePort_SuccessNormalizesExplicitDefaultPortWithLeadingZeros(t *testing.T) {
	u, err := url.Parse("https://example.com:0443/")
	if err != nil {
		t.Fatal(err)
	}
	err = NormalizePort(u, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://example.com:443/" {
		t.Fatal(u)
	}
}

func Test_ValidateURL_ErrorParseURL(t *testing.T) {
	u, err := ValidateURL("://#?!invalid", ValidateURLOptions{})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_ErrorMustBeAbsolute(t *testing.T) {
	u, err := ValidateURL("relative/uri", ValidateURLOptions{
		Abs: NewBool(true),
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_ErrorMustBeRelative(t *testing.T) {
	u, err := ValidateURL("https://example.com/", ValidateURLOptions{
		Abs: NewBool(false),
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_InvalidScheme1(t *testing.T) {
	u, err := ValidateURL("ws://example.com/", ValidateURLOptions{
		AllowedSchemes: []string{"https", "http", "wss"},
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_InvalidScheme2(t *testing.T) {
	u, err := ValidateURL("ws://example.com/", ValidateURLOptions{
		AllowedSchemes: []string{"https"},
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_ErrorNormalizePort(t *testing.T) {
	u, err := ValidateURL("myscheme://example.com/", ValidateURLOptions{
		NormalizePort: NewBool(true),
		SchemeDefaultPorts: func(scheme string) int {
			return -1
		},
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_ErrorUserRequired(t *testing.T) {
	u, err := ValidateURL("https://example.com/", ValidateURLOptions{
		User: NewBool(true),
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_ErrorPasswordRequired(t *testing.T) {
	u, err := ValidateURL("https://myuser@example.com/", ValidateURLOptions{
		UserPassword: NewBool(true),
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_ErrorUserNotAllowed(t *testing.T) {
	u, err := ValidateURL("https://myuser@example.com/", ValidateURLOptions{
		User: new(bool),
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_ErrorPasswordNotAllowed(t *testing.T) {
	u, err := ValidateURL("https://myuser:mypassword@example.com/", ValidateURLOptions{
		UserPassword: NewBool(false),
	})
	if err == nil {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_Success1(t *testing.T) {
	u, err := ValidateURL("https://myuser@example.com/%2F?#frag", ValidateURLOptions{
		AllowedSchemes:           []string{"https"},
		NormalizePort:            NewBool(true),
		StripFragment:            true,
		StripPathTrailingSlashes: true,
		StripQuery:               true,
		StripUser:                true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://example.com:443" {
		t.Logf("RawPath = %#v, Path = %#v", u.RawPath, u.Path)
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_Success2(t *testing.T) {
	u, err := ValidateURL("https://myuser:asdf@example.com/%2f", ValidateURLOptions{
		StripUserPassword:                        true,
		StripPathTrailingSlashes:                 true,
		StripPathTrailingSlashesNoPercentEncoded: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://myuser@example.com/%2f" {
		t.Fatalf("%v", u)
	}
}

func Test_ValidateURL_Success3(t *testing.T) {
	u, err := ValidateURL("https://example.com//", ValidateURLOptions{
		StripPathTrailingSlashes: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if u.String() != "https://example.com" {
		t.Fatalf("%v", u)
	}
}
