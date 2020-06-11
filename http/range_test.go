package http

import (
	"net/http"
	"reflect"
	"testing"
)

func Test_ParseRange_MultipleHeaders(t *testing.T) {
	var req http.Request
	req.Header = http.Header{}
	req.Header.Add("Range", "bytes=0-")
	req.Header.Add("Range", "bytes=0-")
	_, err := ParseRange(&req)
	if err == nil {
		t.Fail()
	}
}

func Test_ParseRange_NoHeader(t *testing.T) {
	var req http.Request
	ranges, err := ParseRange(&req)
	if len(ranges) > 0 || err != nil {
		t.Fail()
	}
}

func Test_ParseRangeHeaderValue_InvalidUnit(t *testing.T) {
	var req http.Request
	req.Header = http.Header{}
	req.Header.Add("Range", "kilobytesnope=1-2")
	_, err := ParseRange(&req)
	if err == nil {
		t.Fail()
	}
}

func Test_ParseRangeHeaderValue_SuffixByteRangeSpecOverflow(t *testing.T) {
	var req http.Request
	req.Header = http.Header{}
	req.Header.Add("Range", "bytes=-129358192384912341234123412341234")
	_, err := ParseRange(&req)
	if err == nil {
		t.Fail()
	}
}

func Test_ParseRangeHeaderValue_ByteRangeSpecFirstBytePosOverflow(t *testing.T) {
	var req http.Request
	req.Header = http.Header{}
	req.Header.Add("Range", "bytes=129358192384912341234123412341234-")
	_, err := ParseRange(&req)
	if err == nil {
		t.Fail()
	}
}

func Test_ParseRangeHeaderValue_ByteRangeSpecLastBytePosOverflow(t *testing.T) {
	var req http.Request
	req.Header = http.Header{}
	req.Header.Add("Range", "bytes=1-1923849182349812934891283498123413424123")
	_, err := ParseRange(&req)
	if err == nil {
		t.Fail()
	}
}

func Test_ParseRangeHeaderValue_EmptyTrailingRangeSpec(t *testing.T) {
	var req http.Request
	req.Header = http.Header{}
	req.Header.Add("Range", "bytes=0-0,")
	_, err := ParseRange(&req)
	if err == nil {
		t.Fail()
	}
}

func Test_ParseRangeHeaderValue_Success(t *testing.T) {
	var req http.Request
	req.Header = http.Header{}
	req.Header.Add("Range", "bytes=0-0, 1000-,\t-500,1-1")
	ranges, err := ParseRange(&req)
	if err != nil {
		t.FailNow()
	}
	if !reflect.DeepEqual(ranges, []Range{
		{
			FirstBytePos: 0,
			LastBytePos:  0,
		},
		{
			FirstBytePos: 1000,
			LastBytePos:  -1,
		},
		{
			FirstBytePos: -1,
			LastBytePos:  -500,
		},
		{
			FirstBytePos: 1,
			LastBytePos:  1,
		},
	}) {
		t.Logf("%+v", ranges)
		t.Fail()
	}
}
