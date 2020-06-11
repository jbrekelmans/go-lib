package http

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Range represents an RFC7233 (suffix) byte range spec. See https://tools.ietf.org/html/rfc7233#page-7
type Range struct {
	// FirstBytePos is -1 if a suffix-byte-range-spec is represented.
	// Otherwise, FirstBytePos is the offset of the first byte in the range.
	FirstBytePos int64
	// LastBytePos has two interpretations, depending on the value of FirstBytePos.
	// If FirstBytePos >= 0 then
	//		If LastBytePos is -1 then the range includes all bytes with offset >= FirstBytePos.
	//		Otherwise, if LastBytePos >= 0, LastBytePos is the offset of the last byte in the range (inclusive).
	// Otherwise, if FirstBytePos < 0 then
	//		The range includes only the last -LastBytePos (note that LastBytePos is negative) bytes of the
	// 		requested resource.
	LastBytePos int64
}

func ParseRange(req *http.Request) ([]Range, error) {
	// See https://tools.ietf.org/html/rfc7233#section-2 and https://tools.ietf.org/html/rfc7230#section-7
	headerValues := req.Header.Values("Range")
	if len(headerValues) > 1 {
		return nil, fmt.Errorf("multiple headers named Range are not supported")
	}
	if len(headerValues) == 0 {
		return nil, nil
	}
	ranges, err := parseRangeHeaderValue(headerValues[0])
	if err != nil {
		return nil, fmt.Errorf("the header named Range has an invalid value: %w", err)
	}
	return ranges, nil
}

func parseRangeHeaderValue(headerValue string) (ranges []Range, err error) {
	remainder := headerValue
	const b = "bytes="
	if !strings.HasPrefix(remainder, b) {
		return nil, fmt.Errorf("value does not start with %#v", b)
	}
	remainder = remainder[len(b):]
	for {
		commaPos := strings.IndexByte(remainder, ',')
		byteRangeSpec := remainder
		if commaPos >= 0 {
			byteRangeSpec = byteRangeSpec[:commaPos]
		}
		hyphenPos := strings.IndexByte(byteRangeSpec, '-')
		if hyphenPos < 0 {
			return nil, fmt.Errorf("value contains a byte-range-spec that contains no hyphen")
		}
		if hyphenPos == 0 {
			// suffix range spec
			suffixLength, err := strconv.ParseInt(byteRangeSpec, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("value contains a suffix-byte-range-spec with an invalid or too large suffix-length: %w", err)
			}
			ranges = append(ranges, Range{
				FirstBytePos: -1,
				LastBytePos:  suffixLength,
			})
		} else {
			firstBytePos, err := strconv.ParseInt(byteRangeSpec[:hyphenPos], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("value contains a byte-range-spec with an invalid or too large first-byte-pos: %w", err)
			}
			if hyphenPos+1 < len(byteRangeSpec) {
				lastBytePos, err := strconv.ParseInt(byteRangeSpec[hyphenPos+1:], 10, 64)
				if err != nil {
					return nil, fmt.Errorf("value contains a byte-range-spec with an invalid or too large last-byte-pos: %w", err)
				}
				ranges = append(ranges, Range{
					FirstBytePos: firstBytePos,
					LastBytePos:  lastBytePos,
				})
			} else {
				ranges = append(ranges, Range{
					FirstBytePos: firstBytePos,
					LastBytePos:  -1,
				})
			}
		}
		if commaPos < 0 {
			break
		}
		owsEnd := commaPos + 1
		for {
			if owsEnd == len(remainder) || (remainder[owsEnd] != ' ' && remainder[owsEnd] != '\t') {
				break
			}
			owsEnd++
		}
		remainder = remainder[owsEnd:]
	}
	return
}
