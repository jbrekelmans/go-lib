package http

import (
	"fmt"
	"strings"

	"golang.org/x/net/http/httpguts"
)

// IsToken returns true if and only if val is a valid token as per https://tools.ietf.org/html/rfc7230.
func IsToken(val string) bool {
	return httpguts.ValidHeaderFieldName(val)
}

// Param represents a parameter that is commonly part of header values.
type Param struct {
	Attribute string
	Value     string
}

// WriteQuotedPair writes a quoted-pair production as defined in https://tools.ietf.org/html/rfc7230 that parses into val to sb.
func WriteQuotedPair(sb *strings.Builder, val string) error {
	sb.WriteByte('"')
	for i := 0; i < len(val); i++ {
		byte := val[i]
		switch {
		case (byte != '\t' && byte < 0x20) || byte == 0x7F: // ASCII control characters except tab
			return fmt.Errorf("value contains ASCII control character (decimal %d)", byte)
		case byte == '"' || byte == '\\':
			sb.WriteByte('\\')
			sb.WriteByte(byte)
		default:
			sb.WriteByte(byte)
		}
	}
	sb.WriteByte('"')
	return nil
}

// WriteQuotedPairWouldWriteBackslashes returns true iff val contains a double quote or backslash character.
func WriteQuotedPairWouldWriteBackslashes(val string) bool {
	return strings.ContainsAny(val, `"\`)
}
