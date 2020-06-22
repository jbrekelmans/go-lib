package http

import (
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/http/httpguts"
)

type octetFlags byte

const (
	octetFlagToken octetFlags = 1 << iota
	octetFlagToken68Head
)

var octetFlagArray [256]octetFlags

func init() {
	for i := 0; i < 256; i++ {
		octetFlagArray[i] = 0
		if i < 0x80 && httpguts.IsTokenRune(rune(i)) {
			octetFlagArray[i] |= octetFlagToken
		}
		if isToken68Head(i) {
			octetFlagArray[i] |= octetFlagToken68Head
		}
	}
}

func isToken68Head(b int) bool {
	switch b {
	case '-', '.', '_', '~', '+', '/':
		return true
	}
	return ('a' <= b && b <= 'z') || ('A' <= b && b <= 'Z') || ('0' <= b && b <= '9')
}

// IsToken returns true if and only if val is a valid token as per https://tools.ietf.org/html/rfc7230.
func IsToken(val string) bool {
	return httpguts.ValidHeaderFieldName(val)
}

func IsToken68(val string) bool {
	n := len(val)
	if n == 0 {
		return false
	}
	if (octetFlagArray[val[0]] & octetFlagToken68Head) == 0 {
		return false
	}
	i := 1
	for {
		if i == n {
			return true
		}
		if (octetFlagArray[val[i]] & octetFlagToken68Head) == 0 {
			break
		}
		i++
	}
	for {
		if val[i] != '=' {
			return false
		}
		i++
		if i == n {
			return true
		}
	}
}

// IsTokenRune returns true if and only if r can be part of a sequence of characters that is a valid token
// as per https://tools.ietf.org/html/rfc7230.
func IsTokenRune(r rune) bool {
	return r < 0x7F && (octetFlagArray[int(r)]&octetFlagToken) != 0
}

// Param represents a parameter that is commonly part of header values.
type Param struct {
	Attribute string
	Value     string
}

type parser struct {
	b           int
	headerValue string
	pos         int
}

func (p *parser) authParam() (arg *Param, err error) {
	posStart1 := p.pos
	if err = p.expectTokenOctet(); err != nil {
		return
	}
	defer func() {
		if err != nil {
			p.pos = posStart1
		}
	}()
	for p.isTokenOctet() {
		p.next()
	}
	attribute := p.headerValue[posStart1:p.pos]
	p.ows()
	if err = p.expectOctet('='); err != nil {
		return
	}
	p.ows()
	var value string
	if p.b == '"' {
		var sb strings.Builder
	L:
		for {
			p.next()
			switch p.b {
			case '"':
				break L
			case '\\':
				p.next()
				if (p.b < ' ' && p.b != '\t') || p.b == 0x7F {
					if p.b < 0 {
						err = fmt.Errorf("incomplete quoted-pair")
					} else {
						err = fmt.Errorf("unexpected octet %#x at position %d", p.b, p.pos)
					}
					return
				}
				sb.WriteByte(byte(p.b))
			case '\x7F':
				err = fmt.Errorf("unexpected octet %#x at position %d", p.b, p.pos)
				return
			default:
				if p.b < ' ' && p.b != '\t' {
					if p.b < 0 {
						err = fmt.Errorf("unterminated quoted-string")
					} else {
						err = fmt.Errorf("unexpected octet %#x at position %d", p.b, p.pos)
					}
					return
				}
				sb.WriteByte(byte(p.b))
			}
		}
		p.next()
		value = sb.String()
	} else {
		posStart2 := p.pos
		if err = p.expectTokenOctet(); err != nil {
			return
		}
		for p.isTokenOctet() {
			p.next()
		}
		value = p.headerValue[posStart2:p.pos]
	}
	arg = &Param{
		Attribute: attribute,
		Value:     value,
	}
	return
}

func (p *parser) challenge() (challenge2 *Challenge, hasTrailingComma bool, err error) {
	posStart := p.pos
	if err = p.expectTokenOctet(); err != nil {
		return
	}
	for p.isTokenOctet() {
		p.next()
	}
	challenge1 := &Challenge{}
	challenge1.Scheme = p.headerValue[posStart:p.pos]
	if p.b == ' ' {
	L:
		for {
			p.next()
			switch p.b {
			case -1:
				challenge2 = challenge1
				return
			case ' ':
			case ',':
				hasTrailingComma = true
				break L
			default:
				var authParam *Param
				authParam, err = p.authParam()
				if err != nil {
					if (octetFlagArray[p.b] & octetFlagToken68Head) != 0 {
						posStart = p.pos
						for {
							p.next()
							if p.b < 0 {
								break
							}
							if (octetFlagArray[p.b] & octetFlagToken68Head) == 0 {
								for p.b == '=' {
									p.next()
								}
								break
							}
						}
						token68 := p.headerValue[posStart:p.pos]
						challenge1.Token68 = token68
						challenge2 = challenge1
						return
					}
					err = fmt.Errorf("expected auth-param, comma or token68 at position %d but got octet %#x and error while parsing "+
						"auth-param: %w", p.pos, p.b, err)
					return
				}
				challenge1.Params = append(challenge1.Params, authParam)
				break L
			}
		}
		for {
			posStart = p.pos
			p.ows()
			if p.b != ',' {
				p.pos = posStart
				break
			}
			p.next()
			hasTrailingComma = true
			posStart = p.pos
			p.ows()
			authParam, err2 := p.authParam()
			if err2 != nil {
				p.pos = posStart
				continue
			}
			challenge1.Params = append(challenge1.Params, authParam)
			hasTrailingComma = false
		}
	}
	challenge2 = challenge1
	return
}

func (p *parser) expectEOF() error {
	if p.pos == len(p.headerValue) {
		return nil
	}
	return fmt.Errorf("unexpected octet %#x at position %d", p.b, p.pos)
}

func (p *parser) expectOctet(b int) error {
	if p.b != b {
		if p.b == -1 {
			return fmt.Errorf("expected octet %#x at position %d but there are no more octets", b, p.pos)
		}
		return fmt.Errorf("expected octet %#x at position %d but got octet %#x", b, p.pos, p.b)
	}
	p.next()
	return nil
}

func (p *parser) expectTokenOctet() error {
	if p.isTokenOctet() {
		p.next()
		return nil
	}
	if p.b >= 0 {
		return fmt.Errorf("expected token character at position %d but got octet %#x", p.pos, p.b)
	}
	return fmt.Errorf("expected token character at position %d but there are no more octets", p.pos)
}

func (p *parser) isTokenOctet() bool {
	return 0 <= p.b && (octetFlagArray[p.b]&octetFlagToken) != 0
}

func (p *parser) next() {
	if p.pos == len(p.headerValue) {
		return
	}
	p.pos++
	if p.pos == len(p.headerValue) {
		p.b = -1
		return
	}
	p.b = int(p.headerValue[p.pos])
}

func (p *parser) ows() {
	for p.b == ' ' || p.b == '\t' {
		p.next()
	}
}

func (p *parser) wwwAuthenticate(r []*Challenge) (challenges []*Challenge, hasTrailingComma bool, err error) {
	posStart := p.pos
	for p.b == ',' {
		p.next()
		p.ows()
	}
	challenge, hasTrailingComma, err := p.challenge()
	if err != nil {
		p.pos = posStart
		return
	}
	challenges = append(r, challenge)
	for {
		if !hasTrailingComma {
			posStart = p.pos
			p.ows()
			if p.b != ',' {
				p.pos = posStart
				break
			}
			p.next()
		}
		posStart = p.pos
		p.ows()
		challenge, hasTrailingComma, err = p.challenge()
		if err != nil {
			p.pos = posStart
			continue
		}
		challenges = append(challenges, challenge)
	}
	return
}

func ParseWwwAuthenticateHeaders(header http.Header) ([]*Challenge, error) {
	var challenges []*Challenge
	for i, headerValue := range header.Values(HeaderNameWWWAuthenticate) {
		var err error
		challenges, err = ParseWwwAuthenticateHeaderValue(challenges, headerValue)
		if err != nil {
			return nil, fmt.Errorf("error parsing header[%#v][%d]: %w", HeaderNameWWWAuthenticate, i, err)
		}
	}
	return challenges, nil
}

func ParseWwwAuthenticateHeaderValue(r []*Challenge, headerValue string) ([]*Challenge, error) {
	p := parser{
		headerValue: headerValue,
		pos:         -1,
	}
	p.next()
	challenges, _, err := p.wwwAuthenticate(r)
	if err != nil {
		return nil, err
	}
	if err := p.expectEOF(); err != nil {
		return nil, err
	}
	return challenges, nil
}

// ValidateFormattableAsQuotedPair returns nil iff val can be formatted as a quoted pair (as defined in https://tools.ietf.org/html/rfc7230)
// that parses into val.
func ValidateFormattableAsQuotedPair(val string) error {
	var sb strings.Builder
	return WriteQuotedPair(&sb, val)
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
