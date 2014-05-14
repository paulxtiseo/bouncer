// Package providers contains primitives related to the authentication process
// provided by the Bouncer module for the Revel Framework.
package providers

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	//"github.com/revel/revel"
	"net/url"
	"sort"
	"strings"
)

type AuthConfig struct {
	Name            string
	CallbackUrl     string
	ConsumerKey     string
	ConsumerSecret  string
	RequestTokenUrl string
	AuthorizeUrl    string
	AccessTokenUrl  string
	Permissions     string
}

type AuthState struct {
	KeyValues map[string]string
}

type RequestOptions struct {
	KeyValues map[string]string
}

type AuthProvider struct {
	AuthConfig
	CommonAuthProvider
	SpecializedAuthorizer
}

//----- interfaces ----------------

type Authorizer interface {
	CommonAuthorizer
	SpecializedAuthorizer
}

type CommonAuthorizer interface {
	GetAuthInitatorUrl(state *AuthState, options *RequestOptions, parent AuthProvider) (returnUrl string, err error)
}

type SpecializedAuthorizer interface {
	MapAuthConfigToUrlValues(parent *AuthProvider) (v url.Values, err error)
}

//----- function types ----------------

// NewAuthProvider is a generic function type that returns a struct that implements the Authorizer interface
// Given an AuthConfig struct, the Authorizer returned will also be pre-configured for use
type NewAuthProvider func(*AuthConfig) AuthProvider

//----- private functions ----------------

func generateNonce(size int) string {
	s := make([]byte, size)
	rand.Read(s)

	enc := base64.StdEncoding
	d := make([]byte, enc.EncodedLen(len(s)))
	enc.Encode(d, s)

	return string(d)
}

// Compute an OAuth HMAC-SHA1 signature based on request method, URL (unescaped), params, the app/consumer key and a token (optional)
func calculateOAuthSig(method string, baseUrl string, params *url.Values, key string, token string) (msg string, err error) {

	if method == "" {
		err = errors.New("No method provided.")
		return
	}

	if baseUrl == "" {
		err = errors.New("No baseUrl provided.")
		return
	}

	if key == "" {
		err = errors.New("No key provided.")
		return
	}

	base := escape(strings.ToUpper(method), encodeEverything) + "&" + escape(baseUrl, encodeEverything) + "&" + escape(encode(params), encodeEverything)
	sign := escape(key, encodeEverything) + "&" + escape(token, encodeEverything)

	enc := hmac.New(sha1.New, []byte(sign))
	enc.Write([]byte(base))
	return base64.StdEncoding.EncodeToString(enc.Sum(nil)), nil
}

//----- extracted from net/url for modding; needed access to the private escape() and shouldEscape() ----------------

type encoding int

const (
	encodePath encoding = 1 + iota
	encodeUserPassword
	encodeQueryComponent
	encodeFragment
	encodeEverything // added this relative to original net/url, such that space is encoded to %20 not +
)

func encode(vals *url.Values) string {

	v := *vals

	if v == nil {
		return ""
	}

	var buf bytes.Buffer
	keys := make([]string, 0, len(v))
	for k := range v {
		keys = append(keys, k)
	}

	sort.Strings(keys)

	for _, k := range keys {
		vs := v[k]
		prefix := escape(k, encodeEverything) + "="
		for _, v := range vs {
			if buf.Len() > 0 {
				buf.WriteByte('&')
			}
			buf.WriteString(prefix)
			buf.WriteString(escape(v, encodeEverything))
		}
	}

	return buf.String()
}

func escape(s string, mode encoding) string {
	spaceCount, hexCount := 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if shouldEscape(c, mode) {
			if c == ' ' && mode == encodeQueryComponent {
				spaceCount++
			} else {
				hexCount++
			}
		}
	}

	if spaceCount == 0 && hexCount == 0 {
		return s
	}

	t := make([]byte, len(s)+2*hexCount)
	j := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == ' ' && mode == encodeQueryComponent:
			t[j] = '+'
			j++
		case shouldEscape(c, mode):
			t[j] = '%'
			t[j+1] = "0123456789ABCDEF"[c>>4]
			t[j+2] = "0123456789ABCDEF"[c&15]
			j += 3
		default:
			t[j] = s[i]
			j++
		}
	}
	return string(t)
}

func shouldEscape(c byte, mode encoding) bool {

	if 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' {
		return false
	}

	switch c {
	case '-', '_', '.', '~': // §2.3 Unreserved characters (mark)
		return false

	case '$', '&', '+', ',', '/', ':', ';', '=', '?', '@': // §2.2 Reserved characters (reserved)
		// Different sections of the URL allow a few of
		// the reserved characters to appear unescaped.
		switch mode {
		case encodePath: // §3.3
			// The RFC allows : @ & = + $ but saves / ; , for assigning
			// meaning to individual path segments. This package
			// only manipulates the path as a whole, so we allow those
			// last two as well. That leaves only ? to escape.
			return c == '?'

		case encodeUserPassword: // §3.2.2
			// The RFC allows ; : & = + $ , in userinfo, so we must escape only @ and /.
			// The parsing of userinfo treats : as special so we must escape that too.
			return c == '@' || c == '/' || c == ':'

		case encodeQueryComponent: // §3.4
			// The RFC reserves (so we must escape) everything.
			return true

		case encodeEverything: // §3.4
			// Added this option to encode everything; net/url code converts space to '+'
			return true

		case encodeFragment: // §4.1
			// The RFC text is silent but the grammar allows everything, so escape nothing.
			return false
		}
	}

	// Everything else must be escaped.
	return true
}
