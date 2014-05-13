// Package providers contains primitives related to the authentication process
// provided by the Bouncer module for the Revel Framework.
package providers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"github.com/revel/revel"
	"net/url"
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

	base := url.QueryEscape(strings.ToUpper(method)) + "&" + url.QueryEscape(baseUrl) + "&" + url.QueryEscape(params.Encode())
	revel.INFO.Println("calculateOAuthSig params: " + strings.Replace(params.Encode(), "%", "%%", -1))
	revel.INFO.Println("calculateOAuthSig params: " + strings.Replace(params.Encode(), "%", "%%", -1))
	revel.INFO.Println("calculateOAuthSig base: " + strings.Replace(strings.ToUpper(method), "%", "%%", -1) + "&" + strings.Replace(url.QueryEscape(baseUrl), "%", "%%", -1) + "&" + strings.Replace(url.QueryEscape(params.Encode()), "%", "%%", -1))
	sign := url.QueryEscape(key) + "&" + url.QueryEscape(token)
	revel.INFO.Println("calculateOAuthSig sign: " + strings.Replace(url.QueryEscape(key), "%", "%%", -1) + "&" + strings.Replace(url.QueryEscape(token), "%", "%%", -1))

	enc := hmac.New(sha1.New, []byte(sign))
	enc.Write([]byte(base))
	revel.INFO.Println("calculateOAuthSig return: " + base64.StdEncoding.EncodeToString(enc.Sum(nil)))
	return base64.StdEncoding.EncodeToString(enc.Sum(nil)), nil
}
