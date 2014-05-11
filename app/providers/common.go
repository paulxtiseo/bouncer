// Package providers contains primitives related to the authentication process
// provided by the Bouncer module for the Revel Framework.
package providers

import (
	"crypto/rand"
	"encoding/base64"
	"net/url"
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
	en := base64.StdEncoding
	d := make([]byte, en.EncodedLen(len(s)))
	en.Encode(d, s)
	return string(d)
}

// Compute an OAuth HMAC-SHA1 signature
func calculateOAuthSig(method string, baseUrl string, params *url.Values) string {
	return ""
}
