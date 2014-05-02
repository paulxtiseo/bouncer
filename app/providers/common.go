// Package providers contains primitives related to the authentication process
// provided by the Bouncer module for the Revel Framework.
package providers

type AuthConfig struct {
	AuthRealm       string
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
	Authorizer
}

//----- functions ----------------

// NewAuthProvider is a generic function type that returns a struct that implements the Authorizer interface
// Given an AuthConfig struct, the Authorizer returned will also be pre-configured for use
type NewAuthProvider func(*AuthConfig) Authorizer

//----- interfaces ----------------

type Authorizer interface {
	GetAuthInitatorUrl(state *AuthState, options *RequestOptions) (url string, err error)
	MapAuthConfigToStartAuthMap() (v map[string][]string)
}
