package providers

import (
	"net/url"
)

// -- generator function ----

func NewGoogleAuthProvider(config *AuthConfig) AuthProvider {

	p := new(AuthProvider)
	p.AuthConfig = *config
	p.Name = "Facebook"

	c := new(CommonAuthProvider)
	p.CommonAuthProvider = *c

	p.SpecializedAuthorizer = new(GoogleAuthProvider)

	return *p
}

// -- provider ----
type GoogleAuthProvider struct {
}

func (a *GoogleAuthProvider) MapAuthConfigToUrlValues(parent *AuthProvider) (v url.Values, err error) {
	v = url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", parent.ConsumerKey)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("scope", parent.Permissions)
	return
}
