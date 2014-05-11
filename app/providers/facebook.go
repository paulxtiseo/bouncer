package providers

import (
	"net/url"
)

// -- generator function ----

func NewFacebookAuthProvider(config *AuthConfig) AuthProvider {

	p := new(AuthProvider)
	p.AuthConfig = *config
	p.Name = "Facebook"

	c := new(CommonAuthProvider)
	p.CommonAuthProvider = *c

	p.SpecializedAuthorizer = new(FacebookAuthProvider)

	return *p
}

// -- provider ----
type FacebookAuthProvider struct {
}

func (a *FacebookAuthProvider) MapAuthConfigToUrlValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("response_type", "code")
	v.Set("scope", parent.Permissions)
	v.Set("state", "gfhgdfhdgfhbfnfgngfddn")
	return

}

func (a *FacebookAuthProvider) ConfirmAuth(parent *AuthProvider) (v url.Values, err error) {
	v = url.Values{}
	return
}
