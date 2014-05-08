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
	v.Add("client_id", parent.ConsumerKey)
	v.Add("redirect_uri", parent.CallbackUrl)
	v.Add("reponse_type", "code")
	v.Set("scope", parent.Permissions)
	return

}
