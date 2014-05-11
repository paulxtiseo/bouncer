package providers

import (
	"net/url"
)

// -- generator function ----

func NewLinkedinAuthProvider(config *AuthConfig) AuthProvider {

	p := new(AuthProvider)
	p.AuthConfig = *config
	p.Name = "Facebook"

	c := new(CommonAuthProvider)
	p.CommonAuthProvider = *c

	p.SpecializedAuthorizer = new(LinkedinAuthProvider)

	return *p
}

// -- provider ----
type LinkedinAuthProvider struct {
}

func (a *LinkedinAuthProvider) MapAuthConfigToUrlValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", parent.ConsumerKey)
	v.Set("scope", parent.Permissions)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("state", "gfhgdfhdgfhbfnfgngfddn")
	return

}

func (a *LinkedinAuthProvider) ConfirmAuth(parent *AuthProvider) (v url.Values, err error) {
	v = url.Values{}
	return
}
