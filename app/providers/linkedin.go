package providers

import (
	"net/url"
	"strings"
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
	v.Add("client_id", parent.ConsumerKey)
	v.Add("redirect_uri", parent.CallbackUrl)
	// TODO: state?
	v.Add("reponse_type", "code")
	perms := strings.Split(parent.Permissions, ",")
	for idx := 0; idx < len(perms); idx++ {
		v.Add("scope", perms[idx])
	}
	return

}
