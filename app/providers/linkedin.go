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

func (a *LinkedinAuthProvider) AuthenticateBase(parent *AuthProvider, request *revel.Request, session *revel.Session) (resp AuthResponse, err error) {
	// validation has previously been done in Authenticate()
	theUrl, parseErr := url.ParseRequestURI(parent.AuthConfig.AuthorizeUrl)
	if parseErr != nil {
		err = fmt.Errorf("Bad URL in AuthorizeUrl: %s", parent.AuthConfig.AuthorizeUrl)
		return
	}

	// create a Map of all necessary params to pass to authenticator
	valueMap, err := MapAuthInitatorValues(parent)
	if err != nil {
		err = fmt.Errorf("Could not MapAuthInitatorValues: %+v", parent)
		return
	}

	theUrl.RawQuery = valueMap.Encode()

	return theUrl.String(), nil
}

func (a *LinkedinAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", parent.ConsumerKey)
	v.Set("scope", parent.Permissions)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("state", "gfhgdfhdgfhbfnfgngfddn")
	return

}

func (a *LinkedinAuthProvider) MapExchangeValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("client_secret", parent.ConsumerSecret)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("grant_type", "authorization_code")
	return
}
