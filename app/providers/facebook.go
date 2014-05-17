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

func (a *FacebookAuthProvider) AuthenticateBase(parent *AuthProvider, request *revel.Request, session *revel.Session) (resp AuthResponse, err error) {
	// validation has previously been done in Authenticate()
	if
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

func (a *FacebookAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("response_type", "code")
	v.Set("scope", parent.Permissions)
	v.Set("state", "gfhgdfhdgfhbfnfgngfddn")
	return

}

func (a *FacebookAuthProvider) MapExchangeValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("client_secret", parent.ConsumerSecret)
	v.Set("redirect_uri", parent.CallbackUrl)
	return
}
