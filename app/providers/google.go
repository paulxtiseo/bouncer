package providers

import (
	"fmt"
	"github.com/revel/revel"
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

func (a *GoogleAuthProvider) AuthenticateBase(parent *AuthProvider, params *revel.Params) (resp AuthResponse, err error) {
	// validation has previously been done in Authenticate(); we've checked if we have a token
	// if we do not, we are authenticating; check if we have a code, else first we are at step
	code := params.Get("code")
	revel.INFO.Printf("Configured %s for authentication.", code)
	if code != "" {
		// we have no token, so begin authorization
		theUrl, parseErr := url.ParseRequestURI(parent.AuthConfig.AuthorizeUrl)
		if parseErr != nil {
			err = fmt.Errorf("Bad URL in AuthorizeUrl: %s", parent.AuthConfig.AuthorizeUrl)
			return
		}

		// create a Map of all necessary params to pass to authenticator
		valueMap, err := parent.MapAuthInitatorValues(parent)
		if err != nil {
			err = fmt.Errorf("Could not MapAuthInitatorValues: %+v", parent)
			return
		}

		theUrl.RawQuery = valueMap.Encode()
		resp, err := AuthResponse{Type: AuthResponseRedirect, Response: theUrl.String()}
		return
	}
	return
}

func (a *GoogleAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", parent.ConsumerKey)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("scope", parent.Permissions)
	v.Set("state", "MapAuthConfigToUrlValues")
	return

}

func (a *GoogleAuthProvider) MapExchangeValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("client_secret", parent.ConsumerSecret)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("grant_type", "authorization_code")
	return

}
