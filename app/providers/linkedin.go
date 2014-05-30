package providers

import (
	//"fmt"
	"github.com/revel/revel"
	"net/url"
)

// -- generator function ----

func NewLinkedinAuthProvider(config *AuthConfig) AuthProvider {

	p := new(AuthProvider)
	p.AuthConfig = *config
	p.Name = "LinkedIn"

	c := new(CommonAuthProvider)
	p.CommonAuthProvider = *c

	p.SpecializedAuthorizer = new(LinkedinAuthProvider)

	return *p
}

// -- provider ----
type LinkedinAuthProvider struct {
}

func (a *LinkedinAuthProvider) AuthenticateBase(parent *AuthProvider, params *revel.Params) (resp AuthResponse, err error) {
	// assumption: validation has previously been done revel.OnAppStart() and then in in Authenticate()
	errorCode := params.Get("error")
	if errorCode != "" {
		resp = AuthResponse{Type: AuthResponseError, Response: params.Get("error_description")}
		return resp, err
	}

	code := params.Get("code")
	if code == "" {
		// we have no token, so begin authorization
		theUrl, _ := url.ParseRequestURI(parent.AuthConfig.AuthorizeUrl)

		// create a Map of all necessary params to pass to authenticator
		valueMap, _ := parent.MapAuthInitatorValues(parent)
		valueMap.Add("state", "blahblahblah")

		theUrl.RawQuery = valueMap.Encode()
		resp = AuthResponse{Type: AuthResponseRedirect, Response: theUrl.String()}
		return resp, err
	} else {
		// we have a code, so it's exchange time!
		theUrl, _ := url.ParseRequestURI(parent.AuthConfig.AccessTokenUrl)

		// create a map of all necessary params to pass to authenticator
		valueMap, _ := parent.MapExchangeValues(parent, code, "")
		valueMap.Add("state", "blahblahblah")

		// push the whole valueMap into the URL instance
		theUrl.RawQuery = valueMap.Encode()

		// do the POST, then post
		theJson, err := postRequestForJson(theUrl.Scheme+"://"+theUrl.Host+theUrl.Path, valueMap.Encode())
		if err == nil {
			resp = AuthResponse{Type: AuthResponseString, Response: theJson}
			return resp, err
		} else {
			resp = AuthResponse{Type: AuthResponseError, Response: err.Error()}
			return resp, err
		}
	}
}

func (a *LinkedinAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", parent.ConsumerKey)
	v.Set("scope", parent.Permissions)
	v.Set("redirect_uri", parent.CallbackUrl)
	return

}

func (a *LinkedinAuthProvider) MapExchangeValues(parent *AuthProvider, token string, verifier string) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("client_secret", parent.ConsumerSecret)
	v.Set("code", token)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("grant_type", "authorization_code")
	return
}
