package providers

import (
	//"errors"
	"fmt"
	"github.com/revel/revel"
	"net/url"
)

// GetAuthInitatorUrl generates the URL that begins the auth process with any common provider.
// At a minimum, the process requires:
// 	- an authorization URL, set in AuthCofig.AuthorizeUrl before invoking this method
// 	- the app's id with the authorizer, set in AuthConfig.ConsumerKey
// 	- a callback URL, set in AuthConfig.CallbackUrl
func (a *AuthProvider) GetAuthInitatorUrl(state *AuthState, options *RequestOptions) (returnUrl string, err error) {

	// validate key items to generate auth URL
	if a.AuthConfig.AuthorizeUrl == "" || a.AuthConfig.CallbackUrl == "" || a.AuthConfig.ConsumerKey == "" {
		err = fmt.Errorf("Missing required config info in GetAuthInitatorUrl: {AuthorizeUrl: %s, CallbackUrl: %s, ConsumerKey: %s}", a.AuthConfig.AuthorizeUrl, a.AuthConfig.CallbackUrl, a.AuthConfig.ConsumerKey)
		return
	}

	theUrl, parseErr := url.ParseRequestURI(a.AuthConfig.AuthorizeUrl)
	if parseErr != nil {
		err = fmt.Errorf("Bad URL in AuthorizeUrl: %s", a.AuthConfig.AuthorizeUrl)
		return
	}

	// TODO: validate state and options

	// create a Map of all necessary params to pass to authenticator
	revel.INFO.Print("Calling MapAuthConfigToStartAuthMap")
	valueMap := a.MapAuthConfigToStartAuthMap()
	revel.INFO.Printf("GetAuthInitatorUrl: %+v", valueMap)
	// convert state and add as a RequestOption
	if state != nil {
		//options["state"] = query.Values(state).Encode() // TODO: convert to JSON string?
	}

	// convert options into a QueryString
	if options != nil {
		//queryString, queryErr := query.Values(options)
		//if queryErr != nil {
		//	return "", queryErr
		//}
	}

	return theUrl.String(), nil
}
