package providers

import (
	//"errors"
	"fmt"
	//"github.com/revel/revel"
	"net/url"
)

type CommonAuthProvider struct {
}

// GetAuthInitatorUrl generates the URL that begins the auth process with any common provider.
// At a minimum, the process requires:
// 	- an authorization URL, set in AuthConfig.AuthorizeUrl before invoking this method
// 	- the app's id with the authorizer, set in AuthConfig.ConsumerKey
// 	- a callback URL, set in AuthConfig.CallbackUrl
func (a *CommonAuthProvider) GetAuthInitatorUrl(state *AuthState, options *RequestOptions, parent *AuthProvider) (returnUrl string, err error) {

	if parent == nil {
		err = fmt.Errorf("No parent received: %+v", parent)
		return
	}

	// validate key items to generate auth URL
	if parent.AuthConfig.AuthorizeUrl == "" || parent.AuthConfig.CallbackUrl == "" || parent.AuthConfig.ConsumerKey == "" {
		err = fmt.Errorf("Missing required config info in GetAuthInitatorUrl: {AuthorizeUrl: %s, CallbackUrl: %s, ConsumerKey: %s}", parent.AuthConfig.AuthorizeUrl, parent.AuthConfig.CallbackUrl, parent.AuthConfig.ConsumerKey)
		return
	}

	theUrl, parseErr := url.ParseRequestURI(parent.AuthConfig.AuthorizeUrl)
	if parseErr != nil {
		err = fmt.Errorf("Bad URL in AuthorizeUrl: %s", parent.AuthConfig.AuthorizeUrl)
		return
	}

	// TODO: validate state and options

	// create a Map of all necessary params to pass to authenticator
	valueMap, err := parent.MapAuthConfigToUrlValues(parent)
	if err != nil {
		err = fmt.Errorf("Could not MapAuthConfigToUrlValues: %+v", parent)
		return
	}

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

	theUrl.RawQuery = valueMap.Encode()

	return theUrl.String(), nil
}
