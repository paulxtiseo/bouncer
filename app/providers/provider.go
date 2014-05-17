package providers

import (
	//"errors"
	"fmt"
	"github.com/revel/revel"
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
	valueMap, err := parent.MapAuthInitatorValues(parent)
	if err != nil {
		err = fmt.Errorf("Could not MapAuthInitatorValues: %+v", parent)
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

// ExchangeCodeForToken exchanges the code received from the first step of authentication for a token.
// At a minimum, the process requires:
// 	- an exchange URL, set in AuthConfig.AccessTokenUrl before invoking this method
// 	- the app's id with the authorizer, set in AuthConfig.ConsumerKey & AuthConfig.ConsumerSecret
func (a *CommonAuthProvider) ExchangeCodeForToken(state *AuthState, code string, parent *AuthProvider) (returnUrl string, err error) {

	if parent == nil {
		err = fmt.Errorf("No parent received: %+v", parent)
		return
	}

	// validate key items to generate auth URL
	if parent.AuthConfig.AccessTokenUrl == "" || parent.AuthConfig.ConsumerSecret == "" || parent.AuthConfig.ConsumerKey == "" {
		err = fmt.Errorf("Missing required config info in ExchangeCodeForToken: {AccessTokenUrl: %s, ConsumerSecret: %s, ConsumerKey: %s}", parent.AuthConfig.AccessTokenUrl, parent.AuthConfig.ConsumerSecret, parent.AuthConfig.ConsumerKey)
		return
	}

	theUrl, parseErr := url.ParseRequestURI(parent.AuthConfig.AccessTokenUrl)
	if parseErr != nil {
		err = fmt.Errorf("Bad URL in AccessTokenUrl: %s", parent.AuthConfig.AccessTokenUrl)
		return
	}

	// create a map of all necessary params to pass to authenticator
	valueMap, err := parent.MapExchangeValues(parent)
	if err != nil {
		err = fmt.Errorf("Could not MapExchangeValues: %+v", parent)
		return
	}

	// add passed in code
	valueMap.Add("code", code)

	// convert state and add to valueMap
	if state != nil {
		//options["state"] = query.Values(state).Encode() // TODO: convert to JSON string?
	}

	// push the whole valueMap into the URL instance
	theUrl.RawQuery = valueMap.Encode()

	// do the POST
	theJson, err := postRequestForJson(theUrl.Scheme+"://"+theUrl.Host+theUrl.Path, valueMap.Encode())

	return theJson, nil
}

// returns AuthResponse, where Response = "" means skip
func (a *CommonAuthProvider) Authenticate(parent *AuthProvider, params *revel.Params) (resp AuthResponse, err error) {

	// make sure we got all three params
	if parent == nil || request == nil || session == nil {
		err = fmt.Errorf("One or more params were nil: %v, %v, %v", parent, request, session)
		return
	}

	// check if already authenticated
	check, err := parent.IsAuthenticated()
	if err != nil {
		err = fmt.Errorf("Error in authenticated check: %+v", parent)
		return
	}
	if check { // user already authenticated
		return
	}

	// call into specialized AuthenticateBase()
	resp, err := parent.AuthenticateBase(parent*AuthProvider, request*Request, session*Session)
	if err != nil {
		err = fmt.Errorf("Error in AuthenticateBase: %v, %v, %v", parent, request, session)
		return
	}

	return
}

func (a *CommonAuthProvider) IsAuthenticated() (check bool, err error) {
	// TODO: finish it!
	return false, nil
}
