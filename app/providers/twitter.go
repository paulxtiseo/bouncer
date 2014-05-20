package providers

import (
	//"fmt"
	"github.com/revel/revel"
	"net/url"
	"strconv"
	//"strings"
	"time"
)

// -- generator function ----

func NewTwitterAuthProvider(config *AuthConfig) AuthProvider {

	p := new(AuthProvider)
	p.AuthConfig = *config
	p.Name = "Facebook"

	c := new(CommonAuthProvider)
	p.CommonAuthProvider = *c

	p.SpecializedAuthorizer = new(TwitterAuthProvider)

	return *p
}

// -- provider ----
type TwitterAuthProvider struct {
}

func (a *TwitterAuthProvider) AuthenticateBase(parent *AuthProvider, params *revel.Params) (resp AuthResponse, err error) {
	// assumption: validation has previously been done revel.OnAppStart() and then in in Authenticate()
	code := params.Get("code")
	if code == "" {
		// we have no token, so begin authorization
		theUrl, _ := url.ParseRequestURI(parent.AuthConfig.AuthorizeUrl)

		// create a Map of all necessary params to pass to authenticator
		valueMap, _ := parent.MapAuthInitatorValues(parent)

		theUrl.RawQuery = valueMap.Encode()
		resp = AuthResponse{Type: AuthResponseRedirect, Response: theUrl.String()}
		return resp, err
	} else {
		// we have a code, so it's exchange time!
		theUrl, _ := url.ParseRequestURI(parent.AuthConfig.AccessTokenUrl)

		// create a map of all necessary params to pass to authenticator
		valueMap, _ := parent.MapExchangeValues(parent)

		// add passed in code
		valueMap.Add("code", code)

		// push the whole valueMap into the URL instance
		theUrl.RawQuery = valueMap.Encode()

		// do the POST, then post
		theJson, err := postRequestForJson(theUrl.Scheme+"://"+theUrl.Host+theUrl.Path, valueMap.Encode())
		if err != nil {
			resp = AuthResponse{Type: AuthResponseString, Response: theJson}
			return resp, err
		} else {
			resp = AuthResponse{Type: AuthResponseError, Response: theJson}
			return resp, err
		}

	}
}

func (a *TwitterAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("oauth_callback", parent.CallbackUrl)
	v.Set("oauth_consumer_key", parent.ConsumerKey)
	v.Set("oauth_nonce", generateNonce(32))
	v.Set("oauth_signature_method", "HMAC-SHA1")
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("oauth_version", "1.0")
	// calculate signature
	msg, _ := calculateOAuthSig("GET", parent.AuthorizeUrl, &v, parent.ConsumerSecret, "")
	v.Set("oauth_signature", msg)
	return
}

func (a *TwitterAuthProvider) MapExchangeValues(parent *AuthProvider) (v url.Values, err error) {
	v = url.Values{}
	return
}
