package providers

import (
	//"fmt"
	//"errors"
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
	p.Name = "Twitter"

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
	errorCode := params.Get("error_code")
	if errorCode != "" {
		resp = AuthResponse{Type: AuthResponseError, Response: params.Get("error_message")}
		return resp, err
	}

	token := params.Get("oauth_token")
	verifier := params.Get("oauth_verifier")

	if token == "" && verifier == "" { // Step 1: obtain a request token and redirect user
		theUrl, _ := url.ParseRequestURI(parent.AuthConfig.RequestTokenUrl)
		// create a Map of all necessary params to pass to authenticator
		valueMap, _ := parent.MapAuthInitatorValues(parent)
		theUrl.RawQuery = valueMap.Encode()

		// do the POST to get the oauth_token
		theJson, err := postRequestForJson(theUrl.Scheme+"://"+theUrl.Host+theUrl.Path, valueMap.Encode())
		if err != nil {
			resp = AuthResponse{Type: AuthResponseError, Response: err.Error()}
			return resp, err
		}

		// extract oauth_token out of theJson (which is not JSON, but rather a querystring)
		vals, err := url.ParseQuery(theJson)
		if err != nil {
			resp = AuthResponse{Type: AuthResponseError, Response: err.Error()}
			return resp, err
		}

		token := vals.Get("oauth_token")
		if token == "" {
			resp = AuthResponse{Type: AuthResponseError, Response: "No oauth token found in token request to Twitter."}
			return resp, err
		}

		// redirect user to authenticate
		redirectUrl, _ := url.ParseRequestURI(parent.AuthConfig.AuthorizeUrl)
		v := url.Values{}
		v.Set("oauth_token", token)
		redirectUrl.RawQuery = v.Encode()
		resp = AuthResponse{Type: AuthResponseRedirect, Response: redirectUrl.String()}
		return resp, err

	} else {
		// we have a token and verifier, so it's exchange time!
		theUrl, _ := url.ParseRequestURI(parent.AuthConfig.AccessTokenUrl)

		// create a map of all necessary params to pass to authenticator
		valueMap, _ := parent.MapExchangeValues(parent, token, verifier)

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

func (a *TwitterAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("oauth_callback", parent.CallbackUrl)
	v.Set("oauth_consumer_key", parent.ConsumerKey)
	v.Set("oauth_nonce", generateNonce(32))
	v.Set("oauth_signature_method", "HMAC-SHA1")
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("oauth_version", "1.0")
	// calculate signature
	msg, _ := calculateOAuthSig("POST", parent.RequestTokenUrl, &v, parent.ConsumerSecret, "")
	v.Set("oauth_signature", msg)
	return
}

func (a *TwitterAuthProvider) MapExchangeValues(parent *AuthProvider, token string, verifier string) (v url.Values, err error) {
	v = url.Values{}
	v.Set("oauth_consumer_key", parent.ConsumerKey)
	v.Set("oauth_nonce", generateNonce(32))
	v.Set("oauth_signature_method", "HMAC-SHA1")
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("oauth_token", token)
	v.Set("oauth_version", "1.0")
	v.Set("oauth_verifier", verifier)
	// calculate signature
	msg, _ := calculateOAuthSig("POST", parent.AuthConfig.AccessTokenUrl, &v, parent.ConsumerSecret, "")
	v.Set("oauth_signature", msg)
	return
}
