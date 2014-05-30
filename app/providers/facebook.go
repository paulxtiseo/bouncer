package providers

import (
	//"fmt"
	"github.com/revel/revel"
	"net/url"
	"regexp"
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

func (a *FacebookAuthProvider) AuthenticateBase(parent *AuthProvider, params *revel.Params) (resp AuthResponse, err error) {
	// assumption: validation has previously been done revel.OnAppStart() and then in in Authenticate()
	errorCode := params.Get("error_code")
	if errorCode != "" {
		resp = AuthResponse{Type: AuthResponseError, Response: params.Get("error_message")}
		return resp, err
	}

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
		valueMap, _ := parent.MapExchangeValues(parent, code, "")

		// push the whole valueMap into the URL instance
		theUrl.RawQuery = valueMap.Encode()

		// do the POST, then post
		theJson, err := postRequestForJson(theUrl.Scheme+"://"+theUrl.Host+theUrl.Path, valueMap.Encode())
		if err != nil {
			resp = AuthResponse{Type: AuthResponseError, Response: err.Error()}
			return resp, err
		}

		// parse response and return a standard JSON string; Facebook response is form-urlencoded
		tokenRe := regexp.MustCompile(`access_token=([^&]+)`)
		tokens := tokenRe.FindStringSubmatch(theJson)
		if len(tokens) != 2 {
			resp = AuthResponse{Type: AuthResponseError, Response: "Bad match on access token in FacebookAuthProvider"}
			return resp, err
		}
		token := tokens[1]

		expiresRe := regexp.MustCompile(`expires=([^&]+)`)
		expires := expiresRe.FindStringSubmatch(theJson)
		if len(expires) != 2 {
			resp = AuthResponse{Type: AuthResponseError, Response: "Bad match on expires in FacebookAuthProvider"}
			return resp, err
		}
		expire := expires[1]

		resp = AuthResponse{Type: AuthResponseToken, Response: `{"token":"` + token + `", "expires":` + expire + `}`}
		return resp, err

	}

}

func (a *FacebookAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("response_type", "code")
	v.Set("scope", parent.Permissions)
	return

}

func (a *FacebookAuthProvider) MapExchangeValues(parent *AuthProvider, token string, verifier string) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("client_secret", parent.ConsumerSecret)
	v.Set("code", token)
	v.Set("redirect_uri", parent.CallbackUrl)
	return
}
