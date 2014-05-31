package providers

import (
	//"fmt"
	"github.com/revel/revel"
	"net/url"
	"regexp"
)

// -- generator function ----

func NewGoogleAuthProvider(config *AuthConfig) AuthProvider {

	p := new(AuthProvider)
	p.AuthConfig = *config
	p.Name = "Google"

	c := new(CommonAuthProvider)
	p.CommonAuthProvider = *c

	p.SpecializedAuthorizer = new(GoogleAuthProvider)

	return *p
}

// -- provider ----
type GoogleAuthProvider struct {
}

func (a *GoogleAuthProvider) AuthenticateBase(parent *AuthProvider, params *revel.Params) (resp AuthResponse, err error) {
	// assumption: validation has previously been done revel.OnAppStart() and then in in Authenticate()
	errorCode := params.Get("error")
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
		reply, err := postRequestForJson(theUrl.Scheme+"://"+theUrl.Host+theUrl.Path, valueMap.Encode())
		if err != nil {
			resp = AuthResponse{Type: AuthResponseError, Response: err.Error()}
			return resp, err
		}

		// parse response and return an expected JSON string; Google response is in JSON format
		tokenRe := regexp.MustCompile(`"access_token"\s*:\s*"([\S]+)"`)
		tokens := tokenRe.FindStringSubmatch(reply)
		if len(tokens) != 2 {
			revel.ERROR.Printf("GoogleAuthProvider failed access_token match: %s\n\n", reply)
			resp = AuthResponse{Type: AuthResponseError, Response: "Bad match on access token in GoogleAuthProvider"}
			return resp, err
		}
		token := tokens[1]

		expiresRe := regexp.MustCompile(`"expires_in"\s*:\s*(\d+)`)
		expires := expiresRe.FindStringSubmatch(reply)
		if len(expires) != 2 {
			revel.ERROR.Printf("GoogleAuthProvider failed expires_in match: %s\n\n", reply)
			resp = AuthResponse{Type: AuthResponseError, Response: "Bad match on expires in GoogleAuthProvider"}
			return resp, err
		}
		expire := expires[1]

		resp = AuthResponse{Type: AuthResponseToken, Response: `{"token":"` + token + `", "expires":` + expire + `}`}
		return resp, err
	}
}

func (a *GoogleAuthProvider) MapAuthInitatorValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", parent.ConsumerKey)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("scope", parent.Permissions)
	return

}

func (a *GoogleAuthProvider) MapExchangeValues(parent *AuthProvider, token string, verifier string) (v url.Values, err error) {

	v = url.Values{}
	v.Set("client_id", parent.ConsumerKey)
	v.Set("client_secret", parent.ConsumerSecret)
	v.Set("code", token)
	v.Set("redirect_uri", parent.CallbackUrl)
	v.Set("grant_type", "authorization_code")
	return

}
