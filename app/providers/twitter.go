package providers

import (
	"fmt"
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
