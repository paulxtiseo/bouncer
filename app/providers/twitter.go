package providers

import (
	"net/url"
	"strconv"
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

func (a *TwitterAuthProvider) MapAuthConfigToUrlValues(parent *AuthProvider) (v url.Values, err error) {

	v = url.Values{}
	v.Set("oauth_version", "1.0")
	v.Set("oauth_nonce", generateNonce(32))
	v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	v.Set("oauth_consumer_key", parent.ConsumerKey)
	v.Set("oauth_callback", parent.CallbackUrl)
	// calculate signature
	v.Set("oauth_signature_method", "HMAC-SHA1")
	v.Set("oauth_signature", calculateOAuthSig("GET", parent.AuthorizeUrl, &v))
	return

}

func (a *TwitterAuthProvider) ConfirmAuth(parent *AuthProvider) (v url.Values, err error) {
	v = url.Values{}
	return

}
