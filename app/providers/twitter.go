package providers

import (
	//"github.com/revel/revel"
	"net/url"
	//"strconv"
	//"strings"
	//"time"
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
	v.Set("include_entities", "true")
	v.Set("oauth_consumer_key", "xvz1evFS4wEEPTGEFPHBog")
	v.Set("oauth_nonce", "kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg")
	v.Set("oauth_signature_method", "HMAC-SHA1")
	v.Set("oauth_timestamp", "1318622958")
	v.Set("oauth_token", "370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb")
	v.Set("oauth_version", "1.0")
	v.Set("status", "Hello Ladies + Gentlemen, a signed OAuth request!")
	// calculate signature
	msg, _ := calculateOAuthSig("POST", "https://api.twitter.com/1/statuses/update.json", &v, "kAcSOqF21Fu85e7zjz7ZN2U4ZRhfV3WpwPAoE3Z7kBw", "LswwdoUaIvS8ltyTt5jkRh4J50vUPVVHtR2YPi5kE")
	/*
		v.Set("oauth_callback", parent.CallbackUrl)
		v.Set("oauth_consumer_key", parent.ConsumerKey)
		v.Set("oauth_nonce", generateNonce(32))
		v.Set("oauth_signature_method", "HMAC-SHA1")
		v.Set("oauth_timestamp", strconv.FormatInt(time.Now().Unix(), 10))
		v.Set("oauth_version", "1.0")
		// calculate signature
		revel.INFO.Print("Twitter.MapAuthConfigToUrlValues: " + v.Encode())
		msg, _ := calculateOAuthSig("GET", parent.AuthorizeUrl, &v, parent.ConsumerKey, "")
	*/
	v.Set("oauth_signature", msg)
	return

}

func (a *TwitterAuthProvider) ConfirmAuth(parent *AuthProvider) (v url.Values, err error) {
	v = url.Values{}
	return

}
