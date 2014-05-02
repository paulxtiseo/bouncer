package providers

import "strings"

type TwitterAuthProvider struct {
	AuthProvider
}

func NewTwitterAuthProvider(config *AuthConfig) Authorizer {
	provider := new(TwitterAuthProvider)
	provider.AuthConfig = *config
	return provider
}

func (a *TwitterAuthProvider) MapAuthConfigToStartAuthMap() (v map[string][]string) {

	v["client_id"] = append(v["client_id"], a.AuthConfig.ConsumerKey)
	v["redirect_uri"] = append(v["redirect_uri"], a.AuthConfig.CallbackUrl)
	// TODO: state?
	v["reponse_type"] = append(v["reponse_type"], "code")
	v["scope"] = strings.Split(a.AuthConfig.Permissions, ",")
	return
}
