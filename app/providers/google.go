package providers

import "strings"

type GoogleAuthProvider struct {
	AuthProvider
}

func NewGoogleAuthProvider(config *AuthConfig) Authorizer {
	provider := new(GoogleAuthProvider)
	provider.AuthConfig = *config
	return provider
}

func (a *GoogleAuthProvider) MapAuthConfigToStartAuthMap() (v map[string][]string) {

	v["client_id"] = append(v["client_id"], a.AuthConfig.ConsumerKey)
	v["redirect_uri"] = append(v["redirect_uri"], a.AuthConfig.CallbackUrl)
	// TODO: state?
	v["reponse_type"] = append(v["reponse_type"], "code")
	v["scope"] = strings.Split(a.AuthConfig.Permissions, ",")
	return
}
