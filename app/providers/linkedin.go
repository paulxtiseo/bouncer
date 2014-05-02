package providers

import "strings"

type LinkedinAuthProvider struct {
	AuthProvider
}

func NewLinkedinAuthProvider(config *AuthConfig) Authorizer {
	provider := new(LinkedinAuthProvider)
	provider.AuthConfig = *config
	return provider
}

func (a *LinkedinAuthProvider) MapAuthConfigToStartAuthMap() (v map[string][]string) {

	v["client_id"] = append(v["client_id"], a.AuthConfig.ConsumerKey)
	v["redirect_uri"] = append(v["redirect_uri"], a.AuthConfig.CallbackUrl)
	// TODO: state?
	v["reponse_type"] = append(v["reponse_type"], "code")
	v["scope"] = strings.Split(a.AuthConfig.Permissions, ",")
	return
}
