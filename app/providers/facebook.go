package providers

import (
	"github.com/revel/revel"
	"strings"
)

type FacebookAuthProvider struct {
	AuthProvider
}

func NewFacebookAuthProvider(config *AuthConfig) Authorizer {
	provider := new(FacebookAuthProvider)
	provider.AuthConfig = *config
	return provider
}

func (a *FacebookAuthProvider) MapAuthConfigToStartAuthMap() (v map[string][]string) {
	revel.INFO.Print("MapAuthConfigToStartAuthMap")
	revel.INFO.Printf("object data: %+v", a)
	v["client_id"] = append(v["client_id"], a.AuthConfig.ConsumerKey)
	v["redirect_uri"] = append(v["redirect_uri"], a.AuthConfig.CallbackUrl)
	// TODO: state?
	v["reponse_type"] = append(v["reponse_type"], "code")
	v["scope"] = strings.Split(a.AuthConfig.Permissions, ",")
	return
}
