package providers

type FacebookAuthProvider struct {
	AuthProvider
}

FacebookDefaultAuthConfig := AuthConfig {
	Name: "facebook"
	DisplayName: "FaceBook"
	AuthRealm: ""
	AuthProvider: ""
	CallbackUrl: ""
	ConsumerKey: ""
	ConsumerSecret: ""
	RequestTokenUrl: ""
	AuthorizeUrl: "https://www.facebook.com/dialog/oauth"
	AccessTokenUrl: "https://graph.facebook.com/oauth/access_token"
}

func New(config *AuthConfig) *FacebookAuthProvider {
	provider := new(FacebookAuthProvider)
	provider.Name = config.Name
	provider.AuthRealm = config.AuthRealm
	return provider
}
