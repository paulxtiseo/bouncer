package providers

type FacebookAuthProvider struct {
	AuthProvider
}

var DefaultFacebookAuthConfig = AuthConfig{
	Name:            "facebook",
	DisplayName:     "FaceBook",
	AuthRealm:       "",
	AuthProvider:    "",
	CallbackUrl:     "",
	ConsumerKey:     "",
	ConsumerSecret:  "",
	RequestTokenUrl: "",
	AuthorizeUrl:    "https://www.facebook.com/dialog/oauth",
	AccessTokenUrl:  "https://graph.facebook.com/oauth/access_token",
}

func NewFacebookAuthProvider(config *AuthConfig) Authorizer {
	provider := new(FacebookAuthProvider)
	return provider
}
