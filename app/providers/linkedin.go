package providers

type LinkedinAuthProvider struct {
	AuthProvider
}

var DefaultLinkedinAuthConfig = AuthConfig{
	Name:            "linkedin",
	DisplayName:     "LinkedIn",
	AuthRealm:       "",
	AuthProvider:    "",
	CallbackUrl:     "",
	ConsumerKey:     "",
	ConsumerSecret:  "",
	RequestTokenUrl: "",
	AuthorizeUrl:    "https://www.linkedin.com/uas/oauth2/authorization",
	AccessTokenUrl:  "https://www.linkedin.com/uas/oauth2/accessToken",
}

func NewLinkedinAuthProvider(config *AuthConfig) Authorizer {
	provider := new(LinkedinAuthProvider)
	return provider
}
