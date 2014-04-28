package providers

type GoogleAuthProvider struct {
	AuthProvider
}

var DefaultGoogleAuthConfig = AuthConfig{
	Name:            "google",
	DisplayName:     "Google",
	AuthRealm:       "",
	AuthProvider:    "",
	CallbackUrl:     "",
	ConsumerKey:     "",
	ConsumerSecret:  "",
	RequestTokenUrl: "",
	AuthorizeUrl:    "https://accounts.google.com/o/oauth2/auth",
	AccessTokenUrl:  "https://accounts.google.com/o/oauth2/token",
}

func NewGoogleAuthProvider(config *AuthConfig) Authorizer {
	provider := new(GoogleAuthProvider)
	return provider
}
