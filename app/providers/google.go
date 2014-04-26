package providers

type GoogleAuthProvider struct {
	AuthProvider
}

func NewGoogleAuthProvider(config *AuthConfig) *GoogleAuthProvider {
	// setup provider
	provider := new(GoogleAuthProvider)
	provider.Name = config.Name
	provider.AuthRealm = config.AuthRealm
	return provider
}
