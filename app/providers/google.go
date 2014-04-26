package providers

type GoogleAuthProvider struct {
	AuthProvider
}

func New(config *AuthConfig) *GoogleAuthProvider {
	// setup provider
	provider := new(GoogleAuthProvider)
	provider.Name = config.Name
	provider.AuthRealm = config.AuthRealm
	return provider
}
