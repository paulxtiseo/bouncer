package providers

type LinkedinAuthProvider struct {
	AuthProvider
}

func NewLinkedinAuthProvider(config *AuthConfig) *LinkedinAuthProvider {
	provider := new(LinkedinAuthProvider)
	provider.Name = config.Name
	provider.AuthRealm = config.AuthRealm
	return provider
}
