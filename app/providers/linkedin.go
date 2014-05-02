package providers

type LinkedinAuthProvider struct {
	AuthProvider
}

func NewLinkedinAuthProvider(config *AuthConfig) Authorizer {
	provider := new(LinkedinAuthProvider)
	return provider
}
