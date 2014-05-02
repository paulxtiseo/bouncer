package providers

type GoogleAuthProvider struct {
	AuthProvider
}

func NewGoogleAuthProvider(config *AuthConfig) Authorizer {
	provider := new(GoogleAuthProvider)
	return provider
}
