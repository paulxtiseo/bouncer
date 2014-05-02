package providers

type FacebookAuthProvider struct {
	AuthProvider
}

func NewFacebookAuthProvider(config *AuthConfig) Authorizer {
	provider := new(FacebookAuthProvider)

	// assert that we have key fields

	return provider
}
