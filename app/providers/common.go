package providers

//----- structs ----------------

type AuthConfig struct {
	Name            string
	DisplayName     string
	AuthRealm       string
	AuthProvider    string
	CallbackUrl     string
	ConsumerKey     string
	ConsumerSecret  string
	RequestTokenUrl string
	AuthorizeUrl    string
	AccessTokenUrl  string
}

type AuthState struct {
	KeyValues map[string]string
}

type RequestOptions struct {
	KeyValues map[string]string
}

type AuthProvider struct {
	AuthConfig
	Authorizer
}

//----- functions ----------------

type NewAuthProvider func(*AuthConfig) Authorizer

//----- interfaces ----------------

type Authorizer interface {
	GetAuthInitatorUrl(baseUrl string, state *AuthState, options *RequestOptions) (string, error)
}
