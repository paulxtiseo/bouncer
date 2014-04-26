package providers

import "github.com/google/go-querystring/query"

type AuthProvider struct {
	AuthConfig
}

func (a *AuthProvider) GetAuthInitatorUrl(baseUrl string, state *AuthState, options *RequestOptions) (string, error) {

	if baseUrl == nil {
		panic("Missing base URL in GetAuthInitatorUrl.")
	}

	// convert state and add as a RequestOption
	options["state"] = query.Values(state).Encode() // TODO: convert to JSON string?

	// convert options into a QueryString
	queryString, queryErr := query.Values(options)
	if queryErr != nil {
		return "", queryErr
	}

	return baseUrl + "?" + queryString.Encode(), nil
}
