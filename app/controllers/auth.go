package controllers

import (
	//"encoding/json"
	//"errors"
	"github.com/paulxtiseo/bouncer/app/providers"
	"github.com/revel/revel"
)

type Auth struct {
	*revel.Controller
}

// StartAuth() is the method that instantiates the requested provider
// and initiates the authentication process
func (c Auth) StartAuth() revel.Result {

	// find provider requested in /auth/:provider
	requestedProvider := c.Params.Get("provider")
	// check if we had a corresponding authconfig in app.conf
	settings, foundSettings := providers.AppAuthConfigs[requestedProvider]
	if foundSettings {
		// use the generator function to create the linked provider for the request
		generator, foundProvider := providers.AllowedProviderGenerators[requestedProvider]
		if foundProvider {
			provider := generator(&settings)
			// prep and redirect to the authentication provider's AuthorizeUrl per config
			theUrl, err := provider.GetAuthInitatorUrl(nil, nil, &provider)
			if err != nil {
				revel.ERROR.Printf("Error generating the auth URL: %+v", err)
				return c.RenderError(err)
			} else {
				return c.Redirect(theUrl)
			}
		}
	}

	return c.NotFound("No authentication for %s configured for this site.", requestedProvider)
}

// GetAccessToken is the method used to respond to the callback from
// the selected authentication provider
func (c Auth) GetAccessToken() revel.Result {

	return c.RenderText(c.Params.Encode())
}
