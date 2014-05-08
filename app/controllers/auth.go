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

func (c Auth) StartAuth() revel.Result {
	// get provider requested in /auth/:provider and begin the authenticationm
	// by redirecting to the authentication provider's AuthorizeUrl per config
	requestedProvider := c.Params.Get("provider")
	settings, foundSettings := providers.AppAuthConfigs[requestedProvider]
	if foundSettings {
		// use the generator function to create the linked provider for the request
		generator, foundProvider := providers.AllowedProviderGenerators[requestedProvider]
		if foundProvider {
			// prep the provider and then get the URL we need to visit to start auth
			provider := generator(&settings)
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

func (c Auth) Callback() revel.Result {
	return c.RenderText(c.Params.Encode())
}
