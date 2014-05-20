package controllers

import (
	//"encoding/json"
	"errors"
	"github.com/paulxtiseo/bouncer/app/providers"
	"github.com/revel/revel"
)

type Auth struct {
	*revel.Controller
}

// Authenticate() is the method that instantiates the requested provider
// and initiates or completes the authentication process
func (c Auth) Authenticate() revel.Result {
	// find provider requested in /auth/:provider
	requestedProvider := c.Params.Get("provider")
	revel.INFO.Printf("Authenticate() params: %+v\n", c.Params)
	// check if we had a corresponding authconfig in app.conf
	settings, foundSettings := providers.AppAuthConfigs[requestedProvider]
	if foundSettings {
		// use the generator function to create the linked provider for the request
		generator, foundProvider := providers.AllowedProviderGenerators[requestedProvider]
		if foundProvider {
			provider := generator(&settings)
			resp, err := provider.Authenticate(&provider, c.Params)
			revel.INFO.Printf("Authenticate() resp: %+v\n", resp)
			if err != nil {
				revel.ERROR.Printf("Error generating the auth URL: %+v\n", err)
				return c.RenderError(err)
			} else {
				switch resp.Type {
				case providers.AuthResponseError:
					revel.ERROR.Printf("Error from %s provider: %s\n", provider.Name, resp.Response)
					return c.RenderError(errors.New(resp.Response))
				case providers.AuthResponseRedirect:
					return c.Redirect(resp.Response)
				case providers.AuthResponseString:
					return c.RenderText(resp.Response)
				default:
					revel.ERROR.Printf("Unknown response type in Authenticate(): %+v\n", resp)
					return c.RenderError(errors.New(resp.Response))
				}
			}
		}
	}

	return c.NotFound("No authentication for %s configured for this site.", requestedProvider)
}
