package controllers

import (
	"encoding/json"
	"github.com/paulxtiseo/bouncer/app/providers"
	"github.com/revel/revel"
)

type Auth struct {
	*revel.Controller
}

type Test struct { // TODO: eventually delete this
	Name  string
	Other string
}

func (c Auth) StartAuth() revel.Result {

	requestedProvider := c.Params.Get("provider")

	// check if provider requested is in allowed list in Providers. if so, return the Provider for use
	generator, foundProvider := providers.AllowedProviders[requestedProvider]

	if foundProvider {
		// retrieve settings from app.config, instantiate a provider and initiate auth process
		settings, foundSettings := revel.Config.String("auth." + requestedProvider + ".authconfig")
		if foundSettings {
			var authconfig providers.AuthConfig
			//err := json.Unmarshal([]byte(settings), &authconfig)
			//if err != nil {
			//	return c.RenderError("Provider requested not found in configuration.")
			//}
			//provider := generator
			return c.RenderJson(provider)
		}

		return c.RenderError("Provider requested not found in configuration.")

	}

	return c.NotFound("Provider requested not found in configuration.")

}

/*
func (c Auth) Facebook() revel.Result {

	// get Facebook-related AuthConfig settings
	x := new(providers.AuthConfig)
	x.Name = "facebook" // hard-coded; temporary
	x.AuthRealm = "https://graph.facebook.com/"

	// start a Facebook provider with these config settings
	p := providers.NewFacebookAuthProvider(x)

	// start the auth process and redirect to Facebook
	urlForAuth, err := p.GetAuthInitatorUrl()
	if err != nil {
		return c.RenderError(err)
	}

	return c.RenderJson(p)
}

func (c Auth) Google() revel.Result {
	t := Test{"Paul", "LoginGoogle"}
	return c.RenderJson(t)
}
*/
