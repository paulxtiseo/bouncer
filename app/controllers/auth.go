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

	requestedProvider := c.Params.Get("provider")
	settings, foundSettings := providers.AppAuthConfigs[requestedProvider]
	if foundSettings {
		return c.RenderJson(settings)
	}
	return c.RenderJson(settings)
	/*
		generator, foundProvider := providers.AllowedProviderGenerators[requestedProvider]

		if foundProvider && foundSettings {
			provider := generator(settings)

			return c.RenderJson(provider.GetAuthInitatorUrl())
		}

		return c.RenderError(errors.New("Provider or settings requested not found in configuration."))
	*/
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
