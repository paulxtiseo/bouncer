package controllers

import (
	//"code.google.com/p/go.crypto/bcrypt"
	"github.com/paulxtiseo/bouncer/app/providers"
	"github.com/revel/revel"
)

type Auth struct {
	*revel.Controller
}

type Test struct {
	Name  string
	Other string
}

func (c Auth) StartAuth() revel.Result {
	return c.RenderJson(c.Params)
}

func (c Auth) Basic() revel.Result {
	t := Test{"Paul", "LoginBasic"}
	return c.RenderJson(t)
}

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
