package providers

import (
	"github.com/revel/revel"
	"strings"
)

var AllowedProviders = make(map[string]NewAuthProvider)

func init() {

	revel.OnAppStart(func() {
		// setup providers allowed in app.config's auth.providersallowed setting
		result, found := revel.Config.String("auth.providersallowed")
		if found {
			results := strings.Split(result, ",")
			for itm := 0; itm < len(results); itm++ {
				switch strings.ToLower(results[itm]) {
				case "facebook":
					AllowedProviders["facebook"] = NewFacebookAuthProvider
				case "google":
					AllowedProviders["google"] = NewGoogleAuthProvider
				case "linkedin":
					AllowedProviders["linkedin"] = NewLinkedinAuthProvider
				default:
					revel.WARN.Printf("Provider <%s> is not known.\n", results[itm])
				}
			}
		} else {
			revel.ERROR.Fatal("No auth.providersallowed setting was found in app.conf.")
		}
	})

}
