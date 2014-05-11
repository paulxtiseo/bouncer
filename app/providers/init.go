package providers

import (
	"encoding/json"
	"errors"
	"github.com/revel/revel"
	"strings"
)

var AllowedProviderGenerators = make(map[string]NewAuthProvider)
var AppAuthConfigs = make(map[string]AuthConfig)
var SecurityKey string

func init() {

	revel.OnAppStart(func() {

		// set security key to app.secret
		sec, found := revel.Config.String("app.secret")
		if !found {
			revel.ERROR.Fatal("No app.secret setting was found in app.conf.")
		}
		SecurityKey = sec

		// setup providers allowed in app.config's auth.providersallowed setting
		configItm, found := revel.Config.String("auth.providersallowed")
		if found {
			revel.INFO.Printf("Setting up the following providers: %s", configItm)

			configResults := strings.Split(configItm, ",")

			for idx := 0; idx < len(configResults); idx++ {
				providerItm := strings.ToLower(configResults[idx])

				// set the AuthProvider for each type requested
				switch providerItm {
				case "facebook":
					AllowedProviderGenerators["facebook"] = NewFacebookAuthProvider
				case "google":
					AllowedProviderGenerators["google"] = NewGoogleAuthProvider
				case "linkedin":
					AllowedProviderGenerators["linkedin"] = NewLinkedinAuthProvider
				case "twitter":
					AllowedProviderGenerators["twitter"] = NewTwitterAuthProvider
				default:
					revel.WARN.Printf("Provider <%s> is not known. Skipped.", providerItm)
				}

				// pull AuthConfig settings from app.conf
				ac, err := generateAuthConfigFromAppConfig(providerItm)
				if err != nil {
					revel.ERROR.Fatal(err)
				} else {
					AppAuthConfigs[providerItm] = ac
					revel.INFO.Printf("Configured %s for authentication.", providerItm)
				}

			}
		} else {
			revel.ERROR.Fatal("No auth.providersallowed setting was found in app.conf.")
		}

	})

}

func generateAuthConfigFromAppConfig(provider string) (ac AuthConfig, err error) {
	settings, foundSettings := revel.Config.String("auth." + provider + ".authconfig")
	if foundSettings {
		err = json.Unmarshal([]byte(settings), &ac)
		if err != nil {
			err = errors.New("Error reading auth." + provider + ".authconfig in app.conf.")
			return
		}
		return
	}
	err = errors.New("auth." + provider + ".authconfig not found.")
	return
}
