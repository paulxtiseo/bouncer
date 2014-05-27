package providers

import (
	//"errors"
	"fmt"
	"github.com/revel/revel"
	//"net/url"
)

type CommonAuthProvider struct {
}

// returns AuthResponse, where Response = "" means skip
func (a *CommonAuthProvider) Authenticate(parent *AuthProvider, params *revel.Params) (resp AuthResponse, err error) {

	// make sure we got all params
	if parent == nil || params == nil {
		err = fmt.Errorf("One or more params were nil: %v, %v", parent, params)
		return resp, err
	}

	// check if already authenticated
	check, err := parent.IsAuthenticated()
	if err != nil {
		err = fmt.Errorf("Error in authenticated check: %+v", parent)
		return resp, err
	}
	if check { // user already authenticated
		return resp, err
	}

	// call into specialized AuthenticateBase()
	resp, err = parent.AuthenticateBase(parent, params)
	if err != nil {
		err = fmt.Errorf("Error in AuthenticateBase: %v, %v", parent, params)
		return resp, err
	}

	return resp, err
}

func (a *CommonAuthProvider) IsAuthenticated() (check bool, err error) {
	// TODO: finish it!
	return false, nil
}
