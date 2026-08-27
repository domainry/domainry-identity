package auth

import authmodel "github.com/domainry/domainry-identity/internal/domain/auth/model"

import (
	"net/http"
)

func callbackInput(r *http.Request) authmodel.AuthProviderCallbackInput {
	values := map[string]string{}
	for key, items := range r.URL.Query() {
		values[key] = items[0]
	}
	if r.Method == http.MethodPost {
		_ = r.ParseForm()
		for key, items := range r.Form {
			values[key] = items[0]
		}
	}
	return authmodel.AuthProviderCallbackInput{Method: r.Method, Values: values}
}
