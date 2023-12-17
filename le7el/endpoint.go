package le7el

import (
	oauth2 "golang.org/x/oauth2"
)

// Endpoint is LE7EL's OAuth 2.0 default endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:   "https://sso.le7el.com/oauth2/auth",
	TokenURL:  "https://sso.le7el.com/oauth2/token",
	AuthStyle: oauth2.AuthStyleInHeader,
}
