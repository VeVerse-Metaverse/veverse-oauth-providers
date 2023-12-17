package eos

import (
	oauth2 "golang.org/x/oauth2"
)

// Endpoint is LE7EL's OAuth 2.0 default endpoint.
var Endpoint = oauth2.Endpoint{
	AuthURL:   "https://www.epicgames.com/id/authorize",
	TokenURL:  "https://api.epicgames.dev/epic/oauth/v1/token",
	AuthStyle: oauth2.AuthStyleInHeader,
}
