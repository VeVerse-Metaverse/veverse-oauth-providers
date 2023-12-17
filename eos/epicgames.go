// Package epicgames Package epic games implements the OAuth2 protocol for authenticating users
// through Epic Online Services.
package eos

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/markbates/goth"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const endpointProfile string = "https://api.epicgames.dev/epic/id/v1/accounts"

// New creates a new Epic Online Services provider, and sets up important connection details.
// You should always call `eos.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "eos",
		authCodeOptions: []oauth2.AuthCodeOption{
			oauth2.AccessTypeOffline,
			//tokenEndpointAuthMethod,
			//grantTypes,
		},
	}
	p.config = newConfig(p, scopes)
	return p
}

// Provider is the implementation of `goth.Provider` for accessing LE7EL.
type Provider struct {
	ClientKey       string
	Secret          string
	CallbackURL     string
	HTTPClient      *http.Client
	config          *oauth2.Config
	authCodeOptions []oauth2.AuthCodeOption
	providerName    string
}

// Name is the name used to retrieve this provider later.
func (p *Provider) Name() string {
	return p.providerName
}

// SetName is to update the name of the provider (needed in case of multiple providers of 1 type)
func (p *Provider) SetName(name string) {
	p.providerName = name
}

// Client returns an HTTP client to be used in all fetch operations.
func (p *Provider) Client() *http.Client {
	return goth.HTTPClientWithFallBack(p.HTTPClient)
}

// Debug is a no-op for the EOS package.
func (p *Provider) Debug(_ bool) {}

// BeginAuth asks EOS for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	u := p.config.AuthCodeURL(state, p.authCodeOptions...)
	session := &Session{
		AuthURL: u,
	}
	return session, nil
}

type eosUser struct {
	AccountId         string `json:"accountId"`
	DisplayName       string `json:"displayName"`
	PreferredLanguage string `json:"preferredLanguage"`
}

type eosUserResponse struct {
	Data eosUser `json:"data"`
}

// FetchUser will go to EOS and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
		IDToken:      sess.IDToken,
	}

	var (
		epicId    string
		epicToken string
	)

	epicToken = user.AccessToken

	t, err := jwt.Parse(user.IDToken, nil)
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return user, errors.New("token malformed")
			} else if ve.Errors&(jwt.ValidationErrorExpired|jwt.ValidationErrorNotValidYet) != 0 {
				return user, errors.New("token is either expired or not active yet")
			} else if ve.Errors&jwt.ValidationErrorUnverifiable != 0 {
				// ok
				t.Valid = true
			} else {
				return user, err
			}
		}
	}

	if claims, ok := t.Claims.(jwt.MapClaims); ok && t.Valid {
		logrus.Printf("Valid JWT Token, claims: %v", claims)
		if claims["sub"] == nil {
			return user, errors.New("invalid token")
		}

		epicId, ok = claims["sub"].(string)
		if !ok {
			return user, errors.New("invalid token, missing epic id")
		}
	} else {
		return user, errors.New("invalid token")
	}

	if user.AccessToken == "" {
		// Data is not yet retrieved, since accessToken is still empty.
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+epicToken)

	uri, err := url.ParseRequestURI(endpointProfile + "?accountId=" + epicId)
	if err != nil {
		return user, err
	}

	request := http.Request{
		Method: http.MethodGet,
		URL:    uri,
		Header: headers,
	}

	response, err := p.Client().Do(&request)
	if err != nil {
		return user, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			fmt.Println(err)
		}
	}(response.Body)

	if response.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, response.StatusCode)
	}

	responseBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return user, err
	}

	var users []eosUser
	var u eosUser
	if err := json.Unmarshal(responseBytes, &users); err != nil {
		return user, err
	}

	if len(users) > 0 {
		u = users[0]
	} else {
		return user, errors.New("no user found")
	}

	// Extract the user data we got from EOS into our goth.User.
	user.Name = u.DisplayName
	user.NickName = u.DisplayName
	user.UserID = u.AccountId

	// If EOS provides other useful fields, get them from RawData
	var users1 []map[string]interface{}
	if err := json.Unmarshal(responseBytes, &users1); err != nil {
		if len(users1) > 0 {
			user.RawData = users1[0]
		}
		return user, err
	}

	return user, nil
}

func newConfig(provider *Provider, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint:     Endpoint,
		Scopes:       []string{},
	}

	if len(scopes) > 0 {
		c.Scopes = append(c.Scopes, scopes...)
	} else {
		c.Scopes = []string{"offline", "openid"}
	}
	return c
}

// RefreshTokenAvailable refresh token is provided by auth provider or not
func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// RefreshToken get new access token based on the refresh token
func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	token := &oauth2.Token{RefreshToken: refreshToken}
	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
	newToken, err := ts.Token()
	if err != nil {
		return nil, err
	}
	return newToken, err
}

// SetPrompt sets the prompt values for the EOS OAuth call. Use this to
// force users to choose and account every time by passing "select_account",
// for example.
func (p *Provider) SetPrompt(prompt ...string) {
	if len(prompt) == 0 {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("prompt", strings.Join(prompt, " ")))
}

// SetHostedDomain sets the hd parameter for EOS OAuth call.
// Use this to force user to pick user from specific hosted domain.
func (p *Provider) SetHostedDomain(hd string) {
	if hd == "" {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("hd", hd))
}

// SetLoginHint sets the login_hint parameter for the EOS OAuth call.
// Use this to prompt the user to log in with a specific account.
func (p *Provider) SetLoginHint(loginHint string) {
	if loginHint == "" {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("login_hint", loginHint))
}

// SetAccessType sets the access_type parameter for the EOS OAuth call.
// If an access token is being requested, the client does not receive a refresh token unless a value of offline is specified.
func (p *Provider) SetAccessType(at string) {
	if at == "" {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("access_type", at))
}
