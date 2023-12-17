// Package le7el implements the OAuth2 protocol for authenticating users
// through LE7EL.
package le7el

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

const endpointProfile string = "https://le7el.com/identity/v1/accounts/"

// New creates a new LE7EL provider, and sets up important connection details.
// You should always call `le7el.New` to get a new Provider. Never try to create
// one manually.
func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "le7el",
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

// Debug is a no-op for the le7el package.
func (p *Provider) Debug(_ bool) {}

// BeginAuth asks LE7EL for an authentication endpoint.
func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	u := p.config.AuthCodeURL(state, p.authCodeOptions...)
	session := &Session{
		AuthURL: u,
	}
	return session, nil
}

type le7elUser struct {
	ID              int64     `json:"id"`
	InsertedAt      time.Time `json:"inserted_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Email           string    `json:"email"`
	EthWallet       string    `json:"eth_wallet"`
	DisplayName     string    `json:"display_name"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	MatrixToken     string    `json:"matrix_token"`
	MatrixId        string    `json:"matrix_id"`
	NationalityId   string    `json:"nationality_id"`
	ProfileImageURL string    `json:"profile_image_url"`
	Type            string    `json:"type"`
	Username        string    `json:"username"`
}

type le7elUserResponse struct {
	Data le7elUser `json:"data"`
}

// FetchUser will go to LE7EL and access basic information about the user.
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
		greetId            int64
		greetIdentityToken string
	)

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
		if claims["greet_id"] == nil && claims["greet_identity_token"] == nil {
			return user, errors.New("invalid token")
		}

		{
			fGreetId, ok := claims["greet_id"].(float64)
			if !ok {
				return user, errors.New("invalid token, missing id")
			} else {
				greetId = int64(fGreetId)
			}
		}

		greetIdentityToken, ok = claims["greet_identity_token"].(string)
		if !ok {
			return user, errors.New("invalid token, missing identity token")
		}
	} else {
		return user, errors.New("invalid token")
	}

	if user.AccessToken == "" {
		// Data is not yet retrieved, since accessToken is still empty.
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+greetIdentityToken)

	uri, err := url.ParseRequestURI(endpointProfile + strconv.FormatInt(greetId, 10))
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

	var u le7elUser
	if err := json.Unmarshal(responseBytes, &u); err != nil {
		return user, err
	}

	// Extract the user data we got from LE7EL into our goth.User.
	user.Name = u.Username
	user.FirstName = u.FirstName
	user.LastName = u.LastName
	user.NickName = u.Username
	user.Email = u.Email
	user.AvatarURL = u.ProfileImageURL
	user.UserID = strconv.FormatInt(u.ID, 10)
	// LE7EL provides other useful fields, get them from RawData
	if err := json.Unmarshal(responseBytes, &user.RawData); err != nil {
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

// SetPrompt sets the prompt values for the le7el OAuth call. Use this to
// force users to choose and account every time by passing "select_account",
// for example.
func (p *Provider) SetPrompt(prompt ...string) {
	if len(prompt) == 0 {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("prompt", strings.Join(prompt, " ")))
}

// SetHostedDomain sets the hd parameter for le7el OAuth call.
// Use this to force user to pick user from specific hosted domain.
func (p *Provider) SetHostedDomain(hd string) {
	if hd == "" {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("hd", hd))
}

// SetLoginHint sets the login_hint parameter for the LE7EL OAuth call.
// Use this to prompt the user to log in with a specific account.
func (p *Provider) SetLoginHint(loginHint string) {
	if loginHint == "" {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("login_hint", loginHint))
}

// SetAccessType sets the access_type parameter for the LE7EL OAuth call.
// If an access token is being requested, the client does not receive a refresh token unless a value of offline is specified.
func (p *Provider) SetAccessType(at string) {
	if at == "" {
		return
	}
	p.authCodeOptions = append(p.authCodeOptions, oauth2.SetAuthURLParam("access_type", at))
}
