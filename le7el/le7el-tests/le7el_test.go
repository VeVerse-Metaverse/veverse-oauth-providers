package le7el_tests_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"veverse-oauth-providers/le7el"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := le7elProvider()
	a.Equal(provider.ClientKey, os.Getenv("LE7EL_KEY"))
	a.Equal(provider.Secret, os.Getenv("LE7EL_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := le7elProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*le7el.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "sso.demo.le7el.com/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("LE7EL_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=offline+openid")
	a.Contains(s.AuthURL, "access_type=offline")
}

func Test_BeginAuthWithPrompt(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := le7elProvider()
	provider.SetPrompt("test", "prompts")
	session, err := provider.BeginAuth("test_state")
	s := session.(*le7el.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "sso.demo.le7el.com/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("LE7EL_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=offline+openid")
	a.Contains(s.AuthURL, "access_type=offline")
	a.Contains(s.AuthURL, "prompt=test+prompts")
}

func Test_BeginAuthWithHostedDomain(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := le7elProvider()
	provider.SetHostedDomain("example.com")
	session, err := provider.BeginAuth("test_state")
	s := session.(*le7el.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "sso.demo.le7el.com/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("LE7EL_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=offline+openid")
	a.Contains(s.AuthURL, "access_type=offline")
	a.Contains(s.AuthURL, "hd=example.com")
}

func Test_BeginAuthWithLoginHint(t *testing.T) {
	// This exists because there was a panic caused by the oauth2 package when
	// the AuthCodeOption passed was nil. This test uses it, Test_BeginAuth does
	// not, to ensure both cases are covered.
	t.Parallel()
	a := assert.New(t)

	provider := le7elProvider()
	provider.SetLoginHint("john@example.com")
	session, err := provider.BeginAuth("test_state")
	s := session.(*le7el.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "sso.demo.le7el.com/oauth2/auth")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("LE7EL_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=offline+openid")
	a.Contains(s.AuthURL, "access_type=offline")
	a.Contains(s.AuthURL, "login_hint=john%40example.com")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), le7elProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := le7elProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://ssoa.demo.le7el.com/oauth2/auth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*le7el.Session)
	a.Equal(session.AuthURL, "https://ssoa.demo.le7el.com/oauth2/auth")
	a.Equal(session.AccessToken, "1234567890")
}

func le7elProvider() *le7el.Provider {
	return le7el.New(os.Getenv("LE7EL_KEY"), os.Getenv("LE7EL_SECRET"), "/foo")
}
