package eos_tests_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/markbates/goth"
	"github.com/stretchr/testify/assert"
	"veverse-oauth-providers/eos"
)

func Test_New(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := eosProvider()
	a.Equal(provider.ClientKey, os.Getenv("EOS_KEY"))
	a.Equal(provider.Secret, os.Getenv("EOS_SECRET"))
	a.Equal(provider.CallbackURL, "/foo")
}

func Test_BeginAuth(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := eosProvider()
	session, err := provider.BeginAuth("test_state")
	s := session.(*eos.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://www.epicgames.com/id/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("EOS_KEY")))
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

	provider := eosProvider()
	provider.SetPrompt("test", "prompts")
	session, err := provider.BeginAuth("test_state")
	s := session.(*eos.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://www.epicgames.com/id/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("EOS_KEY")))
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

	provider := eosProvider()
	provider.SetHostedDomain("example.com")
	session, err := provider.BeginAuth("test_state")
	s := session.(*eos.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://www.epicgames.com/id/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("EOS_KEY")))
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

	provider := eosProvider()
	provider.SetLoginHint("john@example.com")
	session, err := provider.BeginAuth("test_state")
	s := session.(*eos.Session)
	a.NoError(err)
	a.Contains(s.AuthURL, "https://www.epicgames.com/id/authorize")
	a.Contains(s.AuthURL, fmt.Sprintf("client_id=%s", os.Getenv("EOS_KEY")))
	a.Contains(s.AuthURL, "state=test_state")
	a.Contains(s.AuthURL, "scope=offline+openid")
	a.Contains(s.AuthURL, "access_type=offline")
	a.Contains(s.AuthURL, "login_hint=john%40example.com")
}

func Test_Implements_Provider(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	a.Implements((*goth.Provider)(nil), eosProvider())
}

func Test_SessionFromJSON(t *testing.T) {
	t.Parallel()
	a := assert.New(t)

	provider := eosProvider()

	s, err := provider.UnmarshalSession(`{"AuthURL":"https://ssoa.demo.eos.com/oauth2/auth","AccessToken":"1234567890"}`)
	a.NoError(err)
	session := s.(*eos.Session)
	a.Equal(session.AuthURL, "https://ssoa.demo.eos.com/oauth2/auth")
	a.Equal(session.AccessToken, "1234567890")
}

func eosProvider() *eos.Provider {
	return eos.New(os.Getenv("EOS_KEY"), os.Getenv("EOS_SECRET"), "/foo")
}
