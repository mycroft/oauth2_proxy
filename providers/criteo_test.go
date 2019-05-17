package providers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

func testCriteoProvider(hostname string) *CriteoProvider {
	p := NewCriteoProvider(
		&ProviderData{
			ProviderName: "",
			LoginURL:     &url.URL{},
			RedeemURL:    &url.URL{},
			ProfileURL:   &url.URL{},
			ValidateURL:  &url.URL{},
			Scope:        ""})
	p.Configure("accounts", "identity", []string{})
	if hostname != "" {
		updateURL(p.Data().LoginURL, hostname)
		updateURL(p.Data().RedeemURL, hostname)
		updateURL(p.Data().ProfileURL, hostname)
	}
	return p
}

func testCriteoBackend(payload string) *httptest.Server {
	path := "/auth/oauth2/tokeninfo"

	return httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			url := r.URL
			if url.Path != path {
				w.WriteHeader(404)
			} else if r.Header.Get("Authorization") != "Bearer imaginary_access_token" {
				w.WriteHeader(403)
			} else {
				w.WriteHeader(200)
				w.Write([]byte(payload))
			}
		}))
}

func TestCriteoProviderDefaults(t *testing.T) {
	p := testCriteoProvider("")
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Criteo", p.Data().ProviderName)
	assert.Equal(t, "https://accounts/auth/oauth2/authorize?realm=criteo",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://accounts/auth/oauth2/access_token?realm=criteo",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://accounts/auth/oauth2/tokeninfo?realm=criteo",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://accounts/auth/oauth2/tokeninfo?realm=criteo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "cn mail uid dn umsId", p.Data().Scope)
}

func TestCriteoProviderOverrides(t *testing.T) {
	p := NewCriteoProvider(
		&ProviderData{
			LoginURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/auth"},
			RedeemURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/token"},
			ProfileURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/profile"},
			ValidateURL: &url.URL{
				Scheme: "https",
				Host:   "example.com",
				Path:   "/oauth/tokeninfo"},
			Scope: "profile"})
	assert.NotEqual(t, nil, p)
	assert.Equal(t, "Criteo", p.Data().ProviderName)
	assert.Equal(t, "https://example.com/oauth/auth",
		p.Data().LoginURL.String())
	assert.Equal(t, "https://example.com/oauth/token",
		p.Data().RedeemURL.String())
	assert.Equal(t, "https://example.com/oauth/profile",
		p.Data().ProfileURL.String())
	assert.Equal(t, "https://example.com/oauth/tokeninfo",
		p.Data().ValidateURL.String())
	assert.Equal(t, "profile", p.Data().Scope)
}

func TestCriteoProviderGetEmailAddress(t *testing.T) {
	b := testCriteoBackend(`{"mail": "user@criteo.com"}`)
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCriteoProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	ctx := context.Background()
	email, err := p.GetEmailAddress(ctx, session)
	assert.Equal(t, nil, err)
	assert.Equal(t, "user@criteo.com", email)
}

func TestCriteoProviderGetEmailAddressFailedRequest(t *testing.T) {
	b := testCriteoBackend("unused payload")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCriteoProvider(bURL.Host)

	// We'll trigger a request failure by using an unexpected access
	// token. Alternatively, we could allow the parsing of the payload as
	// JSON to fail.
	session := &sessions.SessionState{AccessToken: "unexpected_access_token"}
	ctx := context.Background()
	email, err := p.GetEmailAddress(ctx, session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}

func TestCriteoProviderGetEmailAddressEmailNotPresentInPayload(t *testing.T) {
	b := testCriteoBackend("{\"foo\": \"bar\"}")
	defer b.Close()

	bURL, _ := url.Parse(b.URL)
	p := testCriteoProvider(bURL.Host)

	session := &sessions.SessionState{AccessToken: "imaginary_access_token"}
	ctx := context.Background()
	email, err := p.GetEmailAddress(ctx, session)
	assert.NotEqual(t, nil, err)
	assert.Equal(t, "", email)
}
