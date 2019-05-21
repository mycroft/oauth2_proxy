package providers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/pusher/oauth2_proxy/api"
)

// CriteoProvider represents a Criteo based Identity Provider
type CriteoProvider struct {
	*ProviderData
	// GroupValidator is a function that determines if the passed email is in
	// the configured groups.
	GroupValidator func(*SessionState) bool
	IdentityURL    *url.URL
}

type tokenInfo struct {
	Email string `json:"mail"`
	User  string `json:"dn"`
}

type profileResponse struct {
	Cn string `json:"cn"`
	Dn string `json:"dn"`
}

type groupInfo struct {
	Name string `json:"name"`
}

type groupsResponse struct {
	Groups []groupInfo
}

type criteoProfile struct {
	profile profileResponse
	groups  groupsResponse
}

// NewCriteoProvider initiates a new CriteoProvider
func NewCriteoProvider(p *ProviderData) *CriteoProvider {
	p.ProviderName = "Criteo"
	if p.Scope == "" {
		p.Scope = "cn mail uid dn umsId"
	}
	return &CriteoProvider{ProviderData: p}
}

// Configure defaults the CriteoProvider configuration options
func (p *CriteoProvider) Configure(ssoHost string, identityHost string, groups []string) {
	p.IdentityURL = &url.URL{Scheme: "http",
		Host: identityHost,
		Path: "/user/",
	}

	if p.LoginURL.String() == "" {
		p.LoginURL = &url.URL{Scheme: "https",
			Host:     ssoHost,
			Path:     "/auth/oauth2/authorize",
			RawQuery: "realm=criteo",
		}
	}
	if p.RedeemURL.String() == "" {
		p.RedeemURL = &url.URL{Scheme: "https",
			Host:     ssoHost,
			Path:     "/auth/oauth2/access_token",
			RawQuery: "realm=criteo",
		}
	}
	if p.ProfileURL.String() == "" {
		p.ProfileURL = &url.URL{Scheme: "https",
			Host:     ssoHost,
			Path:     "/auth/oauth2/tokeninfo",
			RawQuery: "realm=criteo",
		}
	}
	if p.ValidateURL.String() == "" {
		p.ValidateURL = p.ProfileURL
	}
	p.GroupValidator = func(s *SessionState) bool {
		return p.userInGroup(groups, s)
	}
}

func getCriteoHeader(accessToken string) http.Header {
	header := make(http.Header)
	header.Set("Accept", "application/json")
	header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	return header
}

func requestJSON(s *SessionState, url *url.URL, v interface{}) error {
	if s != nil && s.AccessToken == "" {
		return errors.New("missing access token")
	}

	req, err := http.NewRequest("GET", url.String(), nil)
	if err != nil {
		return err
	}
	if s != nil {
		req.Header = getCriteoHeader(s.AccessToken)
	}

	err = api.RequestJSON(req, &v)
	return err
}

func (p *CriteoProvider) getProfile(s *SessionState) error {
	if s.User != "" && s.Email != "" {
		return nil
	}

	var info tokenInfo
	err := requestJSON(s, p.ProfileURL, &info)
	if err != nil {
		return err
	}

	s.Email = info.Email
	s.User = info.User
	if s.Email == "" {
		return fmt.Errorf("can't find email")
	}
	return nil
}

func (p *CriteoProvider) getExtendedProfile(dn string) (*criteoProfile, error) {
	profile := criteoProfile{}

	url := *p.IdentityURL
	url.Path = url.Path + dn
	err := requestJSON(nil, &url, &profile.profile)
	if err != nil {
		return nil, err
	}

	url.Path += "/groups"
	err = requestJSON(nil, &url, &profile.groups.Groups)
	if err != nil {
		return nil, err
	}

	return &profile, nil
}

// GetEmailAddress returns the Account email address
func (p *CriteoProvider) GetEmailAddress(s *SessionState) (string, error) {
	err := p.getProfile(s)
	return s.Email, err
}

// GetUserName returns the Account username
func (p *CriteoProvider) GetUserName(s *SessionState) (string, error) {
	err := p.getProfile(s)
	return s.User, err
}

// ValidateSessionState validates the AccessToken
func (p *CriteoProvider) ValidateSessionState(s *SessionState) bool {
	return validateToken(p, s.AccessToken, getCriteoHeader(s.AccessToken))
}

// ValidateGroup validates that the provided email exists in the configured Criteo
// group(s).
func (p *CriteoProvider) ValidateGroup(s *SessionState) bool {
	return p.GroupValidator(s)
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new ID token if required
func (p *CriteoProvider) RefreshSessionIfNeeded(s *SessionState) (bool, error) {
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}

	if !p.ValidateGroup(s) {
		return false, fmt.Errorf("%s is no longer in the group(s)", s.Email)
	}

	origExpiration := s.ExpiresOn
	s.ExpiresOn = time.Now().Add(time.Second).Truncate(time.Second)
	fmt.Printf("refreshed access token %s (expired on %s)\n", s, origExpiration)
	return false, nil
}

func (p *CriteoProvider) userInGroup(groups []string, s *SessionState) bool {
	profile, err := p.getExtendedProfile(s.User)
	if err != nil {
		log.Print(err)
		return false
	}

	for _, ug := range profile.groups.Groups {
		for _, g := range groups {
			if ug.Name == g {
				return true
			}
		}
	}
	return false
}
