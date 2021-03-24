package header

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/options/util"
	sessionsapi "github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
)

type Injector interface {
	Inject(http.Header, *http.Request, *sessionsapi.SessionState)
}

type injector struct {
	valueInjectors []valueInjector
}

func (i injector) Inject(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
	for _, injector := range i.valueInjectors {
		injector.inject(header, req, session)
	}
}

func NewInjector(headers []options.Header) (Injector, error) {
	injectors := []valueInjector{}
	for _, header := range headers {
		for _, value := range header.Values {
			injector, err := newValueinjector(header.Name, value)
			if err != nil {
				return nil, fmt.Errorf("error building injector for header %q: %v", header.Name, err)
			}
			injectors = append(injectors, injector)
		}
	}

	return &injector{valueInjectors: injectors}, nil
}

type valueInjector interface {
	inject(http.Header, *http.Request, *sessionsapi.SessionState)
}

func newValueinjector(name string, value options.HeaderValue) (valueInjector, error) {
	switch {
	case value.SecretSource != nil && value.ClaimSource == nil && value.RequestSource == nil:
		return newSecretInjector(name, value.SecretSource)
	case value.SecretSource == nil && value.ClaimSource != nil && value.RequestSource == nil:
		return newClaimInjector(name, value.ClaimSource)
	case value.SecretSource == nil && value.ClaimSource == nil && value.RequestSource != nil:
		return newRequestInjector(name, value.RequestSource)
	default:
		return nil, fmt.Errorf("header %q value has multiple entries: only one entry per value is allowed", name)
	}
}

type injectorFunc struct {
	injectFunc func(http.Header, *http.Request, *sessionsapi.SessionState)
}

func (i *injectorFunc) inject(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
	i.injectFunc(header, req, session)
}

func newInjectorFunc(injectFunc func(header http.Header, req *http.Request, session *sessionsapi.SessionState)) valueInjector {
	return &injectorFunc{injectFunc: injectFunc}
}

func newSecretInjector(name string, source *options.SecretSource) (valueInjector, error) {
	value, err := util.GetSecretValue(source)
	if err != nil {
		return nil, fmt.Errorf("error getting secret value: %v", err)
	}

	return newInjectorFunc(func(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
		header.Add(name, string(value))
	}), nil
}

func newClaimInjector(name string, source *options.ClaimSource) (valueInjector, error) {
	switch {
	case source.BasicAuthPassword != nil:
		password, err := util.GetSecretValue(source.BasicAuthPassword)
		if err != nil {
			return nil, fmt.Errorf("error loading basicAuthPassword: %v", err)
		}
		return newInjectorFunc(func(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
			claimValues := session.GetClaim(source.Claim)
			for _, claim := range claimValues {
				if claim == "" {
					continue
				}
				auth := claim + ":" + string(password)
				header.Add(name, "Basic "+base64.StdEncoding.EncodeToString([]byte(auth)))
			}
		}), nil
	case source.Prefix != "":
		return newInjectorFunc(func(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
			claimValues := session.GetClaim(source.Claim)
			for _, claim := range claimValues {
				if claim == "" {
					continue
				}
				header.Add(name, source.Prefix+claim)
			}
		}), nil
	default:
		return newInjectorFunc(func(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
			claimValues := session.GetClaim(source.Claim)
			for _, claim := range claimValues {
				if claim == "" {
					continue
				}
				header.Add(name, claim)
			}
		}), nil
	}
}

func newRequestInjector(name string, source *options.RequestSource) (valueInjector, error) {
	switch source.RequestSourceAttr {
	case options.RequestSourceAttrProto:
		return newInjectorFunc(func(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
			if req.TLS != nil {
				header.Add(name, "https")
			} else {
				header.Add(name, "http")
			}
		}), nil
	case options.RequestSourceAttrHost:
		return newInjectorFunc(func(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
			header.Add(name, req.Host)
		}), nil
	case options.RequestSourceAttrURI:
		return newInjectorFunc(func(header http.Header, req *http.Request, session *sessionsapi.SessionState) {
			header.Add(name, req.RequestURI)
		}), nil
	default:
		return nil, nil
	}
}
