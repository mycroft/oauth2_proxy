package main

import (
	"fmt"
	"strings"

	"log"

	"github.com/BurntSushi/toml"
	"gopkg.in/ldap.v3"
)

type ldapServerConf struct {
	Host         string           `toml:"host"`
	Port         int              `toml:"port"`
	BindDN       string           `toml:"bind_dn"`
	BindPassword string           `toml:"bind_password"`
	Attr         ldapAttributeMap `toml:"attributes"`

	SearchFilter     string   `toml:"search_filter"`
	SearchBaseDnList []string `toml:"search_base_dns"`

	GroupDnList []string `toml:"group_dns"`
}

type ldapAttributeMap struct {
	MemberOf string `toml:"member_of"`
}

// LdapAuthenticator represents the structure of an ldap authenticator
type LdapAuthenticator struct {
	Conf *ldapServerConf
}

// NewLdapAuthenticatorFromFile consctructs an LdapAuthenticator from the file at the path given
func NewLdapAuthenticatorFromFile(path string) (*LdapAuthenticator, error) {
	var conf ldapServerConf
	if _, err := toml.DecodeFile(path, &conf); err != nil {
		return nil, err
	}

	return newLdapAuthenticator(&conf)
}

func newLdapAuthenticator(conf *ldapServerConf) (*LdapAuthenticator, error) {
	return &LdapAuthenticator{Conf: conf}, nil
}

// Validate checks a users password against the LdapAuthenticator
func (a *LdapAuthenticator) Validate(user string, password string) bool {
	ldapHost := fmt.Sprintf("%s:%d", a.Conf.Host, a.Conf.Port)
	l, err := ldap.Dial("tcp", ldapHost)
	if err != nil {
		log.Printf("LDAP: Unable to dial %s: %s", ldapHost, err)
		return false
	}
	defer l.Close()

	// First bind with a read only user
	err = l.Bind(a.Conf.BindDN, a.Conf.BindPassword)
	if err != nil {
		log.Printf("LDAP: Unable to bind as read-only user '%s': %s", a.Conf.BindDN, err)
		return false
	}

	// Search for the given username
	var searchResult *ldap.SearchResult
	for _, searchBase := range a.Conf.SearchBaseDnList {
		searchReq := ldap.SearchRequest{
			BaseDN:       searchBase,
			Scope:        ldap.ScopeWholeSubtree,
			DerefAliases: ldap.NeverDerefAliases,
			Attributes: []string{
				a.Conf.Attr.MemberOf,
			},
			Filter: strings.Replace(a.Conf.SearchFilter, "%s", ldap.EscapeFilter(user), -1),
		}

		searchResult, err = l.Search(&searchReq)
		if err != nil {
			log.Printf("LDAP: Unable to search for user '%s': %s", user, err)
		}

		if len(searchResult.Entries) > 0 {
			break
		}
	}

	if len(searchResult.Entries) != 1 {
		log.Printf("LDAP: User does not exist or too many entries returned")
		return false
	}

	userdn := searchResult.Entries[0].DN

	// Bind as the user to verify their password
	err = l.Bind(userdn, password)
	if err != nil {
		log.Printf("Invalid LDAP entry for %s.", user)
		return false
	}

	// Validate groups
	if a.Conf.GroupDnList == nil {
		return true
	}

	for _, allowedGroupDN := range a.Conf.GroupDnList {
		for _, groupDN := range searchResult.Entries[0].GetAttributeValues("memberOf") {
			if groupDN == allowedGroupDN {
				return true
			}
		}
	}

	log.Printf("Invalid LDAP entry for %s.", user)
	return false
}
