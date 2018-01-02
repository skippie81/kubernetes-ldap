package auth

import (
	"net/http"

	"kubernetes-ldap/ldap"
	"kubernetes-ldap/token"

	goldap "github.com/go-ldap/ldap"
	"github.com/golang/glog"
	"strings"
	"regexp"
	"time"
)

// LDAPTokenIssuer issues cryptographically secure tokens after authenticating the
// user against a backing LDAP directory.
type LDAPTokenIssuer struct {
	LDAPServer        	string
	LDAPAuthenticator 	ldap.Authenticator
	TokenSigner       	token.Signer
	GroupFilter	  	string
	ExpireTime        	int
	UsernameLDAPAttribute	string
}

func (lti *LDAPTokenIssuer) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	user, password, ok := req.BasicAuth()

	if !ok {
		resp.Header().Add("WWW-Authenticate", `Basic realm="kubernetes ldap"`)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	glog.Infof("Got authentication request for user: %s",user)

	// Authenticate the user via LDAP
	ldapEntry, err := lti.LDAPAuthenticator.Authenticate(user, password)
	if err != nil {
		glog.Errorf("Error authenticating user: %v", err)
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Auth was successful, create token
	glog.Info("Authentication sucessfull")
	token := lti.createToken(ldapEntry)

	glog.Infof("Token username: %s",token.Username)
	glog.Infof("Token expire time: %s",token.Exp)
	glog.Infof("Token has folloing groups: %s",token.Groups)

	// Sign token and return
	signedToken, err := lti.TokenSigner.Sign(token)
	if err != nil {
		glog.Errorf("Error signing token: %v", err)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.Header().Add("Content-Type", "text/plain")
	resp.Write([]byte(signedToken))
}

func (lti *LDAPTokenIssuer) getGroupsFromMembersOf(membersOf []string) []string {
	groupsOf := []string {}
	uniqueGroups := make(map[string]struct{})

	re := regexp.MustCompile(`(?i)CN=`)

	for _, memberOf := range membersOf {
		splitted_str := strings.Split(memberOf, ",")
		for _, element := range splitted_str {
			if !strings.Contains(strings.ToUpper(element), "CN=") {
				continue
			}

			group := re.ReplaceAllString(element, "")


			// run the group filter if defined
			if lti.GroupFilter != "" {
			  match,_ := regexp.MatchString(lti.GroupFilter,group)

				if !match {
					//this group does not match the group name filter
					continue
				}
			}

			if _, ok := uniqueGroups[group]; ok {
				//this group has been considered and added already
				continue
			}

			groupsOf = append(groupsOf, group)
			uniqueGroups[group] = struct{}{}
		}
	}

    return groupsOf
}

func (lti *LDAPTokenIssuer) createToken(ldapEntry *goldap.Entry) *token.AuthToken {
	// if attribute for username is empty use mail
	if lti.UsernameLDAPAttribute == "" {
		lti.UsernameLDAPAttribute = "mail"
	}

	return &token.AuthToken{
		Username: ldapEntry.GetAttributeValue(lti.UsernameLDAPAttribute),
		Exp: time.Now().Add(time.Hour * time.Duration(lti.ExpireTime)),
		Groups: lti.getGroupsFromMembersOf(ldapEntry.GetAttributeValues("memberOf")),
		Assertions: map[string]string{
			"ldapServer": lti.LDAPServer,
			"userDN":     ldapEntry.DN,
		},
	}
}
