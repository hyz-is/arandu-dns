package domainconnect

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// Request is one application of a template to a domain.
type Request struct {
	// ProviderID and ServiceID name the template: the file
	// <ProviderID>.<ServiceID>.json of the templates repository.
	ProviderID string
	ServiceID  string
	// Variables fill the %name% variables of the template. The built-in %host%,
	// %domain% and %fqdn% come from the Discovery.
	Variables map[string]string
	// RedirectURI is where the provider sends the browser after the customer
	// confirms or cancels. A provider that requires signed requests honours any
	// address that is signed, so it is part of what is signed.
	RedirectURI string
	// State comes back unchanged on the redirect, as the anti-forgery value of
	// the caller.
	State string
	// GroupIDs apply only the groups of records named. Empty applies all.
	GroupIDs []string
}

// ApplyURL builds the address the customer's browser is sent to.
//
// The query is the request in the order of its keys, encoded once; with a
// Signer, key and sig follow it, sig last, and the signature covers exactly the
// query before them. A nil Signer builds an unsigned address, which only a
// template without a syncPubKeyDomain accepts.
func (d Discovery) ApplyURL(request Request, signer *Signer) (string, error) {
	if d.syncUX == nil {
		return "", ErrUnsupported
	}
	if request.ProviderID == "" || request.ServiceID == "" {
		return "", errors.New("domainconnect: the request names no template")
	}
	query := url.Values{"domain": {d.Domain}}
	if d.Host != "" {
		query.Set("host", d.Host)
	}
	names := make([]string, 0, len(request.Variables))
	for name := range request.Variables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if reserved(name) {
			return "", fmt.Errorf("domainconnect: %q is a parameter of the protocol, not a variable", name)
		}
		query.Set(name, request.Variables[name])
	}
	if request.RedirectURI != "" {
		u, err := url.Parse(request.RedirectURI)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return "", errors.New("domainconnect: the redirect address is not an http(s) URL")
		}
		query.Set("redirect_uri", request.RedirectURI)
	}
	if request.State != "" {
		query.Set("state", request.State)
	}
	if len(request.GroupIDs) > 0 {
		query.Set("groupId", strings.Join(request.GroupIDs, ","))
	}

	encoded := query.Encode()
	if signer != nil {
		signature, err := signer.Sign(encoded)
		if err != nil {
			return "", err
		}
		encoded += "&key=" + url.QueryEscape(signer.KeyHost()) + "&sig=" + url.QueryEscape(signature)
	}
	return d.syncUX.String() + "/v2/domainTemplates/providers/" + url.PathEscape(request.ProviderID) +
		"/services/" + url.PathEscape(request.ServiceID) + "/apply?" + encoded, nil
}

// reserved reports whether a name is a parameter of the protocol, which a
// variable may not shadow.
func reserved(name string) bool {
	switch strings.ToLower(name) {
	case "domain", "host", "redirect_uri", "state", "providername", "servicename", "groupid", "sig", "key":
		return true
	}
	return false
}
