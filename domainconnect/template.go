package domainconnect

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Number is a JSON number that a template may also write as a string, as the
// specification allows for a TTL, a priority and a port.
type Number string

// UnmarshalJSON accepts 3600 and "3600", and a variable such as "%ttl%".
func (n *Number) UnmarshalJSON(raw []byte) error {
	raw = bytes.TrimSpace(raw)
	if len(raw) > 0 && raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return err
		}
		*n = Number(s)
		return nil
	}
	if string(raw) == "null" {
		*n = ""
		return nil
	}
	*n = Number(raw)
	return nil
}

// Template is a Domain Connect template, with the keys of the specification.
type Template struct {
	ProviderID          string           `json:"providerId"`
	ProviderName        string           `json:"providerName"`
	ServiceID           string           `json:"serviceId"`
	ServiceName         string           `json:"serviceName"`
	Version             int              `json:"version,omitempty"`
	LogoURL             string           `json:"logoUrl,omitempty"`
	Description         string           `json:"description,omitempty"`
	VariableDescription string           `json:"variableDescription,omitempty"`
	SyncBlock           bool             `json:"syncBlock,omitempty"`
	SharedProviderName  bool             `json:"sharedProviderName,omitempty"`
	SharedServiceName   bool             `json:"sharedServiceName,omitempty"`
	SyncPubKeyDomain    string           `json:"syncPubKeyDomain,omitempty"`
	SyncRedirectDomain  string           `json:"syncRedirectDomain,omitempty"`
	MultiInstance       bool             `json:"multiInstance,omitempty"`
	WarnPhishing        bool             `json:"warnPhishing,omitempty"`
	HostRequired        bool             `json:"hostRequired,omitempty"`
	Records             []TemplateRecord `json:"records"`
}

// TemplateRecord is one record of a template.
type TemplateRecord struct {
	Type                      string `json:"type"`
	GroupID                   string `json:"groupId,omitempty"`
	Essential                 string `json:"essential,omitempty"`
	Host                      string `json:"host,omitempty"`
	Name                      string `json:"name,omitempty"`
	PointsTo                  string `json:"pointsTo,omitempty"`
	TTL                       Number `json:"ttl,omitempty"`
	Data                      string `json:"data,omitempty"`
	TxtConflictMatchingMode   string `json:"txtConflictMatchingMode,omitempty"`
	TxtConflictMatchingPrefix string `json:"txtConflictMatchingPrefix,omitempty"`
	Priority                  Number `json:"priority,omitempty"`
	SPFRules                  string `json:"spfRules,omitempty"`
}

// maxTemplate is the most bytes ParseTemplate reads.
const maxTemplate = 1 << 20

// ParseTemplate reads a template. Keys it does not know are refused, because a
// misspelled key is a setting that silently does nothing.
func ParseTemplate(r io.Reader) (Template, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxTemplate+1))
	if err != nil {
		return Template{}, fmt.Errorf("domainconnect: reading the template: %w", err)
	}
	if len(raw) > maxTemplate {
		return Template{}, errors.New("domainconnect: the template is larger than 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var t Template
	if err := decoder.Decode(&t); err != nil {
		return Template{}, fmt.Errorf("domainconnect: the template is not valid: %w", err)
	}
	if decoder.More() {
		return Template{}, errors.New("domainconnect: the template has content after its JSON object")
	}
	return t, nil
}

var (
	idPattern       = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	variablePattern = regexp.MustCompile(`%([A-Za-z0-9_]+)%`)
)

// FileName is the name the template must have in the templates repository.
func (t Template) FileName() string { return t.ProviderID + "." + t.ServiceID + ".json" }

// Validate checks a template against the specification and against what a
// service that signs and applies to many DNS providers needs: it reports every
// problem at once.
func (t Template) Validate() error {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	if !idPattern.MatchString(t.ProviderID) || !strings.Contains(t.ProviderID, ".") {
		add("providerId %q must be a domain name", t.ProviderID)
	}
	if !idPattern.MatchString(t.ServiceID) {
		add("serviceId %q must be URL friendly, with no spaces", t.ServiceID)
	}
	if t.ProviderName == "" || t.ServiceName == "" {
		add("providerName and serviceName are required")
	}
	if t.SyncBlock {
		add("syncBlock is true, which disables the synchronous flow this package implements")
	}
	if t.SyncPubKeyDomain == "" {
		add("syncPubKeyDomain is required: requests with variables are signed")
	}
	if t.WarnPhishing {
		add("warnPhishing is set: a service that signs does not need it")
	}
	if len(t.Records) == 0 {
		add("a template needs records")
	}
	for i, r := range t.Records {
		at := fmt.Sprintf("record %d (%s)", i+1, r.Type)
		switch strings.ToUpper(r.Type) {
		case "A", "AAAA":
			require(add, at, "host", r.Host, "pointsTo", r.PointsTo, "ttl", string(r.TTL))
		case "CNAME":
			require(add, at, "host", r.Host, "pointsTo", r.PointsTo, "ttl", string(r.TTL))
			if (r.Host == "" || r.Host == "@") && !t.HostRequired {
				add("%s: a CNAME at the root needs hostRequired", at)
			}
		case "MX":
			require(add, at, "host", r.Host, "pointsTo", r.PointsTo, "ttl", string(r.TTL), "priority", string(r.Priority))
		case "TXT":
			require(add, at, "host", r.Host, "data", r.Data, "ttl", string(r.TTL))
			if v := strings.ToLower(strings.TrimSpace(r.Data)); strings.HasPrefix(v, "v=spf1") {
				add("%s: an SPF record is a plain TXT, and two of them at one name break SPF. Use SPFM", at)
			}
		case "SPFM":
			require(add, at, "host", r.Host, "spfRules", r.SPFRules)
		case "APEXCNAME":
			add("%s: APEXCNAME is not supported by every provider. Use a CNAME", at)
		default:
			add("%s: the type is not one this package expands", at)
		}
		if r.GroupID != "" && strings.Contains(r.GroupID, "%") {
			add("%s: groupId must not contain variables", at)
		}
	}
	if len(problems) > 0 {
		return errors.New("domainconnect: the template has problems: " + strings.Join(problems, "; "))
	}
	return nil
}

func require(add func(string, ...any), at string, pairs ...string) {
	for i := 0; i+1 < len(pairs); i += 2 {
		if strings.TrimSpace(pairs[i+1]) == "" {
			add("%s: %s is required", at, pairs[i])
		}
	}
}

// Variables answers the names of the %variables% the template uses, apart from
// the built-in host, domain and fqdn.
func (t Template) Variables() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range t.Records {
		for _, text := range []string{r.Host, r.Name, r.PointsTo, r.Data, r.SPFRules, string(r.TTL), string(r.Priority)} {
			for _, m := range variablePattern.FindAllStringSubmatch(text, -1) {
				name := m[1]
				if builtin(name) || seen[name] {
					continue
				}
				seen[name] = true
				out = append(out, name)
			}
		}
	}
	return out
}

func builtin(name string) bool { return name == "host" || name == "domain" || name == "fqdn" }

// Expanded is a record a template creates once its variables are filled in.
type Expanded struct {
	Type    string
	GroupID string
	// Host is relative to the zone, empty at the apex: the name as the
	// application's own records spell it.
	Host     string
	Content  string
	TTL      int
	Priority int
}

// Expand fills the variables for a domain (the root) and host (the part below
// it, empty at the root) and answers the records the template would create. An
// SPFM record expands as the TXT record it creates when no SPF exists at the
// name: v=spf1, the rules and ~all.
func (t Template) Expand(domain, host string, variables map[string]string) ([]Expanded, error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	host = strings.ToLower(strings.Trim(host, "."))
	fqdn := domain
	if host != "" {
		fqdn = host + "." + domain
	}
	values := map[string]string{"host": host, "domain": domain, "fqdn": fqdn}
	for name, value := range variables {
		if builtin(name) {
			return nil, fmt.Errorf("domainconnect: %q is built in", name)
		}
		values[name] = value
	}
	var missing []string
	fill := func(text string) string {
		return variablePattern.ReplaceAllStringFunc(text, func(match string) string {
			name := match[1 : len(match)-1]
			value, ok := values[name]
			if !ok {
				missing = append(missing, name)
			}
			return value
		})
	}
	number := func(n Number) (int, error) {
		if n == "" {
			return 0, nil
		}
		return strconv.Atoi(fill(string(n)))
	}
	// relative turns a template host, relative to [host.]domain, into one
	// relative to the zone.
	relative := func(h string) string {
		h = fill(h)
		switch {
		case h == "" || h == "@":
			return host
		case strings.HasSuffix(h, "."):
			return strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(h, "."), domain), ".")
		case host != "":
			return h + "." + host
		}
		return h
	}
	target := func(p string) string {
		if p == "" || p == "@" {
			return fqdn
		}
		return fill(p)
	}

	var out []Expanded
	for i, r := range t.Records {
		e := Expanded{Type: strings.ToUpper(r.Type), GroupID: r.GroupID, Host: relative(r.Host)}
		var err error
		if e.TTL, err = number(r.TTL); err != nil {
			return nil, fmt.Errorf("domainconnect: record %d has a ttl that is not a number", i+1)
		}
		if e.Priority, err = number(r.Priority); err != nil {
			return nil, fmt.Errorf("domainconnect: record %d has a priority that is not a number", i+1)
		}
		switch e.Type {
		case "A", "AAAA", "CNAME", "MX":
			e.Content = target(r.PointsTo)
		case "TXT":
			e.Content = target(r.Data)
		case "SPFM":
			e.Type = "TXT"
			e.Content = "v=spf1 " + strings.TrimSpace(fill(r.SPFRules)) + " ~all"
		default:
			return nil, fmt.Errorf("domainconnect: record %d has a type this package does not expand", i+1)
		}
		out = append(out, e)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("domainconnect: the template needs the variables %s", strings.Join(uniqueSorted(missing), ", "))
	}
	return out, nil
}

func uniqueSorted(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}
