package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strings"

	"github.com/chainreactors/logs"
)

type zombieTarget struct {
	IP       string            `json:"ip"`
	Port     string            `json:"port"`
	Service  string            `json:"service"`
	Username string            `json:"username,omitempty"`
	Password string            `json:"password,omitempty"`
	Scheme   string            `json:"scheme,omitempty"`
	Param    map[string]string `json:"param,omitempty"`
}

func (t *zombieTarget) key() string {
	return t.IP + "|" + t.Port + "|" + t.Service + "|" + t.Username + "|" + t.Password
}

var schemeToService = map[string]string{
	"mysql": "mysql", "mariadb": "mysql",
	"postgres": "postgresql", "postgresql": "postgresql",
	"mongodb": "mongo", "mongodb+srv": "mongo",
	"redis": "redis", "rediss": "redis",
	"mssql": "mssql", "sqlserver": "mssql",
	"ssh": "ssh", "ftp": "ftp",
	"ldap": "ldap", "ldaps": "ldap",
	"http": "http", "https": "https",
	"vnc": "vnc", "rdp": "rdp",
	"telnet": "telnet", "smb": "smb",
	"amqp": "amqp", "mqtt": "mqtt",
	"oracle": "oracle",
}

var serviceDefaultPort = map[string]string{
	"mysql": "3306", "postgresql": "5432", "mssql": "1433",
	"mongo": "27017", "redis": "6379", "ssh": "22",
	"ftp": "21", "rdp": "3389", "smb": "445",
	"ldap": "389", "http": "80", "https": "443",
	"vnc": "5900", "telnet": "23", "oracle": "1521",
	"amqp": "5672", "mqtt": "1883",
}

var placeholders = map[string]bool{
	"localhost": true, "127.0.0.1": true, "0.0.0.0": true,
	"changeme": true, "todo": true, "xxx": true, "example": true,
	"password": true, "your_password": true, "your-password": true,
}

var jdbcPrefix = regexp.MustCompile(`^jdbc:([a-z0-9]+):`)
var odbcPattern = regexp.MustCompile(`(?i)(?:Server|Data\s*Source|Host)\s*=\s*([^;]+)`)
var odbcUser = regexp.MustCompile(`(?i)(?:User(?:\s*Id)?|Uid)\s*=\s*([^;]+)`)
var odbcPass = regexp.MustCompile(`(?i)(?:Password|Pwd)\s*=\s*([^;]+)`)
var odbcPort = regexp.MustCompile(`(?i)(?:Port)\s*=\s*([^;]+)`)
var urlSchemeRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]*://`)

func findingsToZombieTargets(findings []Finding) []*zombieTarget {
	var targets []*zombieTarget
	seen := map[string]bool{}

	for _, f := range findings {
		parsed := parseFinding(f)
		for _, t := range parsed {
			if !isValidTarget(t) {
				continue
			}
			k := t.key()
			if seen[k] {
				continue
			}
			seen[k] = true
			targets = append(targets, t)
		}
	}
	return targets
}

func parseFinding(f Finding) []*zombieTarget {
	var targets []*zombieTarget

	for _, ev := range f.Extracts {
		t := parseExtractValue(ev.Value)
		if t != nil {
			targets = append(targets, t)
		}
	}
	for _, events := range f.Matches {
		for _, ev := range events {
			t := parseExtractValue(ev.Value)
			if t != nil {
				targets = append(targets, t)
			}
		}
	}
	return targets
}

func parseExtractValue(value string) *zombieTarget {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}

	if jdbcPrefix.MatchString(value) {
		return parseJDBC(value)
	}

	if strings.Contains(value, ";") && odbcPattern.MatchString(value) {
		return parseODBC(value)
	}

	if urlSchemeRe.MatchString(value) {
		return parseURL(value)
	}

	return nil
}

func parseURL(raw string) *zombieTarget {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil
	}

	scheme := strings.ToLower(u.Scheme)
	service, ok := schemeToService[scheme]
	if !ok {
		return nil
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = serviceDefaultPort[service]
	}

	t := &zombieTarget{
		IP:      host,
		Port:    port,
		Service: service,
		Scheme:  scheme,
	}

	if u.User != nil {
		t.Username = u.User.Username()
		t.Password, _ = u.User.Password()
	}

	return t
}

func parseJDBC(raw string) *zombieTarget {
	m := jdbcPrefix.FindStringSubmatch(raw)
	if m == nil {
		return nil
	}

	subprotocol := strings.ToLower(m[1])
	rest := raw[len(m[0]):]

	if !strings.HasPrefix(rest, "//") {
		rest = "//" + rest
	}

	service, ok := schemeToService[subprotocol]
	if !ok {
		service = subprotocol
	}

	u, err := url.Parse(subprotocol + ":" + rest)
	if err != nil || u.Host == "" {
		parts := strings.SplitN(rest, "?", 2)
		rest = parts[0]
		u, err = url.Parse("x://" + strings.TrimPrefix(rest, "//"))
		if err != nil || u.Host == "" {
			return nil
		}
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = serviceDefaultPort[service]
	}

	t := &zombieTarget{
		IP:      host,
		Port:    port,
		Service: service,
		Scheme:  subprotocol,
	}

	if u.User != nil {
		t.Username = u.User.Username()
		t.Password, _ = u.User.Password()
	}

	query := u.Query()
	if user := query.Get("user"); user != "" && t.Username == "" {
		t.Username = user
	}
	if pass := query.Get("password"); pass != "" && t.Password == "" {
		t.Password = pass
	}

	if strings.Contains(raw, ";") {
		pairs := strings.Split(raw, ";")
		for _, pair := range pairs {
			kv := strings.SplitN(pair, "=", 2)
			if len(kv) != 2 {
				continue
			}
			k := strings.TrimSpace(strings.ToLower(kv[0]))
			v := strings.TrimSpace(kv[1])
			switch k {
			case "user", "username":
				if t.Username == "" {
					t.Username = v
				}
			case "password":
				if t.Password == "" {
					t.Password = v
				}
			}
		}
	}

	return t
}

func parseODBC(raw string) *zombieTarget {
	t := &zombieTarget{Service: "mssql", Scheme: "mssql"}

	if m := odbcPattern.FindStringSubmatch(raw); m != nil {
		hostPort := strings.TrimSpace(m[1])
		host, port, err := net.SplitHostPort(hostPort)
		if err != nil {
			t.IP = hostPort
		} else {
			t.IP = host
			t.Port = port
		}
	}
	if m := odbcUser.FindStringSubmatch(raw); m != nil {
		t.Username = strings.TrimSpace(m[1])
	}
	if m := odbcPass.FindStringSubmatch(raw); m != nil {
		t.Password = strings.TrimSpace(m[1])
	}
	if m := odbcPort.FindStringSubmatch(raw); m != nil && t.Port == "" {
		t.Port = strings.TrimSpace(m[1])
	}

	if t.Port == "" {
		t.Port = serviceDefaultPort[t.Service]
	}

	if t.IP == "" {
		return nil
	}
	return t
}

func isValidTarget(t *zombieTarget) bool {
	if t.IP == "" {
		return false
	}
	if strings.HasPrefix(t.IP, "${") || strings.HasPrefix(t.IP, "{{") {
		return false
	}
	if placeholders[strings.ToLower(t.IP)] {
		return false
	}
	if t.Password != "" && placeholders[strings.ToLower(t.Password)] {
		t.Password = ""
	}
	return true
}

func writeZombieOutput(w io.Writer, findings []Finding, quiet bool) {
	targets := findingsToZombieTargets(findings)

	withCreds := 0
	for _, t := range targets {
		if t.Username != "" || t.Password != "" {
			withCreds++
		}
		data, _ := json.Marshal(t)
		fmt.Fprintln(w, string(data))
	}

	if !quiet {
		hostOnly := len(targets) - withCreds
		logs.Log.Infof("Extracted %d zombie targets (%d with credentials, %d host-only)",
			len(targets), withCreds, hostOnly)
	}
}

func writeZombieArray(w io.Writer, findings []Finding) {
	targets := findingsToZombieTargets(findings)
	data, _ := json.MarshalIndent(targets, "", "  ")
	fmt.Fprintln(w, string(data))
}

// zombieOutputWriter handles -s file output for zombie format
type zombieOutputWriter struct {
	findings []Finding
}

func (z *zombieOutputWriter) addFinding(f Finding) {
	z.findings = append(z.findings, f)
}

func (z *zombieOutputWriter) flush(w io.Writer, quiet bool) {
	writeZombieOutput(w, z.findings, quiet)
}

// findingHasConnInfo checks if a finding contains parseable connection info
func findingHasConnInfo(f Finding) bool {
	for _, ev := range f.Extracts {
		if urlSchemeRe.MatchString(ev.Value) || jdbcPrefix.MatchString(ev.Value) ||
			odbcPattern.MatchString(ev.Value) {
			return true
		}
	}
	for _, events := range f.Matches {
		for _, ev := range events {
			if urlSchemeRe.MatchString(ev.Value) || jdbcPrefix.MatchString(ev.Value) ||
				odbcPattern.MatchString(ev.Value) {
				return true
			}
		}
	}
	return false
}

// allValues extracts all values from a finding for zombie parsing
func allValues(f Finding) []string {
	var vals []string
	for _, ev := range f.Extracts {
		vals = append(vals, ev.Value)
	}
	for _, events := range f.Matches {
		for _, ev := range events {
			vals = append(vals, ev.Value)
		}
	}
	return vals
}
