// Package analyzer reads third-party (vendor) access logs, checks each event
// against the vendor's access policy and raises alerts for the behaviour the
// case study says must be monitored (report section 7.6): logins from
// unknown locations, unusual times, privilege upgrades, large downloads,
// plus missing MFA, expired access, discovery activity, movement outside
// the vendor's scope and mass file encryption.
//
// Every alert is mapped to a MITRE ATT&CK technique and to a stage of the
// third-party ransomware attack chain, so the analyzer can tell whether a
// single vendor account is walking through the whole chain.
package analyzer

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- Vendor policy ----------

// Window is a start/end time.
type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// Hours is the daily working window, in 24-hour clock (start inclusive, end exclusive).
type Hours struct {
	Start int `json:"start"`
	End   int `json:"end"`
}

// Vendor is a third party's access policy: what it is allowed to do.
type Vendor struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Service          string   `json:"service"`
	Accounts         []string `json:"accounts"`
	AllowedSystems   []string `json:"allowedSystems"`
	AllowedZones     []string `json:"allowedZones"`
	AllowedCountries []string `json:"allowedCountries"`
	AllowedHours     Hours    `json:"allowedHours"`
	MaxRole          string   `json:"maxRole"`
	AccessWindow     Window   `json:"accessWindow"`
	Active           bool     `json:"active"`
}

// Settings holds detection thresholds.
type Settings struct {
	LargeTransferMB         int `json:"largeTransferMB"`
	FailedLoginThreshold    int `json:"failedLoginThreshold"`
	FailedLoginWindowMin    int `json:"failedLoginWindowMin"`
	MassFileChangeThreshold int `json:"massFileChangeThreshold"`
}

// Policy is the whole vendors.json file.
type Policy struct {
	Organisation string   `json:"organisation"`
	Vendors      []Vendor `json:"vendors"`
	Settings     Settings `json:"settings"`
}

// DefaultSettings are used for any threshold left at zero.
var DefaultSettings = Settings{LargeTransferMB: 500, FailedLoginThreshold: 3, FailedLoginWindowMin: 10, MassFileChangeThreshold: 200}

// LoadPolicy parses vendors.json.
func LoadPolicy(r io.Reader) (*Policy, error) {
	var p Policy
	if err := json.NewDecoder(r).Decode(&p); err != nil {
		return nil, fmt.Errorf("vendor policy: %w", err)
	}
	if p.Settings.LargeTransferMB == 0 {
		p.Settings.LargeTransferMB = DefaultSettings.LargeTransferMB
	}
	if p.Settings.FailedLoginThreshold == 0 {
		p.Settings.FailedLoginThreshold = DefaultSettings.FailedLoginThreshold
	}
	if p.Settings.FailedLoginWindowMin == 0 {
		p.Settings.FailedLoginWindowMin = DefaultSettings.FailedLoginWindowMin
	}
	if p.Settings.MassFileChangeThreshold == 0 {
		p.Settings.MassFileChangeThreshold = DefaultSettings.MassFileChangeThreshold
	}
	return &p, nil
}

// roleRank orders roles from least to most privileged.
var roleRank = map[string]int{"viewer": 1, "operator": 2, "admin": 3, "domain_admin": 4}

// ---------- Log events ----------

// Event is one row of the vendor access log.
type Event struct {
	Line          int       `json:"line"`
	Time          time.Time `json:"time"`
	VendorID      string    `json:"vendorId"`
	Account       string    `json:"account"`
	SourceIP      string    `json:"sourceIp"`
	Country       string    `json:"country"`
	Action        string    `json:"action"`
	Target        string    `json:"target"`
	Zone          string    `json:"zone"`
	MFA           bool      `json:"mfa"`
	Role          string    `json:"role"`
	BytesOut      int64     `json:"bytesOut"`
	FilesModified int       `json:"filesModified"`
	Result        string    `json:"result"`
}

// IST is used when a timestamp has no time zone.
var IST = time.FixedZone("IST", 5*3600+30*60)

var timeLayouts = []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04"}

func parseTime(s string) (time.Time, error) {
	for _, l := range timeLayouts {
		if t, err := time.ParseInLocation(l, s, IST); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unrecognised timestamp %q", s)
}

var requiredColumns = []string{"timestamp", "vendor_id", "account", "src_ip", "country", "action", "target", "zone", "mfa", "role", "bytes_out", "files_modified", "result"}

// LoadEvents parses the access-log CSV. Rows that cannot be read are
// returned as warnings rather than stopping the analysis.
func LoadEvents(r io.Reader) ([]Event, []string, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, nil, fmt.Errorf("access log: cannot read header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	for _, c := range requiredColumns {
		if _, ok := col[c]; !ok {
			return nil, nil, fmt.Errorf("access log: missing column %q (expected: %s)", c, strings.Join(requiredColumns, ","))
		}
	}

	var events []Event
	var warnings []string
	line := 1
	for {
		rec, err := cr.Read()
		line++
		if err == io.EOF {
			break
		}
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: %v", line, err))
			continue
		}
		get := func(name string) string {
			if i := col[name]; i < len(rec) {
				return strings.TrimSpace(rec[i])
			}
			return ""
		}
		if strings.Join(rec, "") == "" {
			continue
		}
		t, err := parseTime(get("timestamp"))
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: %v", line, err))
			continue
		}
		bytesOut, _ := strconv.ParseInt(get("bytes_out"), 10, 64)
		files, _ := strconv.Atoi(get("files_modified"))
		mfa := strings.ToLower(get("mfa"))
		events = append(events, Event{
			Line: line, Time: t,
			VendorID: get("vendor_id"), Account: get("account"), SourceIP: get("src_ip"),
			Country: strings.ToUpper(get("country")), Action: strings.ToLower(get("action")),
			Target: get("target"), Zone: strings.ToLower(get("zone")),
			MFA:  mfa == "true" || mfa == "yes" || mfa == "1",
			Role: strings.ToLower(get("role")), BytesOut: bytesOut, FilesModified: files,
			Result: strings.ToLower(get("result")),
		})
	}
	sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	return events, warnings, nil
}

// ---------- Alerts ----------

// Severity weights feed the per-account risk score.
var severityWeight = map[string]int{"Low": 2, "Medium": 5, "High": 10, "Critical": 20}

// Alert is one detection.
type Alert struct {
	Rule      string    `json:"rule"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Stage     int       `json:"stage"`
	Technique string    `json:"technique"`
	Time      time.Time `json:"time"`
	VendorID  string    `json:"vendorId"`
	Vendor    string    `json:"vendor"`
	Account   string    `json:"account"`
	Detail    string    `json:"detail"`
	Controls  []string  `json:"controls"` // control IDs that would prevent or contain this
	Line      int       `json:"line"`
}

// AccountRisk aggregates alerts for one vendor account.
type AccountRisk struct {
	Account   string         `json:"account"`
	VendorID  string         `json:"vendorId"`
	Vendor    string         `json:"vendor"`
	Score     int            `json:"score"`
	Alerts    int            `json:"alerts"`
	Severity  map[string]int `json:"severity"`
	Stages    []int          `json:"stages"`
	Verdict   string         `json:"verdict"`
	FirstSeen time.Time      `json:"firstSeen"`
	LastSeen  time.Time      `json:"lastSeen"`
}

// StageHit says whether a chain stage was observed in the logs.
type StageHit struct {
	Stage
	Observed  bool      `json:"observed"`
	Alerts    int       `json:"alerts"`
	FirstSeen time.Time `json:"firstSeen"`
}

// Result is the full analysis.
type Result struct {
	Organisation string         `json:"organisation"`
	Events       int            `json:"events"`
	Vendors      int            `json:"vendors"`
	Accounts     int            `json:"accounts"`
	From         time.Time      `json:"from"`
	To           time.Time      `json:"to"`
	Alerts       []Alert        `json:"alerts"`
	BySeverity   map[string]int `json:"bySeverity"`
	ByRule       map[string]int `json:"byRule"`
	AccountRisk  []AccountRisk  `json:"accountRisk"`
	Chain        []StageHit     `json:"chain"`
	Warnings     []string       `json:"warnings"`
	Headline     string         `json:"headline"`
}

// Analyze runs every rule over the events.
func Analyze(p *Policy, events []Event) Result {
	vendors := map[string]*Vendor{}
	accountOwner := map[string]string{}
	for i := range p.Vendors {
		v := &p.Vendors[i]
		vendors[v.ID] = v
		for _, a := range v.Accounts {
			accountOwner[a] = v.ID
		}
	}
	s := p.Settings
	res := Result{
		Organisation: p.Organisation,
		Events:       len(events),
		Alerts:       []Alert{},
		BySeverity:   map[string]int{},
		ByRule:       map[string]int{},
		Warnings:     []string{},
	}

	failed := map[string][]time.Time{} // account -> recent failed logins
	bruteRaised := map[string]bool{}   // account -> already alerted in this burst
	seenAccounts := map[string]bool{}
	seenVendors := map[string]bool{}

	add := func(e Event, v *Vendor, rule, title, sev string, stage int, tech, detail string, controls ...string) {
		name := e.VendorID
		if v != nil {
			name = v.Name
		}
		res.Alerts = append(res.Alerts, Alert{
			Rule: rule, Title: title, Severity: sev, Stage: stage, Technique: tech,
			Time: e.Time, VendorID: e.VendorID, Vendor: name, Account: e.Account,
			Detail: detail, Controls: controls, Line: e.Line,
		})
	}

	for _, e := range events {
		seenAccounts[e.Account] = true
		seenVendors[e.VendorID] = true
		v := vendors[e.VendorID]
		success := e.Result == "" || e.Result == "success"

		// Unknown vendor: traffic claiming to be a vendor connection we have no agreement with.
		if v == nil {
			add(e, nil, "UNKNOWN_VENDOR", "Connection from unregistered vendor", "High", 1, "T1199",
				fmt.Sprintf("Vendor ID %q is not in the vendor register.", e.VendorID), "vendor_assessment", "segmentation")
			continue
		}

		// Account not issued to this vendor.
		if owner, ok := accountOwner[e.Account]; !ok || owner != v.ID {
			if e.Action == "login" {
				add(e, v, "UNKNOWN_ACCOUNT", "Account not issued to this vendor", "High", 2, "T1078",
					fmt.Sprintf("%s is not a registered %s account.", e.Account, v.Name), "pam", "jit")
			}
		}

		// Just-in-time window / deactivated vendor.
		if e.Action == "login" && success {
			outside := (!v.AccessWindow.From.IsZero() && e.Time.Before(v.AccessWindow.From)) ||
				(!v.AccessWindow.To.IsZero() && e.Time.After(v.AccessWindow.To))
			if !v.Active || outside {
				detail := fmt.Sprintf("%s is marked inactive but the account still logged in.", v.Name)
				if outside {
					detail = fmt.Sprintf("Approved access for %s ran %s to %s; this login falls outside it.",
						v.Name, v.AccessWindow.From.Format("02 Jan 2006"), v.AccessWindow.To.Format("02 Jan 2006"))
				}
				add(e, v, "EXPIRED_ACCESS", "Login outside approved access window", "High", 2, "T1078", detail, "jit", "pam")
			}
		}

		switch e.Action {
		case "login":
			if !success {
				// Brute force: N failures inside the window.
				win := time.Duration(s.FailedLoginWindowMin) * time.Minute
				list := append(failed[e.Account], e.Time)
				kept := list[:0]
				for _, t := range list {
					if e.Time.Sub(t) <= win {
						kept = append(kept, t)
					}
				}
				failed[e.Account] = kept
				if len(kept) >= s.FailedLoginThreshold && !bruteRaised[e.Account] {
					bruteRaised[e.Account] = true
					add(e, v, "BRUTE_FORCE", "Repeated failed vendor logins", "High", 2, "T1110",
						fmt.Sprintf("%d failed logins in %d minutes from %s.", len(kept), s.FailedLoginWindowMin, e.SourceIP),
						"mfa", "monitoring")
				}
				continue
			}
			bruteRaised[e.Account] = false
			failed[e.Account] = nil

			if !e.MFA {
				add(e, v, "NO_MFA", "Vendor login without MFA", "High", 2, "T1078",
					"Successful login with password only; a stolen password is enough to get in.", "mfa")
			}
			if len(v.AllowedCountries) > 0 && !contains(v.AllowedCountries, e.Country) {
				add(e, v, "UNKNOWN_LOCATION", "Login from unknown location", "High", 1, "T1199",
					fmt.Sprintf("Login from %s (%s); %s is only expected from %s.", e.Country, e.SourceIP, v.Name, strings.Join(v.AllowedCountries, ", ")),
					"mfa", "monitoring")
			}
			if h := e.Time.Hour(); h < v.AllowedHours.Start || h >= v.AllowedHours.End {
				add(e, v, "OFF_HOURS", "Login at unusual time", "Medium", 2, "T1078",
					fmt.Sprintf("Login at %s; approved hours are %02d:00–%02d:00.", e.Time.Format("15:04"), v.AllowedHours.Start, v.AllowedHours.End),
					"jit", "monitoring")
			}

		case "privilege_change":
			if roleRank[e.Role] > roleRank[v.MaxRole] {
				add(e, v, "PRIV_ESCALATION", "Privilege upgrade beyond vendor role", "Critical", 2, "T1078",
					fmt.Sprintf("Role raised to %q on %s; vendor maximum is %q.", e.Role, e.Target, v.MaxRole),
					"pam", "least_privilege")
			}

		case "account_enum":
			add(e, v, "DISCOVERY_ACCOUNTS", "Account discovery from vendor session", "High", 3, "T1087",
				fmt.Sprintf("Directory/account listing run against %s.", e.Target), "least_privilege", "monitoring")

		case "port_scan":
			add(e, v, "DISCOVERY_NETWORK", "Network scan from vendor session", "High", 3, "T1046",
				fmt.Sprintf("Service scan of %s in %s.", e.Target, e.Zone), "segmentation", "monitoring")

		case "remote_session":
			if outOfScope(v, e) {
				add(e, v, "LATERAL_MOVEMENT", "Remote session to system outside vendor scope", "High", 4, "T1021",
					fmt.Sprintf("Remote session to %s in %s; vendor is approved only for %s.", e.Target, e.Zone, strings.Join(v.AllowedSystems, ", ")),
					"least_privilege", "segmentation", "pam")
			}

		case "file_access":
			if outOfScope(v, e) {
				sev := "High"
				if strings.Contains(e.Zone, "restricted") {
					sev = "Critical"
				}
				add(e, v, "SCOPE_VIOLATION", "Data accessed outside vendor scope", sev, 5, "T1005",
					fmt.Sprintf("Read data on %s in %s.", e.Target, e.Zone), "least_privilege", "segmentation")
			}

		case "data_transfer":
			mb := e.BytesOut / (1024 * 1024)
			if mb >= int64(s.LargeTransferMB) {
				add(e, v, "LARGE_TRANSFER", "Large outbound data transfer", "Critical", 6, "T1567",
					fmt.Sprintf("%s sent to %s (threshold %d MB).", humanBytes(e.BytesOut), e.Target, s.LargeTransferMB),
					"monitoring", "segmentation", "least_privilege")
			}

		case "file_modify":
			if e.FilesModified >= s.MassFileChangeThreshold {
				add(e, v, "MASS_ENCRYPTION", "Mass file modification (possible encryption)", "Critical", 7, "T1486",
					fmt.Sprintf("%d files rewritten on %s in one burst.", e.FilesModified, e.Target),
					"backups", "monitoring", "segmentation")
			}
		}
	}

	if len(events) > 0 {
		res.From, res.To = events[0].Time, events[len(events)-1].Time
	}
	res.Accounts, res.Vendors = len(seenAccounts), len(seenVendors)
	for _, a := range res.Alerts {
		res.BySeverity[a.Severity]++
		res.ByRule[a.Rule]++
	}
	res.AccountRisk = accountRisk(res.Alerts)
	res.Chain = chainCoverage(res.Alerts)
	res.Headline = headline(res)
	return res
}

func accountRisk(alerts []Alert) []AccountRisk {
	byAcc := map[string]*AccountRisk{}
	stages := map[string]map[int]bool{}
	var order []string
	for _, a := range alerts {
		r, ok := byAcc[a.Account]
		if !ok {
			r = &AccountRisk{Account: a.Account, VendorID: a.VendorID, Vendor: a.Vendor, Severity: map[string]int{}, FirstSeen: a.Time}
			byAcc[a.Account] = r
			stages[a.Account] = map[int]bool{}
			order = append(order, a.Account)
		}
		r.Alerts++
		r.Severity[a.Severity]++
		r.Score += severityWeight[a.Severity]
		r.LastSeen = a.Time
		stages[a.Account][a.Stage] = true
	}
	out := make([]AccountRisk, 0, len(order))
	for _, acc := range order {
		r := byAcc[acc]
		for st := range stages[acc] {
			r.Stages = append(r.Stages, st)
		}
		sort.Ints(r.Stages)
		if r.Score > 100 {
			r.Score = 100
		}
		n := len(r.Stages)
		late := stages[acc][6] || stages[acc][7]
		switch {
		case n >= 4 && late:
			r.Verdict = "Probable ransomware kill chain — isolate account now"
		case n >= 3:
			r.Verdict = "Multi-stage intrusion suspected — investigate"
		case r.Severity["Critical"] > 0 || r.Score >= 20:
			r.Verdict = "High-risk activity — review session"
		default:
			r.Verdict = "Policy deviation — follow up with vendor"
		}
		out = append(out, *r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out
}

func chainCoverage(alerts []Alert) []StageHit {
	hits := make([]StageHit, len(Chain))
	for i, st := range Chain {
		hits[i] = StageHit{Stage: st}
	}
	for _, a := range alerts {
		i := a.Stage - 1
		if i < 0 || i >= len(hits) {
			continue
		}
		h := &hits[i]
		if !h.Observed || a.Time.Before(h.FirstSeen) {
			h.FirstSeen = a.Time
		}
		h.Observed = true
		h.Alerts++
	}
	return hits
}

func headline(r Result) string {
	if len(r.Alerts) == 0 {
		return "No policy violations found in the vendor access log."
	}
	observed := 0
	for _, h := range r.Chain {
		if h.Observed {
			observed++
		}
	}
	top := r.AccountRisk[0]
	return fmt.Sprintf("%d alerts across %d of 7 attack-chain stages. Highest risk: %s (%s), score %d/100.",
		len(r.Alerts), observed, top.Account, top.Vendor, top.Score)
}

func outOfScope(v *Vendor, e Event) bool {
	sysOK := len(v.AllowedSystems) == 0 || contains(v.AllowedSystems, e.Target)
	zoneOK := len(v.AllowedZones) == 0 || contains(v.AllowedZones, e.Zone)
	return !sysOK || !zoneOK
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}

func humanBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.0f MB", float64(b)/(1<<20))
	default:
		return fmt.Sprintf("%d KB", b/1024)
	}
}
