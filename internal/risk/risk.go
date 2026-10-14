// Package risk implements the risk-assessment model used in the case study:
//
//	Risk = Likelihood × Impact
//
// Likelihood and impact are rated on a 4-point scale
// (1 = Low, 2 = Medium, 3 = High, 4 = Very High), so a risk score
// runs from 1 to 16. The thresholds below reproduce the risk levels
// given in the report's risk-assessment table.
//
// The package also models the effect of the proposed security controls
// (MFA, least privilege, PAM, just-in-time access, segmentation, monitoring,
// backups, vendor assessment). Each enabled control lowers either the
// likelihood or the impact of the threats it addresses by one level,
// giving a residual risk.
package risk

import "sort"

// Level is a rating on the 4-point scale.
type Level int

const (
	Low      Level = 1
	Medium   Level = 2
	High     Level = 3
	VeryHigh Level = 4
)

func (l Level) String() string {
	switch l {
	case Low:
		return "Low"
	case Medium:
		return "Medium"
	case High:
		return "High"
	case VeryHigh:
		return "Very High"
	}
	return "Unknown"
}

// Score returns Likelihood × Impact.
func Score(likelihood, impact Level) int { return int(likelihood) * int(impact) }

// Rating converts a score into a risk level.
//
//	8–16 Critical   (e.g. Medium × Very High = 8, High × High = 9)
//	5–7  High       (e.g. Medium × High = 6)
//	3–4  Medium
//	1–2  Low
func Rating(score int) string {
	switch {
	case score >= 8:
		return "Critical"
	case score >= 5:
		return "High"
	case score >= 3:
		return "Medium"
	default:
		return "Low"
	}
}

// Effect says which side of the risk equation a control reduces.
type Effect string

const (
	ReducesLikelihood Effect = "likelihood"
	ReducesImpact     Effect = "impact"
)

// Control is one of the proposed security controls (report section 7).
type Control struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Section     string `json:"section"` // where it appears in the report
}

// Mitigation links a control to a threat.
type Mitigation struct {
	ControlID string `json:"control"`
	Effect    Effect `json:"effect"`
}

// Threat is one row of the risk register.
type Threat struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Likelihood  Level        `json:"likelihood"`
	Impact      Level        `json:"impact"`
	Techniques  []string     `json:"techniques"` // MITRE ATT&CK IDs
	Mitigations []Mitigation `json:"mitigations"`
}

// Controls lists the controls in the order the report proposes them.
var Controls = []Control{
	{"mfa", "Multi-factor authentication", "Every third-party account needs a second factor, so a stolen password alone cannot open banking systems.", "7.1"},
	{"least_privilege", "Least-privilege access", "Vendors reach only the specific application they support, not the database, file server or internal network.", "7.2"},
	{"pam", "Privileged access management", "Credential vaulting, password rotation, session monitoring and approval workflows for privileged vendor accounts.", "7.3"},
	{"jit", "Just-in-time access", "Access is temporary: request, approval, MFA, time-boxed session, then automatic revocation.", "7.4"},
	{"segmentation", "Network segmentation", "Vendor → DMZ → vendor access zone → application zone → restricted database zone.", "7.5"},
	{"monitoring", "Continuous monitoring", "SIEM, EDR, firewall, VPN, IAM, PAM and database-activity logs with alerts on anomalies.", "7.6"},
	{"backups", "Secure backups", "Offline, immutable, encrypted backups with regular restoration tests.", "7.7"},
	{"vendor_assessment", "Vendor and fourth-party assessment", "Periodic security assessments of vendors and their subcontractors, with security clauses in contracts.", "Recs 7–9"},
}

// Threats is the risk register from the report's risk-assessment table.
var Threats = []Threat{
	{
		ID: "TH1", Name: "Vendor credential compromise", Likelihood: High, Impact: VeryHigh,
		Techniques: []string{"T1199", "T1078"},
		Mitigations: []Mitigation{
			{"mfa", ReducesLikelihood}, {"pam", ReducesLikelihood},
			{"jit", ReducesLikelihood}, {"least_privilege", ReducesImpact},
		},
	},
	{
		ID: "TH2", Name: "Excessive vendor privileges", Likelihood: Medium, Impact: VeryHigh,
		Techniques: []string{"T1078"},
		Mitigations: []Mitigation{
			{"least_privilege", ReducesLikelihood}, {"pam", ReducesLikelihood},
			{"jit", ReducesLikelihood}, {"segmentation", ReducesImpact},
		},
	},
	{
		ID: "TH3", Name: "Remote-access abuse", Likelihood: High, Impact: High,
		Techniques: []string{"T1021", "T1078"},
		Mitigations: []Mitigation{
			{"mfa", ReducesLikelihood}, {"jit", ReducesLikelihood},
			{"monitoring", ReducesImpact}, {"segmentation", ReducesImpact},
		},
	},
	{
		ID: "TH4", Name: "Vendor malware infection", Likelihood: Medium, Impact: High,
		Techniques: []string{"T1199"},
		Mitigations: []Mitigation{
			{"vendor_assessment", ReducesLikelihood}, {"monitoring", ReducesImpact},
			{"segmentation", ReducesImpact},
		},
	},
	{
		ID: "TH5", Name: "Data exfiltration", Likelihood: Medium, Impact: VeryHigh,
		Techniques: []string{"T1005", "T1567"},
		Mitigations: []Mitigation{
			{"least_privilege", ReducesLikelihood}, {"segmentation", ReducesLikelihood},
			{"monitoring", ReducesImpact},
		},
	},
	{
		ID: "TH6", Name: "Ransomware encryption", Likelihood: Medium, Impact: VeryHigh,
		Techniques: []string{"T1486"},
		Mitigations: []Mitigation{
			{"segmentation", ReducesLikelihood}, {"monitoring", ReducesLikelihood},
			{"backups", ReducesImpact},
		},
	},
	{
		ID: "TH7", Name: "Poor vendor monitoring", Likelihood: Medium, Impact: High,
		Techniques: []string{"T1078", "T1021"},
		Mitigations: []Mitigation{
			{"monitoring", ReducesLikelihood}, {"vendor_assessment", ReducesLikelihood},
		},
	},
	{
		ID: "TH8", Name: "Subcontractor compromise", Likelihood: Medium, Impact: High,
		Techniques: []string{"T1199"},
		Mitigations: []Mitigation{
			{"vendor_assessment", ReducesLikelihood}, {"segmentation", ReducesImpact},
			{"least_privilege", ReducesImpact},
		},
	},
}

// Assessment is a threat with its inherent and residual risk.
type Assessment struct {
	Threat
	LikelihoodLabel     string   `json:"likelihoodLabel"`
	ImpactLabel         string   `json:"impactLabel"`
	InherentScore       int      `json:"inherentScore"`
	InherentRating      string   `json:"inherentRating"`
	ResidualLikelihood  Level    `json:"residualLikelihood"`
	ResidualImpact      Level    `json:"residualImpact"`
	ResidualScore       int      `json:"residualScore"`
	ResidualRating      string   `json:"residualRating"`
	AppliedControls     []string `json:"appliedControls"`
	MissingControls     []string `json:"missingControls"`
	ReductionPercentage int      `json:"reductionPct"`
}

func clamp(l Level) Level {
	if l < Low {
		return Low
	}
	return l
}

// Assess scores one threat with the given set of enabled controls.
func Assess(t Threat, enabled map[string]bool) Assessment {
	a := Assessment{
		Threat:          t,
		LikelihoodLabel: t.Likelihood.String(),
		ImpactLabel:     t.Impact.String(),
		InherentScore:   Score(t.Likelihood, t.Impact),
		AppliedControls: []string{},
		MissingControls: []string{},
	}
	a.InherentRating = Rating(a.InherentScore)

	l, i := t.Likelihood, t.Impact
	for _, m := range t.Mitigations {
		if !enabled[m.ControlID] {
			a.MissingControls = append(a.MissingControls, m.ControlID)
			continue
		}
		a.AppliedControls = append(a.AppliedControls, m.ControlID)
		if m.Effect == ReducesLikelihood {
			l--
		} else {
			i--
		}
	}
	a.ResidualLikelihood, a.ResidualImpact = clamp(l), clamp(i)
	a.ResidualScore = Score(a.ResidualLikelihood, a.ResidualImpact)
	a.ResidualRating = Rating(a.ResidualScore)
	a.ReductionPercentage = 100 * (a.InherentScore - a.ResidualScore) / a.InherentScore
	return a
}

// Summary totals the register.
type Summary struct {
	InherentTotal int            `json:"inherentTotal"`
	ResidualTotal int            `json:"residualTotal"`
	ReductionPct  int            `json:"reductionPct"`
	InherentCount map[string]int `json:"inherentCount"`
	ResidualCount map[string]int `json:"residualCount"`
}

// AssessAll scores the full register, highest residual risk first.
func AssessAll(enabled map[string]bool) ([]Assessment, Summary) {
	out := make([]Assessment, 0, len(Threats))
	s := Summary{InherentCount: map[string]int{}, ResidualCount: map[string]int{}}
	for _, t := range Threats {
		a := Assess(t, enabled)
		out = append(out, a)
		s.InherentTotal += a.InherentScore
		s.ResidualTotal += a.ResidualScore
		s.InherentCount[a.InherentRating]++
		s.ResidualCount[a.ResidualRating]++
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ResidualScore > out[j].ResidualScore })
	if s.InherentTotal > 0 {
		s.ReductionPct = 100 * (s.InherentTotal - s.ResidualTotal) / s.InherentTotal
	}
	return out, s
}
