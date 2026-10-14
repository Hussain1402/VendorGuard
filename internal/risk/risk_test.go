package risk

import "testing"

// The inherent ratings must match the risk-assessment table in the report.
func TestInherentRatingsMatchReport(t *testing.T) {
	want := map[string]string{
		"Vendor credential compromise": "Critical",
		"Excessive vendor privileges":  "Critical",
		"Remote-access abuse":          "Critical",
		"Vendor malware infection":     "High",
		"Data exfiltration":            "Critical",
		"Ransomware encryption":        "Critical",
		"Poor vendor monitoring":       "High",
		"Subcontractor compromise":     "High",
	}
	for _, th := range Threats {
		got := Rating(Score(th.Likelihood, th.Impact))
		if got != want[th.Name] {
			t.Errorf("%s: got %s, want %s", th.Name, got, want[th.Name])
		}
	}
}

func TestRatingThresholds(t *testing.T) {
	cases := map[int]string{1: "Low", 2: "Low", 3: "Medium", 4: "Medium", 6: "High", 8: "Critical", 16: "Critical"}
	for score, want := range cases {
		if got := Rating(score); got != want {
			t.Errorf("Rating(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestNoControlsMeansNoReduction(t *testing.T) {
	_, s := AssessAll(map[string]bool{})
	if s.InherentTotal != s.ResidualTotal {
		t.Fatalf("expected no reduction, got %d -> %d", s.InherentTotal, s.ResidualTotal)
	}
}

func TestMFAReducesCredentialCompromise(t *testing.T) {
	a := Assess(Threats[0], map[string]bool{"mfa": true})
	if a.ResidualLikelihood != Medium || a.ResidualScore != 8 {
		t.Fatalf("got likelihood %v score %d", a.ResidualLikelihood, a.ResidualScore)
	}
}

func TestLevelsNeverDropBelowLow(t *testing.T) {
	all := map[string]bool{}
	for _, c := range Controls {
		all[c.ID] = true
	}
	for _, a := range func() []Assessment { r, _ := AssessAll(all); return r }() {
		if a.ResidualLikelihood < Low || a.ResidualImpact < Low {
			t.Errorf("%s dropped below Low", a.Name)
		}
		if a.ResidualRating == "Critical" {
			t.Errorf("%s still Critical with every control enabled", a.Name)
		}
	}
}
