package analyzer

import (
	"os"
	"strings"
	"testing"
)

func loadSample(t *testing.T) Result {
	t.Helper()
	pf, err := os.Open("../../data/vendors.json")
	if err != nil {
		t.Fatal(err)
	}
	defer pf.Close()
	p, err := LoadPolicy(pf)
	if err != nil {
		t.Fatal(err)
	}
	lf, err := os.Open("../../data/sample_access_log.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer lf.Close()
	ev, warn, err := LoadEvents(lf)
	if err != nil {
		t.Fatal(err)
	}
	if len(warn) > 0 {
		t.Fatalf("unexpected warnings: %v", warn)
	}
	return Analyze(p, ev)
}

func TestSampleDetectsFullChain(t *testing.T) {
	r := loadSample(t)
	for _, h := range r.Chain {
		if !h.Observed {
			t.Errorf("stage %d (%s) not observed", h.Number, h.Name)
		}
	}
	top := r.AccountRisk[0]
	if top.Account != "nw.support2" {
		t.Fatalf("top account = %s, want nw.support2", top.Account)
	}
	if !strings.HasPrefix(top.Verdict, "Probable ransomware") {
		t.Errorf("verdict = %q", top.Verdict)
	}
}

func TestSampleRules(t *testing.T) {
	r := loadSample(t)
	want := []string{"BRUTE_FORCE", "NO_MFA", "UNKNOWN_LOCATION", "OFF_HOURS", "PRIV_ESCALATION",
		"DISCOVERY_ACCOUNTS", "DISCOVERY_NETWORK", "LATERAL_MOVEMENT", "SCOPE_VIOLATION",
		"LARGE_TRANSFER", "MASS_ENCRYPTION", "EXPIRED_ACCESS"}
	for _, rule := range want {
		if r.ByRule[rule] == 0 {
			t.Errorf("rule %s never fired", rule)
		}
	}
}

func TestNormalVendorsStayClean(t *testing.T) {
	r := loadSample(t)
	for _, a := range r.Alerts {
		switch a.Account {
		case "nw.support1", "kc.recon1", "kc.recon2":
			t.Errorf("false positive on %s: %s (%s)", a.Account, a.Rule, a.Detail)
		}
	}
}

func TestMissingColumnIsReported(t *testing.T) {
	_, _, err := LoadEvents(strings.NewReader("timestamp,account\n2026-10-01 10:00:00,x\n"))
	if err == nil || !strings.Contains(err.Error(), "missing column") {
		t.Fatalf("expected missing-column error, got %v", err)
	}
}
