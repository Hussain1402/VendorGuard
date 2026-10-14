package main

import (
	"fmt"
	"io"
	"strings"

	"vendorguard/internal/analyzer"
	"vendorguard/internal/risk"
)

// printReport writes the text report used by -cli.
func printReport(w io.Writer, res analyzer.Result, enabled map[string]bool) {
	line := strings.Repeat("=", 78)
	fmt.Fprintln(w, line)
	fmt.Fprintln(w, " VENDORGUARD", version, "— Third-Party Vendor Access Risk Analyzer")
	fmt.Fprintln(w, " Case study: Third-Party Vendor Access as a Ransomware Vector (ICICI Bank, 2025–26)")
	fmt.Fprintln(w, line)

	// 1. Risk register
	threats, sum := risk.AssessAll(enabled)
	fmt.Fprintln(w, "\n[1] RISK REGISTER   (Risk = Likelihood x Impact, scale 1-4)")
	if len(enabled) > 0 {
		names := []string{}
		for _, c := range risk.Controls {
			if enabled[c.ID] {
				names = append(names, c.Name)
			}
		}
		fmt.Fprintf(w, "    Controls applied: %s\n", strings.Join(names, ", "))
	} else {
		fmt.Fprintln(w, "    Controls applied: none (inherent risk). Use -controls all to compare.")
	}
	fmt.Fprintf(w, "\n    %-30s %-10s %-10s %-15s %-15s\n", "Threat", "Likelih.", "Impact", "Inherent", "Residual")
	fmt.Fprintf(w, "    %s\n", strings.Repeat("-", 82))
	for _, t := range threats {
		fmt.Fprintf(w, "    %-30s %-10s %-10s %-15s %-15s\n", t.Name, t.LikelihoodLabel, t.ImpactLabel,
			fmt.Sprintf("%2d %s", t.InherentScore, t.InherentRating),
			fmt.Sprintf("%2d %s", t.ResidualScore, t.ResidualRating))
	}
	fmt.Fprintf(w, "\n    Total risk score: %d -> %d  (%d%% reduction)\n", sum.InherentTotal, sum.ResidualTotal, sum.ReductionPct)

	// 2. Log analysis
	fmt.Fprintln(w, "\n[2] VENDOR ACCESS LOG ANALYSIS")
	if res.Organisation != "" {
		fmt.Fprintf(w, "    Organisation: %s\n", res.Organisation)
	}
	fmt.Fprintf(w, "    Events: %d   Vendors: %d   Accounts: %d   Period: %s to %s\n",
		res.Events, res.Vendors, res.Accounts, res.From.Format("02 Jan 15:04"), res.To.Format("02 Jan 15:04"))
	fmt.Fprintf(w, "    Alerts: %d  (Critical %d, High %d, Medium %d)\n", len(res.Alerts),
		res.BySeverity["Critical"], res.BySeverity["High"], res.BySeverity["Medium"])
	fmt.Fprintf(w, "    %s\n", res.Headline)

	fmt.Fprintln(w, "\n    Time            Sev.      Stage  MITRE  Account        Alert")
	fmt.Fprintf(w, "    %s\n", strings.Repeat("-", 82))
	for _, a := range res.Alerts {
		fmt.Fprintf(w, "    %-15s %-9s %-6d %-6s %-14s %s\n", a.Time.Format("02 Jan 15:04"), a.Severity, a.Stage, a.Technique, a.Account, a.Title)
		fmt.Fprintf(w, "    %38s -> %s\n", "", a.Detail)
	}

	// 3. Attack chain
	fmt.Fprintln(w, "\n[3] ATTACK-CHAIN COVERAGE (MITRE ATT&CK)")
	for _, h := range res.Chain {
		mark := "[ ]"
		when := ""
		if h.Observed {
			mark = "[X]"
			when = "first seen " + h.FirstSeen.Format("02 Jan 15:04")
		}
		ids := []string{}
		for _, t := range h.Techniques {
			ids = append(ids, t.ID)
		}
		fmt.Fprintf(w, "    %s %d. %-22s %-12s %2d alert(s)  %s\n", mark, h.Number, h.Name, strings.Join(ids, ","), h.Alerts, when)
	}

	// 4. Accounts
	fmt.Fprintln(w, "\n[4] ACCOUNTS BY RISK")
	for _, a := range res.AccountRisk {
		fmt.Fprintf(w, "    %-14s %-24s score %3d/100  stages %v\n", a.Account, a.Vendor, a.Score, a.Stages)
		fmt.Fprintf(w, "    %14s -> %s\n", "", a.Verdict)
	}
	for _, wn := range res.Warnings {
		fmt.Fprintln(w, "    warning:", wn)
	}
	fmt.Fprintln(w, "\n"+line)
}
