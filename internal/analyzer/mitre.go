package analyzer

// Stage is one step of the conceptual third-party ransomware attack chain
// (report section 5) with its MITRE ATT&CK techniques (report section 6).
type Stage struct {
	Number      int         `json:"number"`
	Name        string      `json:"name"`
	Techniques  []Technique `json:"techniques"`
	Description string      `json:"description"`
	Prevent     []string    `json:"prevent"` // control IDs that break this stage
	Detect      []string    `json:"detect"`  // analyzer rule IDs that detect it
}

// Technique is a MITRE ATT&CK technique.
type Technique struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Chain is the seven-stage attack path, in order.
var Chain = []Stage{
	{1, "Trusted relationship", []Technique{{"T1199", "Trusted Relationship"}},
		"The attacker enters through a vendor's legitimate connection to the bank.",
		[]string{"vendor_assessment", "segmentation"}, []string{"UNKNOWN_VENDOR", "UNKNOWN_LOCATION"}},
	{2, "Valid accounts", []Technique{{"T1078", "Valid Accounts"}, {"T1110", "Brute Force"}},
		"Stolen or guessed vendor credentials are used to log in and gain privileges.",
		[]string{"mfa", "pam", "jit"}, []string{"BRUTE_FORCE", "NO_MFA", "OFF_HOURS", "EXPIRED_ACCESS", "UNKNOWN_ACCOUNT", "PRIV_ESCALATION"}},
	{3, "Discovery", []Technique{{"T1087", "Account Discovery"}, {"T1046", "Network Service Discovery"}},
		"The attacker maps accounts and reachable systems inside the network.",
		[]string{"segmentation", "monitoring"}, []string{"DISCOVERY_ACCOUNTS", "DISCOVERY_NETWORK"}},
	{4, "Lateral movement", []Technique{{"T1021", "Remote Services"}},
		"The attacker moves from the vendor's system to other bank systems.",
		[]string{"least_privilege", "segmentation", "pam"}, []string{"LATERAL_MOVEMENT"}},
	{5, "Data collection", []Technique{{"T1005", "Data from Local System"}},
		"Sensitive customer and banking data is gathered from systems outside the vendor's scope.",
		[]string{"least_privilege", "segmentation"}, []string{"SCOPE_VIOLATION"}},
	{6, "Exfiltration", []Technique{{"T1567", "Exfiltration Over Web Service"}},
		"Collected data is sent out of the bank, enabling double extortion.",
		[]string{"monitoring", "segmentation"}, []string{"LARGE_TRANSFER"}},
	{7, "Ransomware impact", []Technique{{"T1486", "Data Encrypted for Impact"}},
		"Files and systems are encrypted to force a ransom payment.",
		[]string{"backups", "monitoring", "segmentation"}, []string{"MASS_ENCRYPTION"}},
}
