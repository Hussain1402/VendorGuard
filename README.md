# VendorGuard: Third-Party Vendor Access Risk Analyzer

**GitHub repository:** https://github.com/Hussain1402/VendorGuard

VendorGuard is the implementation part of our Cyber Security case study, **"Third-Party Vendor Access as a Ransomware Vector: The ICICI Bank Case (2025–26)"**. It turns the report's methodology into a working tool. It:

1. **Scores the risk register** using *Risk = Likelihood × Impact* and shows how the proposed controls (MFA, least privilege, PAM, just-in-time access, segmentation, monitoring, backups, vendor assessment) lower each risk.
2. **Analyses vendor access logs.** Every event is checked against the vendor's access policy, and VendorGuard flags the behaviour the report says must be monitored: logins from unknown locations, unusual hours, privilege upgrades, large downloads, missing MFA, expired access, discovery, lateral movement and mass file encryption.
3. **Maps every alert to MITRE ATT&CK** and to the seven-stage third-party ransomware attack chain. This shows whether a single vendor account is moving through the whole chain.

| | |
|---|---|
| Subject | Cyber Security, Semester VII, Batch 2023–27 |
| Department | Electronics and Telecommunication Engineering, Symbiosis Institute of Technology, Pune |
| Faculty | Dr. Mangal Singh |
| Group | 4 |
| Members | Divyansh Rastogi (23070123048), Gaurish Malhotra (23070123054), Hussain Tayyebi (23070123061), Soham Jade (23070123065) |

---

## 1. Quick start (Windows, no installation needed)

1. Extract the zip file anywhere, for example to your Desktop.
2. Open the `bin` folder and **double-click `VendorGuard.exe`**.
   - If Windows shows *"Windows protected your PC"*, click **More info → Run anyway**. The program is unsigned, which is normal for a student project.
3. A console window opens and your browser opens the dashboard at **http://127.0.0.1:8080**.
   - If the browser does not open, copy the address shown in the console window into your browser.
4. **Keep the console window open** while you use the dashboard. To stop VendorGuard, close the window or press `Ctrl + C`.

The program is a single file with the dashboard and sample data built in. It needs no internet connection and no other software, and it accepts connections only from your own computer.

### What you will see

| Tab | What it shows |
|---|---|
| **Overview** | Headline verdict, alert counts, the attack-chain stages found in the log, and the accounts ranked by risk |
| **Log analysis** | Every alert with time, severity, MITRE technique, account, explanation and the controls that would stop it. Filter by severity, account or stage, and export to CSV |
| **Attack chain** | The seven stages (Trusted Relationship → Valid Accounts → Discovery → Lateral Movement → Data Collection → Exfiltration → Ransomware Impact), with techniques, preventive controls and detection rules |
| **Risk register** | The 8 threats from the report. Tick controls on the left to see the residual risk and the percentage reduction |
| **About** | How the tool maps to the report, the list of detection rules, and the input file format |

### The built-in demo scenario

The sample log (`data/sample_access_log.csv`, 74 events over 11–13 Oct 2026) covers four fictional vendors of a fictional bank:

- Three of the six vendor accounts (`nw.support1`, `kc.recon1`, `kc.recon2`) behave normally and raise **no alerts**.
- **Northwind IT Services** account `nw.support2` is taken over. Starting at 01:58 on 13 Oct, the attacker fails several logins from the Netherlands, then logs in without MFA. Next they enumerate accounts, scan the network and raise themselves to `domain_admin`. They then open sessions to the file server and the restricted customer database, read data, send 2.4 GB to an external file-sharing site, and finally rewrite more than 18,000 files.
  VendorGuard detects **all 7 stages** and marks the account **"Probable ransomware kill chain — isolate account now"**.
- **Meridian Payroll Tech**, whose contract ended on 30 Sep, still logs in on 13 Oct. This is caught as *expired access* (report recommendation 14: remove inactive vendor accounts).
- **BlueOrbit Digital** logs in at 20:41, outside its approved hours. This is a minor deviation.

---

## 2. Command-line options

Run these from Command Prompt or PowerShell inside the `bin` folder:

```
VendorGuard.exe                                   start the dashboard (same as double-click)
VendorGuard.exe -cli                              print the full report in the console
VendorGuard.exe -cli -controls all                ...and show residual risk with every control applied
VendorGuard.exe -cli -controls mfa,pam,jit        ...with only the controls you list
VendorGuard.exe -logs mylog.csv -vendors my.json  analyse your own files
VendorGuard.exe -port 9000                        use a different port
VendorGuard.exe -no-browser                       do not open the browser automatically
VendorGuard.exe -help                             list all options
```

Control IDs for `-controls`: `mfa`, `least_privilege`, `pam`, `jit`, `segmentation`, `monitoring`, `backups`, `vendor_assessment`, or `all`.

---

## 3. Using your own data

In the dashboard, click **Load log file…** and choose a CSV. You can also choose a vendor policy JSON; without one, the sample policy is used. Files are analysed on your computer and are not uploaded anywhere.

**Access log CSV columns** (header row required):

```
timestamp,vendor_id,account,src_ip,country,action,target,zone,mfa,role,bytes_out,files_modified,result
2026-10-13 02:04:22,V01,nw.support2,185.220.101.47,NL,login,vpn-gw-01,vendor-zone,false,operator,0,0,success
```

| Column | Meaning |
|---|---|
| `timestamp` | `YYYY-MM-DD HH:MM:SS` (taken as IST) or RFC 3339 |
| `action` | `login`, `logout`, `privilege_change`, `account_enum`, `port_scan`, `remote_session`, `file_access`, `data_transfer`, `file_modify` |
| `zone` | Network zone, e.g. `dmz`, `vendor-zone`, `app-zone`, `core-zone`, `restricted-db-zone`, `external` |
| `mfa` | `true` / `false` |
| `role` | `viewer`, `operator`, `admin`, `domain_admin` |
| `result` | `success` / `failure` |

**Vendor policy JSON** (`data/vendors.json`): for each vendor, it lists the accounts, allowed systems and zones, allowed countries, working hours, maximum role, the just-in-time access window, and whether the vendor is active. It also holds the detection thresholds (large transfer in MB, failed-login count and window, mass file-change count).

---

## 4. Building from source

The source is written in **Go** and uses only the standard library, so there are no third-party dependencies.

1. Install Go 1.22 or newer from https://go.dev/dl/
2. Open a terminal in this folder and run:

```
go test ./...          run the unit tests
go run .               run without building an exe
build.bat              (Windows) test and build bin\VendorGuard.exe
./build.sh             (Linux/macOS) build for Windows, Linux and macOS
```

---

## 5. How it works (link to the report's methodology)

| Report section | Implementation |
|---|---|
| Step 4: Threat modelling; Sections 5–6: attack path and MITRE mapping | `internal/analyzer/mitre.go` defines the 7-stage chain with techniques T1199, T1078, T1110, T1087, T1046, T1021, T1005, T1567 and T1486 |
| Step 5: Risk assessment (Risk = Likelihood × Impact) | `internal/risk/risk.go` uses a 1–4 scale. Score 8–16 is Critical, 5–7 High, 3–4 Medium, 1–2 Low. The inherent ratings reproduce the report's risk table exactly (checked by unit test) |
| Step 6: Security-control analysis; Section 7: proposed controls | Each control lowers the likelihood or impact of the threats it addresses by one level, which gives the residual risk |
| Section 7.6: Continuous monitoring | `internal/analyzer/analyzer.go` runs 14 detection rules over the access log |
| Recommendations | Every alert names the controls that would have prevented or contained it |

### Detection rules

| Rule | Stage | MITRE | Fires when |
|---|---|---|---|
| UNKNOWN_VENDOR | 1 | T1199 | Event from a vendor not in the register |
| UNKNOWN_LOCATION | 1 | T1199 | Login from a country outside the vendor's allowed list |
| BRUTE_FORCE | 2 | T1110 | 3 or more failed logins within 10 minutes |
| NO_MFA | 2 | T1078 | Successful login without MFA |
| OFF_HOURS | 2 | T1078 | Login outside the vendor's approved hours |
| EXPIRED_ACCESS | 2 | T1078 | Login after the just-in-time window ended, or by an inactive vendor |
| UNKNOWN_ACCOUNT | 2 | T1078 | Login with an account not issued to that vendor |
| PRIV_ESCALATION | 2 | T1078 | Role raised above the vendor's maximum |
| DISCOVERY_ACCOUNTS | 3 | T1087 | Account or directory enumeration |
| DISCOVERY_NETWORK | 3 | T1046 | Network or service scan |
| LATERAL_MOVEMENT | 4 | T1021 | Remote session to a system or zone outside the vendor's scope |
| SCOPE_VIOLATION | 5 | T1005 | Data read outside the vendor's scope (Critical in the restricted DB zone) |
| LARGE_TRANSFER | 6 | T1567 | Outbound transfer of 500 MB or more |
| MASS_ENCRYPTION | 7 | T1486 | 200 or more files rewritten in one burst |

**Account verdict.** Each alert adds to the account's score (Medium 5, High 10, Critical 20, capped at 100). An account with alerts in 4 or more stages, including exfiltration or encryption, is marked *Probable ransomware kill chain*. One with alerts in 3 or more stages is marked *Multi-stage intrusion suspected*.

---

## 6. Project structure

```
VendorGuard/
├── README.md                     this file
├── bin/
│   └── VendorGuard.exe           ready-to-run Windows executable (64-bit)
├── main.go                       entry point: command-line options, web server, browser launch
├── api.go                        JSON API used by the dashboard
├── report.go                     text report for -cli mode
├── console_windows.go            UTF-8 output for the Windows console
├── internal/
│   ├── risk/
│   │   ├── risk.go               risk register, controls, Likelihood × Impact model
│   │   └── risk_test.go          unit tests (ratings match the report)
│   └── analyzer/
│       ├── analyzer.go           log parser, policy checks, 14 detection rules, account scoring
│       ├── mitre.go              7-stage attack chain and MITRE ATT&CK techniques
│       └── analyzer_test.go      unit tests (full chain detected, no false positives)
├── web/
│   ├── index.html                dashboard page
│   ├── style.css                 dashboard styles (light and dark mode)
│   └── app.js                    dashboard logic
├── data/
│   ├── sample_access_log.csv     synthetic vendor access log (74 events)
│   └── vendors.json              synthetic vendor access policies
├── build.bat                     build script for Windows
├── build.sh                      build script for Linux/macOS
└── go.mod                        Go module definition
```

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| "Windows protected your PC" | Click **More info → Run anyway** |
| Antivirus quarantines the exe | Allow it, or build it yourself from source (section 4) |
| Browser does not open | Copy the address printed in the console window (e.g. `http://127.0.0.1:8080`) into your browser |
| Port 8080 already in use | VendorGuard picks a free port automatically and prints it. You can also use `-port 9000` |
| Dashboard says "Could not reach VendorGuard" | The console window was closed. Start `VendorGuard.exe` again |

---

## 8. Disclaimer

All data in this project is **synthetic**. The bank, vendors, accounts and IP addresses are fictional, and the logs do not describe ICICI Bank's systems. As the case study explains, the January 2025 ransomware claim by the Bashe group was not substantiated, and ICICI Bank reported no material cybersecurity incident. The tool demonstrates how third-party access *could* become a ransomware vector and how the proposed controls detect and limit it. It is an academic project and is not intended for production use.
