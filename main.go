// VendorGuard — Third-Party Vendor Access Risk Analyzer
//
// Companion tool for the case study "Third-Party Vendor Access as a
// Ransomware Vector: The ICICI Bank Case (2025–26)", Cyber Security,
// Group 4, E&TC, Symbiosis Institute of Technology, Pune.
//
// Run with no arguments to start the local web dashboard, or with -cli to
// print the analysis in the terminal. See README.md for all options.
package main

import (
	"bytes"
	"embed"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"time"

	"vendorguard/internal/analyzer"
	"vendorguard/internal/risk"
)

const version = "1.0.0"

//go:embed web
var webFS embed.FS

//go:embed data/vendors.json
var sampleVendors []byte

//go:embed data/sample_access_log.csv
var sampleLogs []byte

func main() {
	port := flag.Int("port", 8080, "port for the local dashboard (falls back to a free port if busy)")
	logsPath := flag.String("logs", "", "vendor access log CSV to analyse (default: built-in sample)")
	vendorsPath := flag.String("vendors", "", "vendor policy JSON (default: built-in sample)")
	cli := flag.Bool("cli", false, "print the report in the terminal instead of opening the dashboard")
	controls := flag.String("controls", "", "with -cli: comma-separated controls to apply, or \"all\" (e.g. mfa,pam,jit)")
	noBrowser := flag.Bool("no-browser", false, "do not open the browser automatically")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Usage = usage
	flag.Parse()

	if *showVersion {
		fmt.Println("VendorGuard", version)
		return
	}

	logsData, vendorsData, err := loadInputs(*logsPath, *vendorsPath)
	if err != nil {
		fatal(err)
	}
	result, err := analyse(logsData, vendorsData)
	if err != nil {
		fatal(err)
	}

	if *cli {
		printReport(os.Stdout, result, parseControls(*controls))
		return
	}
	serve(*port, !*noBrowser, result)
}

func usage() {
	fmt.Fprintf(os.Stderr, `VendorGuard %s — Third-Party Vendor Access Risk Analyzer

Usage:
  VendorGuard                         start the dashboard and open the browser
  VendorGuard -cli                    print the analysis in this window
  VendorGuard -cli -controls all      also show residual risk with every control applied
  VendorGuard -logs my.csv -vendors my.json   analyse your own files

Options:
`, version)
	flag.PrintDefaults()
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
	if runtime.GOOS == "windows" && len(os.Args) == 1 {
		// Started by double-click: keep the window open so the error can be read.
		fmt.Fprintln(os.Stderr, "\nPress Enter to close.")
		fmt.Scanln()
	}
	os.Exit(1)
}

func loadInputs(logsPath, vendorsPath string) ([]byte, []byte, error) {
	logs, vendors := sampleLogs, sampleVendors
	var err error
	if logsPath != "" {
		if logs, err = os.ReadFile(logsPath); err != nil {
			return nil, nil, fmt.Errorf("reading log file: %w", err)
		}
	}
	if vendorsPath != "" {
		if vendors, err = os.ReadFile(vendorsPath); err != nil {
			return nil, nil, fmt.Errorf("reading vendor policy: %w", err)
		}
	}
	return logs, vendors, nil
}

func analyse(logs, vendors []byte) (analyzer.Result, error) {
	policy, err := analyzer.LoadPolicy(bytes.NewReader(vendors))
	if err != nil {
		return analyzer.Result{}, err
	}
	events, warnings, err := analyzer.LoadEvents(bytes.NewReader(logs))
	if err != nil {
		return analyzer.Result{}, err
	}
	res := analyzer.Analyze(policy, events)
	res.Warnings = append(res.Warnings, warnings...)
	return res, nil
}

func parseControls(s string) map[string]bool {
	set := map[string]bool{}
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "all" {
		for _, c := range risk.Controls {
			set[c.ID] = true
		}
		return set
	}
	for _, id := range strings.Split(s, ",") {
		if id = strings.TrimSpace(id); id != "" {
			set[id] = true
		}
	}
	return set
}

// ---------- Web dashboard ----------

func serve(port int, openBrowser bool, initial analyzer.Result) {
	static, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(static)))
	registerAPI(mux, initial)

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			fatal(fmt.Errorf("cannot start web server: %w", err))
		}
	}
	url := "http://" + ln.Addr().String()

	fmt.Println("==============================================================")
	fmt.Println(" VendorGuard", version, "— Third-Party Vendor Access Risk Analyzer")
	fmt.Println(" Cyber Security Case Study · Group 4 · SIT Pune")
	fmt.Println("==============================================================")
	fmt.Println(" Dashboard running at:", url)
	fmt.Println(" (only reachable from this computer)")
	fmt.Println()
	fmt.Println(" Keep this window open while you use the dashboard.")
	fmt.Println(" Close it, or press Ctrl+C, to stop VendorGuard.")
	fmt.Println("==============================================================")

	if openBrowser {
		go func() {
			time.Sleep(400 * time.Millisecond)
			if err := openURL(url); err != nil {
				fmt.Println(" Could not open the browser automatically. Open", url, "yourself.")
			}
		}()
	}

	srv := &http.Server{Handler: logRequests(mux), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt)
		<-stop
		fmt.Println("\n Stopping VendorGuard.")
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			fmt.Printf(" %s  %s %s\n", time.Now().Format("15:04:05"), r.Method, r.URL.Path)
		}
		h.ServeHTTP(w, r)
	})
}

func openURL(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Start()
}

// readLimited reads at most n bytes from r.
func readLimited(r io.Reader, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, n+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > n {
		return nil, fmt.Errorf("upload larger than %d MB", n>>20)
	}
	return b, nil
}
