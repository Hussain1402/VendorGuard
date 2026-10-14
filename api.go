package main

import (
	"encoding/json"
	"net/http"
	"strings"

	"vendorguard/internal/analyzer"
	"vendorguard/internal/risk"
)

// registerAPI adds the JSON endpoints used by the dashboard.
//
//	GET  /api/meta            controls, attack chain, version
//	GET  /api/risk?controls=  risk register with the given controls applied
//	GET  /api/analysis        analysis of the log loaded at start-up
//	POST /api/analyze         analyse an uploaded log  {"logs": "<csv>", "vendors": "<json, optional>"}
//	GET  /api/sample/logs     download the sample access log
//	GET  /api/sample/vendors  download the sample vendor policy
func registerAPI(mux *http.ServeMux, initial analyzer.Result) {
	mux.HandleFunc("/api/meta", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"version":  version,
			"controls": risk.Controls,
			"chain":    analyzer.Chain,
		})
	})

	mux.HandleFunc("/api/risk", func(w http.ResponseWriter, r *http.Request) {
		enabled := parseControls(r.URL.Query().Get("controls"))
		threats, summary := risk.AssessAll(enabled)
		writeJSON(w, http.StatusOK, map[string]any{"threats": threats, "summary": summary})
	})

	mux.HandleFunc("/api/analysis", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, initial)
	})

	mux.HandleFunc("/api/analyze", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "use POST"})
			return
		}
		body, err := readLimited(r.Body, 20<<20)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		var req struct {
			Logs    string `json:"logs"`
			Vendors string `json:"vendors"`
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request: " + err.Error()})
			return
		}
		vendors := sampleVendors
		if strings.TrimSpace(req.Vendors) != "" {
			vendors = []byte(req.Vendors)
		}
		res, err := analyse([]byte(req.Logs), vendors)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, res)
	})

	mux.HandleFunc("/api/sample/logs", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", `attachment; filename="sample_access_log.csv"`)
		w.Write(sampleLogs)
	})
	mux.HandleFunc("/api/sample/vendors", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", `attachment; filename="vendors.json"`)
		w.Write(sampleVendors)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
