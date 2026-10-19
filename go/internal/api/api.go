// Package api implements the analyst-facing REST API: browsing/filtering
// alerts, the open/investigating/resolved/false_positive triage workflow,
// notes, incident report export, the asset inventory, and a raw-event
// search across OpenSearch by IP.
package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/tsebro/network-intrusion-detection-platform/internal/report"
	osstore "github.com/tsebro/network-intrusion-detection-platform/internal/store/opensearch"
	"github.com/tsebro/network-intrusion-detection-platform/internal/store/postgres"
)

type Server struct {
	pg *postgres.Store
	os *osstore.Client
}

func NewServer(pg *postgres.Store, os *osstore.Client) *Server {
	return &Server{pg: pg, os: os}
}

func (s *Server) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api/alerts", s.handleListAlerts)
	mux.HandleFunc("GET /api/alerts/{id}", s.handleGetAlert)
	mux.HandleFunc("PATCH /api/alerts/{id}", s.handleUpdateAlertStatus)
	mux.HandleFunc("GET /api/alerts/{id}/notes", s.handleListNotes)
	mux.HandleFunc("POST /api/alerts/{id}/notes", s.handleAddNote)
	mux.HandleFunc("GET /api/alerts/{id}/report", s.handleExportReport)
	mux.HandleFunc("GET /api/assets", s.handleListAssets)
	mux.HandleFunc("GET /api/events/search", s.handleSearchEvents)
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := postgres.ListAlertsParams{
		Status:    q.Get("status"),
		Severity:  q.Get("severity"),
		AlertType: q.Get("alert_type"),
		Limit:     atoiDefault(q.Get("limit"), 100),
		Offset:    atoiDefault(q.Get("offset"), 0),
	}
	alerts, err := s.pg.ListAlerts(r.Context(), params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, alerts)
}

func (s *Server) handleGetAlert(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	alert, err := s.pg.GetAlert(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

type updateStatusRequest struct {
	Status string `json:"status"`
}

var validStatuses = map[string]bool{
	"open": true, "investigating": true, "resolved": true, "false_positive": true,
}

func (s *Server) handleUpdateAlertStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req updateStatusRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return
	}
	if !validStatuses[req.Status] {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "status must be one of: open, investigating, resolved, false_positive",
		})
		return
	}
	if err := s.pg.UpdateAlertStatus(r.Context(), id, req.Status); errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	} else if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	alert, err := s.pg.GetAlert(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, alert)
}

func (s *Server) handleListNotes(w http.ResponseWriter, r *http.Request) {
	notes, err := s.pg.ListNotes(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, notes)
}

type addNoteRequest struct {
	Author string `json:"author"`
	Note   string `json:"note"`
}

func (s *Server) handleAddNote(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req addNoteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Note) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "note text is required"})
		return
	}
	author := req.Author
	if author == "" {
		author = "analyst"
	}
	note, err := s.pg.AddNote(r.Context(), id, author, req.Note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusCreated, note)
}

func (s *Server) handleExportReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	alert, err := s.pg.GetAlert(r.Context(), id)
	if errors.Is(err, pgx.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "alert not found"})
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	notes, err := s.pg.ListNotes(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	md := report.GenerateMarkdown(*alert, notes)
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(md))
}

func (s *Server) handleListAssets(w http.ResponseWriter, r *http.Request) {
	assets, err := s.pg.ListAssets(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, assets)
}

func (s *Server) handleSearchEvents(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "?ip= query parameter is required"})
		return
	}
	limit := atoiDefault(r.URL.Query().Get("limit"), 50)
	events, err := s.os.SearchEventsByIP(r.Context(), ip, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}
