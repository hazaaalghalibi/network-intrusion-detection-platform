// Package postgres stores alert workflow state and asset metadata — the
// project's "Store analyst notes, alert status, and asset data in
// PostgreSQL" requirement. OpenSearch holds the searchable event/alert
// documents; Postgres is the system of record for the analyst triage
// workflow.
package postgres

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/tsebro/network-intrusion-detection-platform/internal/models"
)

type Store struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return &Store{pool: pool}, nil
}

func (s *Store) Close() { s.pool.Close() }

// UpsertAlert inserts a new alert. If one with the same ID already exists
// (the worker re-reads a delivery, or the same detector fires again for the
// same underlying alert), the insert is a no-op so in-progress analyst
// triage (status, notes) is never clobbered.
func (s *Store) UpsertAlert(ctx context.Context, a models.Alert) error {
	threatIntel, err := json.Marshal(nonNilSlice(a.ThreatIntel))
	if err != nil {
		return fmt.Errorf("marshal threat_intel: %w", err)
	}
	sourceRefs, err := json.Marshal(nonNilSlice(a.SourceRefs))
	if err != nil {
		return fmt.Errorf("marshal source_refs: %w", err)
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO alerts (id, created_at, alert_type, severity, title, description,
			src_ip, dst_ip, dst_port, asset_hostname, event_count, threat_intel, source_refs, status, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$2)
		ON CONFLICT (id) DO NOTHING`,
		a.ID, a.CreatedAt, string(a.AlertType), string(a.Severity), a.Title, a.Description,
		nullIfEmpty(a.SrcIP), nullIfEmpty(a.DstIP), nullIfZero(a.DstPort), nullIfEmpty(a.AssetHostname),
		a.EventCount, threatIntel, sourceRefs, string(a.Status))
	if err != nil {
		return fmt.Errorf("upsert alert %s: %w", a.ID, err)
	}
	return nil
}

type ListAlertsParams struct {
	Status    string
	Severity  string
	AlertType string
	Limit     int
	Offset    int
}

func (s *Store) ListAlerts(ctx context.Context, p ListAlertsParams) ([]models.Alert, error) {
	limit := p.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	query := `SELECT id, created_at, alert_type, severity, title, description,
			COALESCE(src_ip,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(asset_hostname,''),
			event_count, threat_intel, source_refs, status, updated_at
		FROM alerts WHERE 1=1`
	args := []any{}
	if p.Status != "" {
		args = append(args, p.Status)
		query += fmt.Sprintf(" AND status = $%d", len(args))
	}
	if p.Severity != "" {
		args = append(args, p.Severity)
		query += fmt.Sprintf(" AND severity = $%d", len(args))
	}
	if p.AlertType != "" {
		args = append(args, p.AlertType)
		query += fmt.Sprintf(" AND alert_type = $%d", len(args))
	}
	query += " ORDER BY created_at DESC"
	args = append(args, limit)
	query += fmt.Sprintf(" LIMIT $%d", len(args))
	args = append(args, p.Offset)
	query += fmt.Sprintf(" OFFSET $%d", len(args))

	rows, err := s.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list alerts: %w", err)
	}
	defer rows.Close()
	return scanAlerts(rows)
}

func (s *Store) GetAlert(ctx context.Context, id string) (*models.Alert, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, created_at, alert_type, severity, title, description,
			COALESCE(src_ip,''), COALESCE(dst_ip,''), COALESCE(dst_port,0), COALESCE(asset_hostname,''),
			event_count, threat_intel, source_refs, status, updated_at
		FROM alerts WHERE id = $1`, id)
	if err != nil {
		return nil, fmt.Errorf("get alert %s: %w", id, err)
	}
	defer rows.Close()
	alerts, err := scanAlerts(rows)
	if err != nil {
		return nil, err
	}
	if len(alerts) == 0 {
		return nil, pgx.ErrNoRows
	}
	return &alerts[0], nil
}

// UpdateAlertStatus is the "mark alert as open/investigating/resolved/false
// positive" analyst workflow action.
func (s *Store) UpdateAlertStatus(ctx context.Context, id, status string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE alerts SET status = $1, updated_at = now() WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("update alert status %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

func (s *Store) AddNote(ctx context.Context, alertID, author, note string) (models.AlertNote, error) {
	var n models.AlertNote
	err := s.pool.QueryRow(ctx, `
		INSERT INTO alert_notes (alert_id, author, note) VALUES ($1, $2, $3)
		RETURNING id, alert_id, author, note, created_at`,
		alertID, author, note,
	).Scan(&n.ID, &n.AlertID, &n.Author, &n.Note, &n.CreatedAt)
	if err != nil {
		return models.AlertNote{}, fmt.Errorf("add note to alert %s: %w", alertID, err)
	}
	return n, nil
}

func (s *Store) ListNotes(ctx context.Context, alertID string) ([]models.AlertNote, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, alert_id, author, note, created_at FROM alert_notes
		WHERE alert_id = $1 ORDER BY created_at ASC`, alertID)
	if err != nil {
		return nil, fmt.Errorf("list notes for alert %s: %w", alertID, err)
	}
	defer rows.Close()
	var notes []models.AlertNote
	for rows.Next() {
		var n models.AlertNote
		if err := rows.Scan(&n.ID, &n.AlertID, &n.Author, &n.Note, &n.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan note: %w", err)
		}
		notes = append(notes, n)
	}
	return notes, rows.Err()
}

func (s *Store) ListAssets(ctx context.Context) ([]models.Asset, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ip, hostname, asset_type, COALESCE(role,''), criticality, COALESCE(owner,'')
		FROM assets ORDER BY hostname ASC`)
	if err != nil {
		return nil, fmt.Errorf("list assets: %w", err)
	}
	defer rows.Close()
	var assets []models.Asset
	for rows.Next() {
		var a models.Asset
		if err := rows.Scan(&a.IP, &a.Hostname, &a.AssetType, &a.Role, &a.Criticality, &a.Owner); err != nil {
			return nil, fmt.Errorf("scan asset: %w", err)
		}
		assets = append(assets, a)
	}
	return assets, rows.Err()
}

func scanAlerts(rows pgx.Rows) ([]models.Alert, error) {
	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		var threatIntel, sourceRefs []byte
		var alertType, severity, status string
		if err := rows.Scan(&a.ID, &a.CreatedAt, &alertType, &severity, &a.Title, &a.Description,
			&a.SrcIP, &a.DstIP, &a.DstPort, &a.AssetHostname,
			&a.EventCount, &threatIntel, &sourceRefs, &status, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		a.AlertType = models.AlertType(alertType)
		a.Severity = models.Severity(severity)
		a.Status = models.AlertStatus(status)
		if err := json.Unmarshal(threatIntel, &a.ThreatIntel); err != nil {
			return nil, fmt.Errorf("unmarshal threat_intel for alert %s: %w", a.ID, err)
		}
		if err := json.Unmarshal(sourceRefs, &a.SourceRefs); err != nil {
			return nil, fmt.Errorf("unmarshal source_refs for alert %s: %w", a.ID, err)
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullIfZero(n int) any {
	if n == 0 {
		return nil
	}
	return n
}

func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
