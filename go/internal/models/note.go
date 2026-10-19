package models

import "time"

// AlertNote is an analyst-authored note attached to an alert during triage
// (part of the "add notes" analyst workflow requirement).
type AlertNote struct {
	ID        int64     `json:"id"`
	AlertID   string    `json:"alert_id"`
	Author    string    `json:"author"`
	Note      string    `json:"note"`
	CreatedAt time.Time `json:"created_at"`
}
