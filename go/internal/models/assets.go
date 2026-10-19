package models

import (
	"encoding/json"
	"fmt"
	"os"
)

// Asset mirrors a row of data/assets.json — the small inventory used both to
// seed PostgreSQL (scripts/seed_assets.py) and to label alerts with a
// hostname in the Go services.
type Asset struct {
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	AssetType   string `json:"asset_type"`
	Role        string `json:"role"`
	Criticality string `json:"criticality"`
	Owner       string `json:"owner"`
}

func LoadAssets(path string) ([]Asset, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read assets file %s: %w", path, err)
	}
	var assets []Asset
	if err := json.Unmarshal(b, &assets); err != nil {
		return nil, fmt.Errorf("parse assets file %s: %w", path, err)
	}
	return assets, nil
}

// AssetHostnameMap builds the ip -> hostname lookup the detection engine
// uses to label alerts.
func AssetHostnameMap(assets []Asset) map[string]string {
	m := make(map[string]string, len(assets))
	for _, a := range assets {
		m[a.IP] = a.Hostname
	}
	return m
}
