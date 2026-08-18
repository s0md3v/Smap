package core

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	g "github.com/s0md3v/smap/internal/global"
)

// ShodanConfig models the on-disk config file smap reads the Shodan API key from.
// See configs/smap.example.json for a template.
type ShodanConfig struct {
	ShodanAPIKey string `json:"shodan_api_key"`
}

const (
	configDirName  = "smap"
	configFileName = "config.json"
)

var (
	shodanAPIKeyOnce  sync.Once
	shodanAPIKeyValue string
)

// ConfigFilePath returns the config file smap will look for the Shodan API key in.
// Priority: --config <path> > $SMAP_CONFIG > the OS-standard per-user config directory
// (e.g. %AppData%\smap\config.json on Windows, ~/.config/smap/config.json on Linux,
// ~/Library/Application Support/smap/config.json on macOS).
func ConfigFilePath() string {
	if value, ok := g.Args["config"]; ok && value != "" {
		return value
	}
	if value := os.Getenv("SMAP_CONFIG"); value != "" {
		return value
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return ""
	}
	return filepath.Join(configDir, configDirName, configFileName)
}

func readShodanConfig(path string) (ShodanConfig, error) {
	var cfg ShodanConfig
	if path == "" {
		return cfg, nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(content, &cfg); err != nil {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// shodanAPIKey resolves the Shodan API key, if any was configured, from (in priority
// order) the --shodan-key flag, the SHODAN_API_KEY environment variable and the config
// file. An empty return means smap falls back to the free InternetDB endpoint.
func shodanAPIKey() string {
	shodanAPIKeyOnce.Do(func() {
		if value, ok := g.Args["shodan-key"]; ok && value != "" {
			shodanAPIKeyValue = value
			return
		}
		if value := os.Getenv("SHODAN_API_KEY"); value != "" {
			shodanAPIKeyValue = value
			return
		}
		path := ConfigFilePath()
		cfg, err := readShodanConfig(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to read config file %s: %v\n", path, err)
			return
		}
		shodanAPIKeyValue = cfg.ShodanAPIKey
	})
	return shodanAPIKeyValue
}
