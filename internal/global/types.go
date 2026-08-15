package global

import (
	"time"
)

type OS struct {
	Name string   `json:"name"`
	Cpes []string `json:"cpes"`
	Port int      `json:"port"`
}

type Script struct {
	ID       string          `json:"id"`
	Output   string          `json:"output,omitempty"`
	Elements []ScriptElement `json:"elements,omitempty"`
}

type ScriptElement struct {
	Kind     string          `json:"kind"`
	Key      string          `json:"key,omitempty"`
	Value    string          `json:"value,omitempty"`
	Elements []ScriptElement `json:"elements,omitempty"`
}

type Output struct {
	IP             string    `json:"ip"`
	Hostnames      []string  `json:"hostnames"`
	UHostname      string    `json:"user_hostname,omitempty"`
	Ports          []Port    `json:"ports"`
	Scripts        []Script  `json:"scripts,omitempty"`
	Tags           []string  `json:"tags,omitempty"`
	Vulns          []string  `json:"vulns,omitempty"`
	Start          time.Time `json:"start_time"`
	End            time.Time `json:"end_time"`
	OS             OS        `json:"os,omitempty"`
	ObservedCpes   []string  `json:"observed_cpes,omitempty"`
	UnassignedCpes []string  `json:"unassigned_cpes,omitempty"`
}

type Association struct {
	Cpe            string `json:"cpe"`
	Service        string `json:"service"`
	Product        string `json:"product,omitempty"`
	Confidence     string `json:"confidence"`
	NmapConfidence int    `json:"nmap_confidence,omitempty"`
}

type Port struct {
	Port           int           `json:"port"`
	Service        string        `json:"service"`
	ServiceSource  string        `json:"service_source,omitempty"`
	Cpes           []string      `json:"cpes"`
	Protocol       string        `json:"protocol"`
	ProtocolSource string        `json:"protocol_source,omitempty"`
	Product        string        `json:"product,omitempty"`
	Version        string        `json:"version,omitempty"`
	Ssl            bool          `json:"ssl,omitempty"`
	NmapConfidence int           `json:"nmap_confidence,omitempty"`
	Associations   []Association `json:"associations,omitempty"`
	Scripts        []Script      `json:"scripts,omitempty"`
}
