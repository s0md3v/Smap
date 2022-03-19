package global

import (
	"time"
)

type Contender struct {
	Service     string   `json:"service"`
	Cpes        []string `json:"cpes"`
	Protocol    string   `json:"protocol"`
	Softmatch   bool     `json:"softmatch"`
	Product     string   `json:"product,omitempty"`
	Heuristic   []int    `json:"heuristic,omitempty"`
	Os          string   `json:"os,omitempty"`
	Devicetype  string   `json:"devicetype,omitempty"`
	Ports       []int    `json:"ports,omitempty"`
	Sslports    []int    `json:"sslports,omitempty"`
	Ssl         bool     `json:"ssl,omitempty"`
	Score       int      `json:"score,omitempty"`
}

type Output struct {
	IP        string     `json:"ip"`
	Hostnames []string   `json:"hostnames"`
    UHostname string     `json:"user_hostname"` 
	Ports     []Port `json:"ports"`
	Tags      []string   `json:"tags"`
	Vulns     []string   `json:"vulns"`
	Start     time.Time
    End       time.Time
    OS        struct {
		Name string `json:"name"`
		Cpe  string `json:"name"`
        Port int    `json:"port"`
	} `json:"os"`
}

type Port struct {
	Port     int      `json:"port"`
	Service  string   `json:"service"`
	Cpes     []string `json:"cpes"`
	Protocol string   `json:"protocol"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Ssl      bool     `json:"ssl,omitempty"`
}
