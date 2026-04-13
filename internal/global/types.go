package global

import (
	"time"
)

type Contender struct {
	Service    string   `json:"service"`
	Cpes       []string `json:"cpes"`
	Protocol   string   `json:"protocol"`
	Softmatch  bool     `json:"softmatch"`
	Product    string   `json:"product,omitempty"`
	Heuristic  []int    `json:"heuristic,omitempty"`
	OS         string   `json:"os,omitempty"`
	Devicetype string   `json:"devicetype,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	Sslports   []int    `json:"sslports,omitempty"`
	Ssl        bool     `json:"ssl,omitempty"`
	Score      int      `json:"score,omitempty"`
}

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
	IP        string    `json:"ip"`
	Hostnames []string  `json:"hostnames"`
	UHostname string    `json:"user_hostname,omitempty"`
	Ports     []Port    `json:"ports"`
	Scripts   []Script  `json:"scripts,omitempty"`
	Tags      []string  `json:"tags,omitempty"`
	Vulns     []string  `json:"vulns,omitempty"`
	Start     time.Time `json:"start_time"`
	End       time.Time `json:"end_time"`
	OS        OS        `json:"os,omitempty"`
}

type Port struct {
	Port     int      `json:"port"`
	Service  string   `json:"service"`
	Cpes     []string `json:"cpes"`
	Protocol string   `json:"protocol"`
	Product  string   `json:"product,omitempty"`
	Version  string   `json:"version,omitempty"`
	Ssl      bool     `json:"ssl,omitempty"`
	Scripts  []Script `json:"scripts,omitempty"`
}
