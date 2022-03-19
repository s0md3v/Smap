package core

type Contender struct {
	Service    string   `json:"service"`
	Cpes       []string `json:"cpes"`
	Protocol   string   `json:"protocol"`
	Softmatch  bool     `json:"softmatch"`
	Product    string   `json:"product,omitempty"`
	Heuristic  []int    `json:"heuristic,omitempty"`
	Os         string   `json:"os,omitempty"`
	Devicetype string   `json:"devicetype,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	Sslports   []int    `json:"sslports,omitempty"`
	Ssl        bool     `json:"ssl,omitempty"`
	Score      int      `json:"score,omitempty"`
}
