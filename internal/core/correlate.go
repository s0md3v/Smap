package core

import (
	"strconv"
	"strings"

	g "github.com/s0md3v/smap/internal/global"
)

type capability struct {
	Cpe     string `json:"cpe"`
	Service string `json:"service"`
	Product string `json:"product,omitempty"`
	TLS     bool   `json:"tls"`
}

var Table map[string]string
var catalog []capability
var capabilities map[string][]capability
var capabilityServiceCounts map[string]int
var cpeAliases = map[string]string{
	"a:f5:nginx":    "a:igor_sysoev:nginx",
	"a:nginx:nginx": "a:igor_sysoev:nginx",
}

func containsInt(array []int, item int) bool {
	for _, thisItem := range array {
		if thisItem == item {
			return true
		}
	}
	return false
}

func cpeParts(value string) (string, string) {
	parts := strings.Split(value, ":")
	if len(parts) >= 4 && parts[0] == "cpe" && strings.HasPrefix(parts[1], "/") {
		kind := strings.TrimPrefix(parts[1], "/")
		return kind, strings.Join([]string{kind, parts[2], parts[3]}, ":")
	}
	if len(parts) >= 5 && parts[0] == "cpe" && parts[1] == "2.3" {
		return parts[2], strings.Join([]string{parts[2], parts[3], parts[4]}, ":")
	}
	return "", ""
}

func cpeVersion(value string) string {
	parts := strings.Split(value, ":")
	version := ""
	if len(parts) >= 5 && parts[0] == "cpe" && strings.HasPrefix(parts[1], "/") {
		version = parts[4]
	} else if len(parts) >= 6 && parts[0] == "cpe" && parts[1] == "2.3" {
		version = parts[5]
	}
	if version == "*" || version == "-" {
		return ""
	}
	return version
}

func portService(value string) (string, bool, bool) {
	switch strings.ToLower(value) {
	case "https":
		return "http", true, false
	case "http-alt", "http-proxy":
		return "http", false, true
	case "https-alt", "pcsync-https":
		return "http", true, true
	case "smtps":
		return "smtp", true, false
	case "submission":
		return "smtp", false, true
	case "imaps", "imap4-ssl":
		return "imap", true, false
	case "pop3s":
		return "pop3", true, false
	case "ftps":
		return "ftp", true, false
	case "ldaps", "ldapssl":
		return "ldap", true, false
	case "nntps", "snews":
		return "nntp", true, false
	case "domain-s":
		return "domain", true, false
	case "telnets":
		return "telnet", true, false
	case "ircs", "ircs-u":
		return "irc", true, false
	case "sip-tls":
		return "sip", true, false
	case "secure-mqtt":
		return "mqtt", true, false
	case "syslog-tls":
		return "syslog", true, false
	case "rtsp-alt":
		return "rtsp", false, true
	default:
		return strings.ToLower(value), false, false
	}
}

func applicationCPEKey(value string) string {
	kind, key := cpeParts(value)
	if kind != "a" {
		return ""
	}
	if alias, ok := cpeAliases[key]; ok {
		return alias
	}
	return key
}

func buildCapabilities() {
	capabilities = map[string][]capability{}
	capabilityServiceCounts = map[string]int{}
	services := map[string]map[string]bool{}
	for _, candidate := range catalog {
		capabilities[candidate.Cpe] = append(capabilities[candidate.Cpe], candidate)
		if services[candidate.Cpe] == nil {
			services[candidate.Cpe] = map[string]bool{}
		}
		services[candidate.Cpe][candidate.Service] = true
	}
	for cpe, values := range services {
		capabilityServiceCounts[cpe] = len(values)
	}
}

func associationsFor(service string, cpes []string) []g.Association {
	wanted, tls, alternate := portService(service)
	if wanted == "" {
		return nil
	}
	result := []g.Association{}
	for _, cpe := range cpes {
		key := applicationCPEKey(cpe)
		if key == "" {
			continue
		}
		best := g.Association{}
		for _, candidate := range capabilities[key] {
			exact := candidate.Service == strings.ToLower(service)
			if candidate.Service != wanted && !(alternate && exact) {
				continue
			}
			confidence := "inferred"
			nmapConfidence := 6
			if alternate && !exact {
				nmapConfidence--
			}
			if tls && !candidate.TLS {
				confidence = "candidate"
				nmapConfidence = 0
			} else {
				if capabilityServiceCounts[key] == 1 {
					nmapConfidence++
				}
				if tls && candidate.TLS {
					nmapConfidence++
				}
				if nmapConfidence > 8 {
					nmapConfidence = 8
				}
			}
			if best.Cpe == "" || (best.Confidence == "candidate" && confidence == "inferred") || (best.Confidence == confidence && nmapConfidence > best.NmapConfidence) {
				best = g.Association{
					Cpe:            cpe,
					Service:        candidate.Service,
					Product:        candidate.Product,
					Confidence:     confidence,
					NmapConfidence: nmapConfidence,
				}
			}
		}
		if best.Cpe != "" {
			result = append(result, best)
		}
	}
	return result
}

func unassignedCPEs(observed []string, ports []g.Port) []string {
	assigned := map[string]bool{}
	for _, port := range ports {
		for _, cpe := range port.Cpes {
			if key := applicationCPEKey(cpe); key != "" {
				assigned[key] = true
			}
		}
		for _, association := range port.Associations {
			if key := applicationCPEKey(association.Cpe); key != "" {
				assigned[key] = true
			}
		}
	}

	result := []string{}
	for _, cpe := range observed {
		key := applicationCPEKey(cpe)
		if key != "" && !assigned[key] {
			result = append(result, cpe)
		}
	}
	return result
}

func Correlate(ports []int, cpes []string) ([]g.Port, g.OS, []string) {
	result := make([]g.Port, 0, len(ports))
	for _, number := range ports {
		thisPort := g.Port{Port: number, Protocol: "tcp", ProtocolSource: "compatibility-default", Cpes: []string{}}
		service := Table[strconv.Itoa(number)]
		if service != "" {
			thisPort.Service = service + "?"
			thisPort.ServiceSource = "port-default"
			thisPort.NmapConfidence = 3
		}
		thisPort.Associations = associationsFor(service, cpes)
		inferredCount := 0
		bestConfidence := 0
		bestCount := 0
		for _, association := range thisPort.Associations {
			if association.Confidence == "inferred" {
				inferredCount++
				if association.NmapConfidence > bestConfidence {
					bestConfidence = association.NmapConfidence
					bestCount = 1
				} else if association.NmapConfidence == bestConfidence {
					bestCount++
				}
			}
		}
		if inferredCount > 1 {
			for index := range thisPort.Associations {
				if thisPort.Associations[index].Confidence == "inferred" && (bestCount != 1 || thisPort.Associations[index].NmapConfidence != bestConfidence) {
					thisPort.Associations[index].Confidence = "candidate"
					thisPort.Associations[index].NmapConfidence = 0
				}
			}
			if bestCount == 1 {
				inferredCount = 1
			}
		}
		if inferredCount == 1 {
			selected := g.Association{}
			for _, association := range thisPort.Associations {
				if association.Confidence == "inferred" {
					selected = association
					break
				}
			}
			thisPort.Service = service
			thisPort.ServiceSource = "inferred"
			thisPort.NmapConfidence = selected.NmapConfidence
			thisPort.Cpes = []string{selected.Cpe}
			thisPort.Product = selected.Product
			thisPort.Version = cpeVersion(selected.Cpe)
			_, thisPort.Ssl, _ = portService(service)
		}
		result = append(result, thisPort)
	}
	return result, g.OS{}, unassignedCPEs(cpes, result)
}
