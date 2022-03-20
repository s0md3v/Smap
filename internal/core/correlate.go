package core

import (
	"strconv"
	"strings"

	g "github.com/s0md3v/smap/internal/global"
)

var Probes []g.Contender
var Table map[string]string

func deleteString(s []string, i int) []string {
	return append(s[:i], s[i+1:]...)
}

func containsInt(array []int, item int) bool {
	for _, thisItem := range array {
		if thisItem == item {
			return true
		}
	}
	return false
}

func Correlate(ports []int, cpes []string) ([]g.Port, g.OS) {
	contenders := map[int]g.Contender{}
	used_cpes := map[string]int{}
	result := []g.Port{}
	var thisOS g.OS
	duplicateMap := map[string][]int{} // {joined_cpe: [score, port]}
	for _, service := range Probes {
		cpeMatched := false
		thisContender := service
		for _, cpe := range service.Cpes {
			minus := len(service.Cpes)
			for _, shodanCpe := range cpes {
				if strings.HasPrefix(shodanCpe, cpe) {
					minus--
					if strings.HasPrefix(shodanCpe, "cpe:/a") {
						cpeMatched = true
					}
					if strings.Count(cpe, ":") < 3 {
						thisContender.Score += 1
					} else {
						thisContender.Score += 2
					}
				}
			}
			thisContender.Score -= minus
		}
		if !cpeMatched {
			continue
		}
		if !service.Softmatch {
			thisContender.Score--
		}
		for _, port := range ports {
			tempContender := thisContender
			if containsInt(service.Heuristic, port) {
				tempContender.Score += 3
			}
			if containsInt(service.Ports, port) {
				tempContender.Score += 2
			}
			if containsInt(service.Sslports, port) {
				tempContender.Score += 2
				tempContender.Ssl = true
			}
			if tempContender.Score > contenders[port].Score {
				failed := false
				for _, cpe := range tempContender.Cpes {
					if bestScore, ok := used_cpes[cpe]; ok {
						if tempContender.Score < bestScore {
							failed = true
						}
					}
				}
				if failed {
					continue
				}
				joinedCpes := strings.Join(tempContender.Cpes, "")
				if scoreAndPort, ok := duplicateMap[joinedCpes]; ok {
					localScore, localPort := scoreAndPort[0], scoreAndPort[1]
					if tempContender.Score > localScore {
						duplicateMap[joinedCpes] = []int{tempContender.Score, port}
						delete(contenders, localPort)
					} else {
						continue
					}
				} else {
					duplicateMap[joinedCpes] = []int{tempContender.Score, port}
				}
				if tempContender.OS != "" {
					thisOS.Port = port
					thisOS.Name = tempContender.OS
					thisOS.Cpes = []string{}
					for _, cpe := range tempContender.Cpes {
						if strings.HasPrefix(cpe, "cpe:/o") {
							thisOS.Cpes = append(thisOS.Cpes, cpe)
						}
					}
				}
				tempContender.Ports = []int{}
				tempContender.Sslports = []int{}
				tempContender.Heuristic = []int{}
				contenders[port] = tempContender
				for _, cpe := range tempContender.Cpes {
					used_cpes[cpe] = tempContender.Score
				}
			}
		}
	}
	orphan_ports := []int{}
	for port, contender := range contenders {
		thisPort := g.Port{}
		thisPort.Port = port
		thisPort.Service = contender.Service
		thisPort.Protocol = contender.Protocol
		thisPort.Product = contender.Product
		thisPort.Ssl = contender.Ssl
		thisPort.Cpes = []string{}
		replaceWith := cpes
		for _, cpe := range contender.Cpes {
			cpes = replaceWith
			for index, shodanCpe := range cpes {
				if strings.HasPrefix(shodanCpe, cpe) {
					thisPort.Cpes = append(thisPort.Cpes, shodanCpe)
					if strings.Count(shodanCpe, ":") > 3 {
						thisPort.Version = strings.Split(shodanCpe, ":")[4]
					}
					replaceWith = deleteString(cpes, index)
					break
				}
			}
		}
		result = append(result, thisPort)
	}
	for _, port := range ports {
		if _, ok := contenders[port]; !ok {
			orphan_ports = append(orphan_ports, port)
		}
	}
	for _, port := range orphan_ports {
		dummyPort := g.Port{}
		dummyPort.Port = port
		if value, ok := Table[strconv.Itoa(port)]; ok {
			dummyPort.Service = value + "?"
		}
		dummyPort.Protocol = "tcp"
		result = append(result, dummyPort)
	}
	return result, thisOS
}
