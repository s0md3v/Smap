package core

import (
	"os"
	"regexp"
	"strings"
)

var reValidPair = regexp.MustCompile(`^([-]{1,2}[A-Za-z-]+)(\d.*)?`)

var validArgs = map[string]bool{ // name : is_boolean_type
	"iL":                  false,
	"iR":                  false,
	"exclude":             false,
	"excludefile":         false,
	"sL":                  true,
	"sn":                  true,
	"Pn":                  true,
	"PS":                  true,
	"PA":                  true,
	"PU":                  true,
	"PY":                  true,
	"PE":                  true,
	"PP":                  true,
	"PM":                  true,
	"PO":                  true,
	"n":                   true,
	"R":                   true,
	"dns-servers":         false,
	"system-dns":          true,
	"traceroute":          true,
	"sS":                  true,
	"sT":                  true,
	"sA":                  true,
	"sW":                  true,
	"sM":                  true,
	"sU":                  true,
	"sN":                  true,
	"sF":                  true,
	"sX":                  true,
	"scanflags":           false,
	"sI":                  false,
	"sY":                  true,
	"sZ":                  true,
	"sO":                  true,
	"b":                   false,
	"p":                   false,
	"exclude-ports":       false,
	"F":                   true,
	"r":                   true,
	"top-ports":           false,
	"port-ratio":          false,
	"sV":                  true,
	"version-intensity":   false,
	"version-light":       true,
	"version-all":         true,
	"version-trace":       true,
	"sC":                  true,
	"script":              true,
	"script-args":         true,
	"script-args-file":    true,
	"script-trace":        true,
	"script-updatedb":     true,
	"script-help":         true,
	"O":                   true,
	"osscan-limit":        true,
	"osscan-guess":        true,
	"T":                   false,
	"min-hostgroup":       false,
	"max-hostgroup":       false,
	"min-parallelism":     false,
	"max-parallelism":     false,
	"min-rtt-timeout":     false,
	"max-rtt-timeout":     false,
	"initial-rtt-timeout": false,
	"max-retries":         false,
	"host-timeout":        false,
	"scan-delay":          false,
	"max-scan-delay":      false,
	"min-rate":            false,
	"max-rate":            false,
	"f":                   true,
	"D":                   false,
	"S":                   false,
	"e":                   false,
	"g":                   false,
	"source-port":         false,
	"proxies":             false,
	"data":                false,
	"data-string":         false,
	"data-length":         false,
	"ip-options":          false,
	"ttl":                 false,
	"spoof-mac":           false,
	"badsum":              true,
	"oN":                  false,
	"oX":                  false,
	"oS":                  false,
	"oG":                  false,
	"oA":                  false,
	"oJ":                  false,
	"oP":                  false,
	"v":                   true,
	"d":                   true,
	"reason":              true,
	"open":                true,
	"packet-trace":        true,
	"iflist":              true,
	"append-output":       true,
	"resume":              false,
	"stylesheet":          false,
	"webxml":              true,
	"no-stylesheet":       true,
	"6":                   true,
	"A":                   true,
	"datadir":             false,
	"send-eth":            true,
	"send-ip":             true,
	"privileged":          true,
	"unprivileged":        true,
	"V":                   true,
	"h":                   true,
}

func whatToDo(token string, lastAction int) (string, int) {
	/*
	   -1 = error
	    0 = look for next arg
	    1 = look for arg's value
	    2 = treat as extra data
	*/
	if strings.HasPrefix(token, "-") {
		if lastAction == 1 {
			if token == "-" {
				return token, 0
			}
			return token, -1
		}
		newToken := strings.TrimPrefix(strings.TrimPrefix(token, "-"), "-")
		if newToken == "6" {
			return newToken, 0
		}
		argName := strings.Replace(newToken, "_", "-", -1)
		if boolType, ok := validArgs[argName]; ok {
			if boolType {
				return argName, 0
			}
			return argName, 1
		}
		return argName, -1
	} else if lastAction == 1 {
		return token, 0
	}
	return token, 2
}

func ParseArgs() (map[string]string, []string, bool) {
	var lastAction int
	var lastArg string
	var extra []string
	argPair := map[string]string{}
	for _, token := range os.Args[1:] {
		groups := reValidPair.FindStringSubmatch(token)
		if strings.HasPrefix(token, "-") && (strings.Contains(token, "=") || groups != nil) {
			if lastAction == 1 {
				return argPair, extra, true
			}
			thisArgName := strings.Split(token, "=")[0]
			if groups != nil {
				thisArgName = groups[1]
			}
			cleaned, action := whatToDo(thisArgName, lastAction)
			if action == 1 {
				if groups != nil {
					argPair[cleaned] = groups[2]
				} else {
					argPair[cleaned] = strings.Replace(token, thisArgName+"=", "", 1)
				}
			} else if action == 0 {
				argPair[cleaned] = ""
			} else if action == 2 {
				extra = append(extra, cleaned)
			} else if action == -1 {
				return argPair, extra, true
			}
			lastArg = cleaned
			lastAction = action
			continue
		}
		cleaned, action := whatToDo(token, lastAction)
		if action == 2 {
			extra = append(extra, cleaned)
		} else if action == 1 {
			lastArg = cleaned
		} else if action == -1 {
			return argPair, extra, true
		} else if action == 0 && lastAction == 1 {
			argPair[lastArg] = cleaned
		}
		lastAction = action
	}
	if lastAction == 1 {
		return argPair, extra, true
	}
	return argPair, extra, false
}
