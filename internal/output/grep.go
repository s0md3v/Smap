package output

import (
	"fmt"
	"strings"
	"time"

	g "github.com/s0md3v/smap/internal/global"
)

func StartGrep() {
	startstr := ConvertTime(g.ScanStartTime, "nmap-file")
	Write(fmt.Sprintf("# Nmap 9.99 scan initiated %s as: %s\n", startstr, GetCommand()), g.GrepFilename)
}

func ContinueGrep(result g.Output) {
	hostname := ""
	if len(result.Hostnames) > 0 {
		hostname = result.Hostnames[0]
	}
	hostPrefix := fmt.Sprintf("Host: %s (%s)", result.IP, hostname)
	if hostname == "" {
		hostPrefix += "   "
	}
	entireString := fmt.Sprintf("%s Status: Up\n", hostPrefix)
	thesePorts := []string{}
	for _, port := range result.Ports {
		thisPort := fmt.Sprintf("%d/open/%s//%s//%s", port.Port, port.Protocol, port.Service, port.Product)
		if port.Version != "" {
			thisPort += fmt.Sprintf(" %s/", port.Version)
		} else {
			thisPort += "/"
		}
		thesePorts = append(thesePorts, thisPort)
	}
	entireString += fmt.Sprintf("%s Ports: %s\n", hostPrefix, strings.Join(thesePorts, ", "))
	Write(entireString, g.GrepFilename)
}

func EndGrep() {
	elapsed := fmt.Sprintf("%.2f", time.Since(g.ScanStartTime).Seconds())
	Write(fmt.Sprintf("# Nmap done at %s -- %d IP address (%d host up) scanned in %s seconds\n", ConvertTime(g.ScanEndTime, "nmap-file"), g.TotalHosts, g.AliveHosts, elapsed), g.GrepFilename)
}
