package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	g "github.com/s0md3v/smap/internal/global"
)

var openedGrepFile *os.File

func StartGrep() {
	if g.GrepFilename != "-" {
		openedGrepFile = OpenFile(g.GrepFilename)
	}
	startstr := ConvertTime(g.ScanStartTime, "nmap-file")
	Write(fmt.Sprintf("# Nmap 9.99 scan initiated %s as: %s\n", startstr, GetCommand()), g.GrepFilename, openedGrepFile)
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
	Write(entireString, g.GrepFilename, openedGrepFile)
}

func EndGrep() {
	elapsed := fmt.Sprintf("%.2f", time.Since(g.ScanStartTime).Seconds())
	esTotal := ""
	if g.TotalHosts > 1 {
		esTotal = "es"
	}
	sAlive := ""
	if g.AliveHosts > 1 {
		sAlive = "s"
	}
	Write(fmt.Sprintf("# Nmap done at %s -- %d IP address%s (%d host%s up) scanned in %s seconds\n", ConvertTime(g.ScanEndTime, "nmap-file"), g.TotalHosts, esTotal, g.AliveHosts, sAlive, elapsed), g.GrepFilename, openedGrepFile)
	defer openedGrepFile.Close()
}
