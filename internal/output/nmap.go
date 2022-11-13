package output

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	g "github.com/s0md3v/smap/internal/global"
)

var openedNmapFile *os.File

func pad(str string, n int) string {
	return strings.Repeat(" ", n) + str
}

func StartNmap() {
	if value, ok := g.Args["oN"]; ok {
		openedNmapFile = OpenFile(value)
		startstr := ConvertTime(g.ScanStartTime, "nmap-file")
		Write(fmt.Sprintf("# Starting Nmap 9.99 ( https://nmap.org ) at %s as: %s\n", startstr, GetCommand()), value, openedNmapFile)
	} else {
		startstr := ConvertTime(g.ScanStartTime, "nmap-stdout")
		Write(fmt.Sprintf("Starting Nmap 9.99 ( https://nmap.org ) at %s\n", startstr), "-", openedNmapFile)
	}
}

func ContinueNmap(result g.Output) {
	longestPort := 5
	longestService := 7
	for _, port := range result.Ports {
		strPort := strconv.Itoa(port.Port)
		if len(strPort)+4 > longestPort {
			longestPort = len(strPort) + 4
		}
		if len(port.Service) > longestService {
			longestService = len(port.Service)
		}
	}
	thisOutput := ""
	if result.UHostname != "" {
		thisOutput += fmt.Sprintf("Nmap scan report for %s (%s)\nHost is up.\n", result.UHostname, result.IP)
		if len(result.Hostnames) > 0 {
			thisOutput += fmt.Sprintf("rDNS record for %s: %s\n\n", result.IP, result.Hostnames[0])
		}
	} else if len(result.Hostnames) > 0 {
		thisOutput += fmt.Sprintf("Nmap scan report for %s (%s)\nHost is up.\n\n", result.Hostnames[0], result.IP)
	} else {
		thisOutput += fmt.Sprintf("Nmap scan report for %s\nHost is up.\n\n", result.IP)
	}
	if len(result.Ports) == 0 {
		return
	}
	thisOutput += fmt.Sprintf("PORT %sSTATE SERVICE %sVERSION\n", pad("", longestPort-4), pad(" ", longestService-7))
	serviceString := ""
	for _, port := range result.Ports {
		strPort := fmt.Sprintf("%d/%s", port.Port, port.Protocol)
		productLine := ""
		if port.Product != "" {
			productLine += port.Product
			if port.Version != "" {
				productLine += " " + port.Version
			}
		}
		thisOutput += fmt.Sprintf("%s%s  %s%s\n", strPort, pad("open", longestPort-len(strPort)+1), port.Service, pad(productLine, longestService-len(port.Service)+2))
		if result.OS.Name != "" && result.OS.Port == port.Port {
			serviceString += fmt.Sprintf("Service Info: OS: %s", result.OS.Name)
			if len(result.OS.Cpes) > 0 {
				for _, cpe := range result.OS.Cpes {
					if strings.Contains(cpe, strings.ToLower(result.OS.Name)) {
						serviceString += fmt.Sprintf("; CPE: %s", cpe)
						break
					}
				}
			}
			serviceString += "\n"
		}
	}
	thisOutput += serviceString
	thisOutput += "\n"
	if value, ok := g.Args["oN"]; ok {
		Write(thisOutput, value, openedNmapFile)
	} else {
		Write(thisOutput, "-", openedNmapFile)
	}
	Write(thisOutput, "Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\n", openedNmapFile)
}

func EndNmap() {
	elapsed := fmt.Sprintf("%.2f", time.Since(g.ScanStartTime).Seconds())
	esTotal := ""
	if g.TotalHosts > 1 {
		esTotal = "es"
	}
	sAlive := ""
	if g.AliveHosts > 1 {
		sAlive = "s"
	}
	footer := ""
	if value, ok := g.Args["oN"]; ok {
		endstr := ConvertTime(g.ScanEndTime, "nmap-file")
		footer += fmt.Sprintf("# Nmap done at %s -- %d IP address%s (%d host%s up) scanned in %s seconds\n", endstr, g.TotalHosts, esTotal, g.AliveHosts, sAlive, elapsed)
		Write(footer, value, openedNmapFile)
	} else {
		footer += fmt.Sprintf("Nmap done: %d IP address%s (%d host%s up) scanned in %s seconds\n", g.TotalHosts, esTotal, g.AliveHosts, sAlive, elapsed)
		Write(footer, "-", openedNmapFile)
	}
	defer openedNmapFile.Close()
}
