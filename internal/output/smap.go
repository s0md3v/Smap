package output

import (
	"fmt"
	"os"
	"strings"

	g "github.com/s0md3v/smap/internal/global"
)

var openedSmapFile *os.File

func StartSmap() {
	if g.SmapFilename != "-" {
		openedSmapFile = OpenFile(g.SmapFilename)
	}
	Write(fmt.Sprintf("\n\tSmap (%s)\n", g.Version), g.SmapFilename, openedSmapFile)
}

func ContinueSmap(result g.Output) {
	thisString := ""
	hostnames := append([]string{}, result.Hostnames...)
	if result.UHostname != "" {
		hostnames = append(hostnames, result.UHostname)
	}
	if len(hostnames) != 0 {
		thisString += fmt.Sprintf("\n+ %s (%s)\n", result.IP, strings.Join(hostnames, ", "))
	} else {
		thisString += fmt.Sprintf("\n+ %s\n", result.IP)
	}
	if result.OS.Name != "" {
		thisString += fmt.Sprintf("  - OS: %s\n", result.OS.Name)
	}
	if len(result.Tags) != 0 {
		thisString += fmt.Sprintf("  - Tags: %s\n", strings.Join(result.Tags, ", "))
	}
	if len(result.Scripts) != 0 {
		thisString += "  - Scripts:\n"
		for _, script := range result.Scripts {
			thisString += fmt.Sprintf("    - %s", script.ID)
			if text := scriptText(script); text != "" {
				thisString += fmt.Sprintf(": %s", strings.ReplaceAll(text, "\n", "\n      "))
			}
			thisString += "\n"
		}
	}
	if len(result.ObservedCpes) != 0 {
		thisString += "  + Observed CPEs:\n"
		for _, cpe := range result.ObservedCpes {
			thisString += fmt.Sprintf("    - %s\n", cpe)
		}
	}
	thisString += "  + Reported ports:\n"
	for _, port := range result.Ports {
		thisString += fmt.Sprintf("    - %d %s", port.Port, port.Protocol)
		if port.Service != "" {
			thisString += fmt.Sprintf("/%s", port.Service)
		}
		thisString += "\n"
		if len(port.Associations) == 0 {
			for _, cpe := range port.Cpes {
				thisString += fmt.Sprintf("      - CPE: %s\n", cpe)
			}
		}
		for _, script := range port.Scripts {
			thisString += fmt.Sprintf("      - %s", script.ID)
			if text := scriptText(script); text != "" {
				thisString += fmt.Sprintf(": %s", strings.ReplaceAll(text, "\n", "\n        "))
			}
			thisString += "\n"
		}
		for _, association := range port.Associations {
			confidence := association.Confidence
			if association.NmapConfidence != 0 {
				confidence += fmt.Sprintf(" %d/10", association.NmapConfidence)
			}
			product := association.Product
			if product == "" {
				product = association.Cpe
			}
			thisString += fmt.Sprintf("      - %s: %s [%s] %s\n", confidence, product, association.Service, association.Cpe)
		}
	}
	if len(result.UnassignedCpes) != 0 {
		thisString += "  + Unassigned application CPEs:\n"
		for _, cpe := range result.UnassignedCpes {
			thisString += fmt.Sprintf("    - %s\n", cpe)
		}
	}
	if len(result.Vulns) != 0 {
		thisString += fmt.Sprintf("  - Vulns: %s\n", strings.Join(result.Vulns, ", "))
	}
	Write(thisString, g.SmapFilename, openedSmapFile)
}

func EndSmap() {
	CloseFile(openedSmapFile)
}
