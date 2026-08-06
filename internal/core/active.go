package core

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	g "github.com/dylan1501/smap/internal/global"
)

var execNmap = func(args []string) ([]byte, []byte, error) {
	cmd := exec.Command("nmap", args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

type nmapRun struct {
	Hosts    []nmapHost   `xml:"host"`
	RunStats nmapRunStats `xml:"runstats"`
}

type nmapRunStats struct {
	Finished nmapFinished `xml:"finished"`
}

type nmapFinished struct {
	Exit     string `xml:"exit,attr"`
	ErrorMsg string `xml:"errormsg,attr"`
}

type nmapHost struct {
	StartTime string        `xml:"starttime,attr"`
	EndTime   string        `xml:"endtime,attr"`
	Status    nmapStatus    `xml:"status"`
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Scripts   nmapScripts   `xml:"hostscript"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Items []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
}

type nmapPorts struct {
	Items []nmapPort `xml:"port"`
}

type nmapScripts struct {
	Items []nmapScript `xml:"script"`
}

type nmapPort struct {
	Protocol string       `xml:"protocol,attr"`
	PortID   int          `xml:"portid,attr"`
	State    nmapState    `xml:"state"`
	Service  nmapService  `xml:"service"`
	Scripts  []nmapScript `xml:"script"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string   `xml:"name,attr"`
	Product string   `xml:"product,attr"`
	Version string   `xml:"version,attr"`
	Tunnel  string   `xml:"tunnel,attr"`
	CPEs    []string `xml:"cpe"`
}

type nmapScript struct {
	ID       string              `xml:"id,attr"`
	Output   string              `xml:"output,attr"`
	Elements []nmapScriptElement `xml:",any"`
}

type nmapScriptElement struct {
	XMLName  xml.Name            `xml:""`
	Key      string              `xml:"key,attr"`
	Value    string              `xml:",chardata"`
	Elements []nmapScriptElement `xml:",any"`
}

type activeScanResult struct {
	IP        string
	Hostnames []string
	Scripts   []g.Script
	Ports     []g.Port
	Up        bool
	Start     time.Time
	End       time.Time
}

func validateActiveMode() error {
	if value, ok := g.Args["oA"]; ok && value == "-" {
		return fmt.Errorf("cannot display multiple output types to stdout")
	}
	for _, argName := range []string{"oS", "oJ", "oP"} {
		if value, ok := g.Args[argName]; ok && value == "-" {
			return fmt.Errorf("--active requires -%s to write to a file, not stdout", argName)
		}
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		return fmt.Errorf("nmap is required for --active")
	}
	return nil
}

func activePortList(result g.Output) string {
	ports := make([]int, 0, len(result.Ports))
	for _, port := range result.Ports {
		ports = append(ports, port.Port)
	}
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

func candidatePortUnion(results []g.Output) []int {
	seen := map[int]bool{}
	ports := make([]int, 0)
	for _, result := range results {
		for _, port := range result.Ports {
			if seen[port.Port] {
				continue
			}
			seen[port.Port] = true
			ports = append(ports, port.Port)
		}
	}
	sort.Ints(ports)
	return ports
}

func convertScripts(scripts []nmapScript) []g.Script {
	converted := make([]g.Script, 0, len(scripts))
	for _, script := range scripts {
		if script.ID == "" {
			continue
		}
		converted = append(converted, g.Script{
			ID:       script.ID,
			Output:   decodeHexEscapes(script.Output),
			Elements: convertScriptElements(script.Elements),
		})
	}
	return converted
}

func convertScriptElements(elements []nmapScriptElement) []g.ScriptElement {
	converted := make([]g.ScriptElement, 0, len(elements))
	for _, element := range elements {
		kind := element.XMLName.Local
		if kind != "elem" && kind != "table" {
			continue
		}
		convertedElement := g.ScriptElement{
			Kind:     kind,
			Key:      element.Key,
			Value:    decodeHexEscapes(strings.TrimSpace(element.Value)),
			Elements: convertScriptElements(element.Elements),
		}
		converted = append(converted, convertedElement)
	}
	if len(converted) == 0 {
		return nil
	}
	return converted
}

func decodeHexEscapes(value string) string {
	if !strings.Contains(value, `\x`) {
		return value
	}

	buf := make([]byte, 0, len(value))
	for index := 0; index < len(value); index++ {
		if value[index] == '\\' && index+3 < len(value) && value[index+1] == 'x' {
			decoded, err := strconv.ParseUint(value[index+2:index+4], 16, 8)
			if err == nil {
				buf = append(buf, byte(decoded))
				index += 3
				continue
			}
		}
		buf = append(buf, value[index])
	}
	if !utf8.Valid(buf) {
		return value
	}
	return string(buf)
}

func flagString(name string) string {
	if len(name) <= 2 && !strings.Contains(name, "-") {
		return "-" + name
	}
	return "--" + name
}

func shouldForwardToNmap(name string) bool {
	switch name {
	case "active", "append-output", "concurrency", "h", "iL", "oA", "oG", "oJ", "oN", "oP", "oS", "oX", "p", "V":
		return false
	default:
		return true
	}
}

func buildActiveNmapArgs(result g.Output) []string {
	keys := make([]string, 0, len(g.Args))
	for key := range g.Args {
		if shouldForwardToNmap(key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	args := make([]string, 0, len(keys)*2+5)
	for _, key := range keys {
		args = append(args, flagString(key))
		if boolType, ok := validArgs[key]; ok && !boolType {
			args = append(args, g.Args[key])
		}
	}
	args = append(args, "-p", activePortList(result), "-oX", "-", result.IP)
	return args
}

func parseUnixAttr(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(value, 0)
}

func parseNmapXML(data []byte) (activeScanResult, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return activeScanResult{}, err
	}
	if run.RunStats.Finished.Exit != "" && run.RunStats.Finished.Exit != "success" {
		if run.RunStats.Finished.ErrorMsg != "" {
			return activeScanResult{}, fmt.Errorf("%s", run.RunStats.Finished.ErrorMsg)
		}
		return activeScanResult{}, fmt.Errorf("nmap reported %s", run.RunStats.Finished.Exit)
	}
	if len(run.Hosts) == 0 {
		return activeScanResult{}, nil
	}

	host := run.Hosts[0]
	result := activeScanResult{
		Start: parseUnixAttr(host.StartTime),
		End:   parseUnixAttr(host.EndTime),
	}

	for _, address := range host.Addresses {
		if address.AddrType == "ipv4" {
			result.IP = address.Addr
			break
		}
	}
	for _, hostname := range host.Hostnames.Items {
		if hostname.Name != "" {
			result.Hostnames = append(result.Hostnames, hostname.Name)
		}
	}
	result.Scripts = convertScripts(host.Scripts.Items)
	result.Up = host.Status.State == "up"
	if !result.Up {
		return result, nil
	}
	for _, port := range host.Ports.Items {
		if port.State.State != "open" {
			continue
		}
		result.Ports = append(result.Ports, g.Port{
			Port:     port.PortID,
			Service:  port.Service.Name,
			Cpes:     port.Service.CPEs,
			Protocol: port.Protocol,
			Product:  port.Service.Product,
			Version:  port.Service.Version,
			Ssl:      port.Service.Tunnel == "ssl",
			Scripts:  convertScripts(port.Scripts),
		})
	}
	sort.Slice(result.Ports, func(i int, j int) bool {
		return result.Ports[i].Port < result.Ports[j].Port
	})
	return result, nil
}

func mergeHostnames(existing []string, incoming []string) []string {
	seen := map[string]bool{}
	merged := make([]string, 0, len(existing)+len(incoming))
	for _, hostname := range existing {
		if hostname == "" || seen[hostname] {
			continue
		}
		seen[hostname] = true
		merged = append(merged, hostname)
	}
	for _, hostname := range incoming {
		if hostname == "" || seen[hostname] {
			continue
		}
		seen[hostname] = true
		merged = append(merged, hostname)
	}
	return merged
}

func normalizeServiceIdentity(service string) string {
	return strings.TrimSuffix(service, "?")
}

func sameServiceIdentity(left string, right string) bool {
	return normalizeServiceIdentity(left) == normalizeServiceIdentity(right)
}

func mergeActiveResult(passive g.Output, active activeScanResult) g.Output {
	merged := passive
	if active.IP != "" {
		merged.IP = active.IP
	}
	if !active.Start.IsZero() {
		merged.Start = active.Start
	}
	if !active.End.IsZero() {
		merged.End = active.End
	}
	merged.Hostnames = mergeHostnames(passive.Hostnames, active.Hostnames)
	if len(active.Scripts) != 0 {
		merged.Scripts = active.Scripts
	}

	passivePorts := make(map[int]g.Port, len(passive.Ports))
	for _, port := range passive.Ports {
		passivePorts[port.Port] = port
	}

	merged.Ports = make([]g.Port, 0, len(active.Ports))
	for _, activePort := range active.Ports {
		port := activePort
		if passivePort, ok := passivePorts[activePort.Port]; ok {
			port = passivePort
			serviceChanged := activePort.Service != "" && !sameServiceIdentity(activePort.Service, passivePort.Service)
			if activePort.Service != "" {
				port.Service = activePort.Service
			}
			if activePort.Protocol != "" {
				port.Protocol = activePort.Protocol
			}
			if serviceChanged {
				port.Product = ""
				port.Version = ""
				port.Cpes = nil
			}
			if activePort.Product != "" {
				port.Product = activePort.Product
			}
			if activePort.Version != "" {
				port.Version = activePort.Version
			}
			if len(activePort.Cpes) != 0 {
				port.Cpes = activePort.Cpes
			}
			if len(activePort.Scripts) != 0 {
				port.Scripts = activePort.Scripts
			}
			port.Ssl = activePort.Ssl
		}
		if port.Protocol == "" {
			port.Protocol = "tcp"
		}
		merged.Ports = append(merged.Ports, port)
	}

	sort.Slice(merged.Ports, func(i int, j int) bool {
		return merged.Ports[i].Port < merged.Ports[j].Port
	})
	if merged.OS.Port != 0 {
		osPortConfirmed := false
		for _, port := range merged.Ports {
			if port.Port == merged.OS.Port {
				osPortConfirmed = true
				break
			}
		}
		if !osPortConfirmed {
			merged.OS = g.OS{}
		}
	}
	return merged
}

func enrichActiveHost(result g.Output) (g.Output, bool, activeHostStats) {
	args := buildActiveNmapArgs(result)
	stdout, stderr, err := execNmap(args)
	if len(stderr) != 0 {
		fmt.Fprintf(os.Stderr, "Nmap stderr for %s:\n%s", result.IP, string(stderr))
	}
	if err != nil && len(stdout) == 0 {
		fmt.Fprintf(os.Stderr, "Warning: active scan failed for %s, keeping passive result.\n", result.IP)
		return result, true, activeHostStats{Alive: true, Fallback: true}
	}
	activeResult, parseErr := parseNmapXML(stdout)
	if parseErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: active scan did not complete successfully for %s, keeping passive result.\n", result.IP)
		return result, true, activeHostStats{Alive: true, Fallback: true}
	}
	merged := mergeActiveResult(result, activeResult)
	if len(merged.Ports) == 0 {
		return g.Output{}, false, activeHostStats{Alive: activeResult.Up, Dropped: true}
	}
	return merged, true, activeHostStats{Alive: true, ConfirmedPorts: len(merged.Ports)}
}

type activeStats struct {
	CandidateHosts int
	CandidatePorts int
	AliveHosts     int
	ConfirmedHosts int
	ConfirmedPorts int
	DroppedHosts   int
	FallbackHosts  int
}

type activeHostStats struct {
	ConfirmedPorts int
	Alive          bool
	Fallback       bool
	Dropped        bool
}

func pluralize(count int, singular string) string {
	if count == 1 {
		return singular
	}
	return singular + "s"
}

func formatActiveSummary(totalTargets int, stats activeStats) string {
	if stats.CandidateHosts == 0 {
		return fmt.Sprintf(
			"Active mode: Shodan found no passive-open ports across %d %s, so Nmap verification was skipped.",
			totalTargets,
			pluralize(totalTargets, "target"),
		)
	}

	summary := fmt.Sprintf(
		"Active mode: Shodan reduced %d %s to %d candidate %s / %d candidate %s for Nmap verification; confirmed %d %s / %d %s",
		totalTargets,
		pluralize(totalTargets, "target"),
		stats.CandidateHosts,
		pluralize(stats.CandidateHosts, "host"),
		stats.CandidatePorts,
		pluralize(stats.CandidatePorts, "port"),
		stats.ConfirmedHosts,
		pluralize(stats.ConfirmedHosts, "host"),
		stats.ConfirmedPorts,
		pluralize(stats.ConfirmedPorts, "port"),
	)
	if stats.DroppedHosts != 0 {
		summary += fmt.Sprintf(", dropped %d stale %s", stats.DroppedHosts, pluralize(stats.DroppedHosts, "host"))
	}
	if stats.FallbackHosts != 0 {
		summary += fmt.Sprintf(", kept %d %s passive after active errors", stats.FallbackHosts, pluralize(stats.FallbackHosts, "host"))
	}
	return summary + "."
}

func enrichActive(results []g.Output) ([]g.Output, activeStats, error) {
	type indexedResult struct {
		index  int
		result g.Output
		keep   bool
		stats  activeHostStats
	}

	stats := activeStats{}
	threads := make(chan bool, g.Concurrency)
	done := make(chan indexedResult, len(results))
	for index, result := range results {
		if len(result.Ports) == 0 {
			done <- indexedResult{index: index, keep: false}
			continue
		}
		stats.CandidateHosts++
		stats.CandidatePorts += len(result.Ports)
		threads <- true
		go func(index int, result g.Output) {
			defer func() {
				<-threads
			}()
			merged, keep, hostStats := enrichActiveHost(result)
			done <- indexedResult{index: index, result: merged, keep: keep, stats: hostStats}
		}(index, result)
	}

	indexed := make([]indexedResult, 0, len(results))
	for range results {
		indexed = append(indexed, <-done)
	}
	sort.Slice(indexed, func(i int, j int) bool {
		return indexed[i].index < indexed[j].index
	})

	enriched := make([]g.Output, 0, len(results))
	for _, item := range indexed {
		if item.stats.Alive {
			stats.AliveHosts++
		}
		if item.stats.ConfirmedPorts != 0 {
			stats.ConfirmedHosts++
			stats.ConfirmedPorts += item.stats.ConfirmedPorts
		}
		if item.stats.Dropped {
			stats.DroppedHosts++
		}
		if item.stats.Fallback {
			stats.FallbackHosts++
		}
		if item.keep {
			enriched = append(enriched, item.result)
		}
	}
	return enriched, stats, nil
}
