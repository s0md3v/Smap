package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dylan1501/smap/internal/db"
	g "github.com/dylan1501/smap/internal/global"
	o "github.com/dylan1501/smap/internal/output"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var (
	activeScans    sync.WaitGroup
	activeOutputs  sync.WaitGroup
	activeEnders   sync.WaitGroup
	activeObjects  sync.WaitGroup
	seenTargets    sync.Map
	targetsChannel = make(chan scanObject, 128)
	outputChannel  = make(chan g.Output, 1000)
	reAddressRange = regexp.MustCompile(`^\d{1,3}(-\d{1,3})?\.\d{1,3}(-\d{1,3})?\.\d{1,3}(-\d{1,3})?\.\d{1,3}(-\d{1,3})?$`)
)

type scanObject struct {
	IP       string
	Ports    []int
	Hostname string
}

type respone struct {
	Cpes      []string `json:"cpes"`
	Hostnames []string `json:"hostnames"`
	IP        string   `json:"ip"`
	Ports     []int    `json:"ports"`
	Tags      []string `json:"tags"`
	Vulns     []string `json:"vulns"`
}

type outputHandlers struct {
	start []func()
	write []func(g.Output)
	end   []func()
}

func getPorts() []int {
	thesePorts := []int{}
	if value, ok := g.Args["p"]; ok {
		for _, port := range strings.Split(value, ",") {
			portList := strings.Split(port, "-")
			if len(portList) == 2 {
				start, err := strconv.Atoi(portList[0])
				if err != nil {
					fmt.Fprint(os.Stderr, "' ' is not a valid port number.\nQUITTING!\n")
					os.Exit(1)
				}
				end, err := strconv.Atoi(portList[1])
				if err == nil && start >= 0 && start <= end && end <= 65535 {
					for i := start; i <= end; i++ {
						thesePorts = append(thesePorts, i)
					}
				} else {
					fmt.Fprint(os.Stderr, "' ' is not a valid port number.\nQUITTING!\n")
					os.Exit(1)
				}
			} else if len(portList) == 1 {
				intPort, err := strconv.Atoi(portList[0])
				if err == nil && intPort >= 0 && intPort <= 65535 {
					thesePorts = append(thesePorts, intPort)
				} else {
					fmt.Fprint(os.Stderr, "' ' is not a valid port number.\nQUITTING!\n")
					os.Exit(1)
				}
			} else {
				fmt.Fprint(os.Stderr, "' ' is not a valid port number.\nQUITTING!\n")
				os.Exit(1)
			}
		}
	}
	return thesePorts
}

func isIPv4(str string) bool {
	parsed := net.ParseIP(str)
	if parsed == nil {
		return false
	}
	return reAddressRange.MatchString(str)
}

func isHostname(str string) bool {
	_, err := publicsuffix.Domain(str)
	return err == nil
}

func isAddressRange(str string) bool {
	if !reAddressRange.MatchString(str) {
		return false
	}
	for _, part := range strings.Split(str, ".") {
		for _, each := range strings.Split(part, "-") {
			if len(each) > 1 && each[0] == 48 { // 48 is 0 in decimal
				return false
			}
			n, _ := strconv.Atoi(each)
			if n > 255 {
				return false
			}
		}
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			start, _ := strconv.Atoi(bounds[0])
			end, _ := strconv.Atoi(bounds[1])
			if start > end {
				return false
			}
		}
	}
	return true
}

func hostnameToIP(hostname string) string {
	ips, _ := net.LookupIP(hostname)
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			return ip4.String()
		}
	}
	return ""
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func handleOutput() {
	handlers := getOutputHandlers()
	if value, ok := g.Args["oA"]; ok {
		if value == "-" {
			fmt.Fprint(os.Stderr, "Cannot display multiple output types to stdout.\nQUITTING!\n")
			os.Exit(1)
		}
	}
	activeEnders.Add(len(handlers.end))
	for _, function := range handlers.start {
		function()
	}
	for output := range outputChannel {
		for _, function := range handlers.write {
			function(output)
		}
		activeOutputs.Done()
	}
	for _, function := range handlers.end {
		function()
		activeEnders.Done()
	}
}

func getOutputHandlers() outputHandlers {
	if value, ok := g.Args["oA"]; ok {
		g.XmlFilename = value + ".xml"
		g.GrepFilename = value + ".gnmap"
		g.Args["oN"] = value + ".nmap"
		return outputHandlers{
			start: []func(){o.StartXML, o.StartGrep, o.StartNmap},
			write: []func(g.Output){o.ContinueXML, o.ContinueGrep, o.ContinueNmap},
			end:   []func(){o.EndXML, o.EndGrep, o.EndNmap},
		}
	} else if value, ok := g.Args["oX"]; ok {
		g.XmlFilename = value
		return outputHandlers{
			start: []func(){o.StartXML},
			write: []func(g.Output){o.ContinueXML},
			end:   []func(){o.EndXML},
		}
	} else if value, ok := g.Args["oG"]; ok {
		g.GrepFilename = value
		return outputHandlers{
			start: []func(){o.StartGrep},
			write: []func(g.Output){o.ContinueGrep},
			end:   []func(){o.EndGrep},
		}
	} else if value, ok := g.Args["oJ"]; ok {
		g.JsonFilename = value
		return outputHandlers{
			start: []func(){o.StartJson},
			write: []func(g.Output){o.ContinueJson},
			end:   []func(){o.EndJson},
		}
	} else if value, ok := g.Args["oS"]; ok {
		g.SmapFilename = value
		return outputHandlers{
			start: []func(){o.StartSmap},
			write: []func(g.Output){o.ContinueSmap},
			end:   []func(){o.EndSmap},
		}
	} else if value, ok := g.Args["oP"]; ok {
		g.PairFilename = value
		return outputHandlers{
			start: []func(){o.StartPair},
			write: []func(g.Output){o.ContinuePair},
			end:   []func(){o.EndPair},
		}
	}
	return outputHandlers{
		start: []func(){o.StartNmap},
		write: []func(g.Output){o.ContinueNmap},
		end:   []func(){o.EndNmap},
	}
}

func renderResults(results []g.Output) {
	handlers := getOutputHandlers()
	for _, function := range handlers.start {
		function()
	}
	for _, result := range results {
		for _, function := range handlers.write {
			function(result)
		}
	}
	for _, function := range handlers.end {
		function()
	}
}

func scanner() {
	threads := make(chan bool, g.Concurrency)
	for target := range targetsChannel {
		threads <- true
		go func(target scanObject) {
			processScanObject(target)
			activeScans.Done()
			<-threads
		}(target)
	}
}

func shouldQueueTarget(ip string) bool {
	if ip == "" {
		return false
	}
	_, loaded := seenTargets.LoadOrStore(ip, true)
	return !loaded
}

func createScanObjects(object string) {
	activeScans.Add(1)
	var oneObject scanObject
	oneObject.Ports = g.PortList
	if isIPv4(object) {
		oneObject.IP = object
		if shouldQueueTarget(oneObject.IP) {
			targetsChannel <- oneObject
		} else {
			activeScans.Done()
		}
	} else if strings.Contains(object, "/") && isIPv4(strings.Split(object, "/")[0]) {
		activeScans.Done()
		ip, ipnet, err := net.ParseCIDR(object)
		if err != nil {
			return
		}
		for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
			oneObject.IP = ip.String()
			activeScans.Add(1)
			if shouldQueueTarget(oneObject.IP) {
				targetsChannel <- oneObject
			} else {
				activeScans.Done()
			}
		}
	} else if isAddressRange(object) {
		activeScans.Done()
		targets, err := expandAddressRange(object)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Skipping invalid address range %q\n", object)
			return
		}
		for _, target := range targets {
			oneObject.IP = target
			activeScans.Add(1)
			if shouldQueueTarget(oneObject.IP) {
				targetsChannel <- oneObject
			} else {
				activeScans.Done()
			}
		}
		return
	} else if isHostname(object) {
		ip := hostnameToIP(object)
		if ip != "" {
			oneObject.IP = ip
			oneObject.Hostname = object
			if shouldQueueTarget(oneObject.IP) {
				targetsChannel <- oneObject
			} else {
				activeScans.Done()
			}
		} else {
			activeScans.Done()
		}
	} else if object == "" {
		activeScans.Done()
		return
	} else {
		activeScans.Done()
	}
}

func processScanObject(object scanObject) {
	g.Increment(0)
	scanStarted := time.Now()
	response := Query(object.IP)
	var output g.Output
	if len(response) < 50 {
		return
	} else {
		activeOutputs.Add(1)
	}
	var data respone
	json.Unmarshal(response, &data)
	output.IP = data.IP
	output.Tags = data.Tags
	output.Vulns = data.Vulns
	output.Hostnames = data.Hostnames
	output.UHostname = object.Hostname
	filteredPorts := []int{}
	if len(object.Ports) > 0 {
		for _, port := range data.Ports {
			if containsInt(object.Ports, port) {
				filteredPorts = append(filteredPorts, port)
			}
		}
	} else {
		filteredPorts = data.Ports
	}
	output.Ports, output.OS = Correlate(filteredPorts, data.Cpes)
	output.Start = scanStarted
	output.End = time.Now()
	g.Increment(1)
	outputChannel <- output
}

func Init() {
	args, extra, invalid := ParseArgs()
	if invalid {
		fmt.Fprintln(os.Stderr, "One or more of your arguments are invalid. Refer to docs.\nQUITTING!")
		os.Exit(1)
	} else if _, ok := args["h"]; ok || len(os.Args) == 1 {
		fmt.Print(db.HelpText)
		os.Exit(0)
	}
	g.Args = args
	g.OutputPorts = nil
	seenTargets = sync.Map{}
	concurrency, err := getConcurrency()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\nQUITTING!\n", err)
		os.Exit(1)
	}
	g.Concurrency = concurrency
	shodanRPS, err := getShodanRPS()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\nQUITTING!\n", err)
		os.Exit(1)
	}
	g.ShodanRPS = shodanRPS
	if err := json.Unmarshal(db.NmapSigs, &Probes); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load embedded probe signatures: %v\nQUITTING!\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(db.NmapTable, &Table); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load embedded port table: %v\nQUITTING!\n", err)
		os.Exit(1)
	}
	g.PortList = getPorts()
	g.ScanStartTime = time.Now()
	go scanner()
	if _, ok := g.Args["active"]; ok {
		if err := validateActiveMode(); err != nil {
			fmt.Fprintf(os.Stderr, "%s\nQUITTING!\n", err)
			os.Exit(1)
		}
		resultsChannel := make(chan []g.Output, 1)
		go collectOutput(resultsChannel)
		enqueueTargets(extra)
		activeScans.Wait()
		close(targetsChannel)
		activeOutputs.Wait()
		close(outputChannel)
		passiveResults := <-resultsChannel
		activeResults, activeStats, err := enrichActive(passiveResults)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s\nQUITTING!\n", err)
			os.Exit(1)
		}
		totalHosts := int(g.TotalHosts)
		g.ScanEndTime = time.Now()
		g.SetCounts(totalHosts, activeStats.AliveHosts)
		g.OutputPorts = candidatePortUnion(passiveResults)
		renderResults(activeResults)
		fmt.Fprintln(os.Stderr, formatActiveSummary(totalHosts, activeStats))
		return
	}
	go handleOutput()
	enqueueTargets(extra)
	activeScans.Wait()
	close(targetsChannel)
	g.ScanEndTime = time.Now()
	activeOutputs.Wait()
	close(outputChannel)
	activeEnders.Wait()
}

func enqueueTargets(extra []string) {
	if value, ok := g.Args["iL"]; ok {
		scanner := bufio.NewScanner(os.Stdin)
		if value != "-" {
			file, err := os.Open(value)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open %s: %v\nQUITTING!\n", value, err)
				os.Exit(1)
			}
			defer file.Close()
			scanner = bufio.NewScanner(file)
		}
		for scanner.Scan() {
			createScanObjects(scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read targets: %v\nQUITTING!\n", err)
			os.Exit(1)
		}
	} else if len(extra) != 0 {
		threads := make(chan bool, g.Concurrency)
		for _, arg := range extra {
			activeObjects.Add(1)
			threads <- true
			go func(object string) {
				createScanObjects(object)
				<-threads
				activeObjects.Done()
			}(arg)
		}
		activeObjects.Wait()
	} else {
		fmt.Println("WARNING: No targets were specified, so 0 hosts scanned.")
	}
}
