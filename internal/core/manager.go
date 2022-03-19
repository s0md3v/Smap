package core

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"encoding/json"

	"github.com/s0md3v/smap/internal/db"
	g "github.com/s0md3v/smap/internal/global"
	o "github.com/s0md3v/smap/internal/output"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var (
	activeScans    sync.WaitGroup
	activeOutputs  sync.WaitGroup
	activeEnders   sync.WaitGroup
	targetsChannel = make(chan scanObject, 3)
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

func getPorts() []int {
	thesePorts := []int{}
	if value, ok := g.Args["p"]; ok {
		for _, port := range strings.Split(value, ",") {
			intPort, err := strconv.Atoi(port)
			if err == nil && intPort >= 0 && intPort <= 65535 {
				thesePorts = append(thesePorts, intPort)
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
			if each[0] == 48 { // 48 is 0 in decimal
				return false
			}
			n, _ := strconv.Atoi(each)
			if n > 255 {
				return false
			}
		}
	}
	return true
}

func hostnameToIP(hostname string) string {
	ips, _ := net.LookupIP(hostname)
	if len(ips) > 0 {
		return ips[0].String()
	}
	return ""
}

func handleOutput() {
	var (
		startOutput    []func()
		continueOutput []func(g.Output)
		endOutput      []func()
	)

	activeEnders.Add(1)
	if value, ok := g.Args["oA"]; ok {
		activeEnders.Add(2)
		if value == "-" {
			fmt.Fprint(os.Stderr, "Cannot display multiple output types to stdout.\nQUITTING!\n")
			os.Exit(1)
		} else {
			g.XmlFilename = value + ".xml"
			g.GrepFilename = value + ".gnmap"
			g.Args["oN"] = value + ".nmap"
		}
		startOutput = []func(){o.StartXML, o.StartGrep, o.StartNmap}
		continueOutput = []func(g.Output){o.ContinueXML, o.ContinueGrep, o.ContinueNmap}
		endOutput = []func(){o.EndXML, o.EndGrep, o.EndNmap}
	} else if value, ok := g.Args["oX"]; ok {
		startOutput = []func(){o.StartXML}
		continueOutput = []func(g.Output){o.ContinueXML}
		endOutput = []func(){o.EndXML}
		g.XmlFilename = value
	} else if value, ok := g.Args["oG"]; ok {
		startOutput = []func(){o.StartGrep}
		continueOutput = []func(g.Output){o.ContinueGrep}
		endOutput = []func(){o.EndGrep}
		g.GrepFilename = value
	} else {
		startOutput = []func(){o.StartNmap}
		continueOutput = []func(g.Output){o.ContinueNmap}
		endOutput = []func(){o.EndNmap}
	}
	for _, function := range startOutput {
		function()
	}
	for output := range outputChannel {
		for _, function := range continueOutput {
			function(output)
		}
		activeOutputs.Done()
	}
	for _, function := range endOutput {
		function()
		activeEnders.Done()
	}
}

func scanner() {
	threads := make(chan bool, 3)
	g.ScanStartTime = time.Now()
	for target := range targetsChannel {
		threads <- true
		go func() {
			processScanObject(target)
			activeScans.Done()
			<-threads
		}()
	}
	g.ScanEndTime = time.Now()
}

func createScanObjects(object string) {
	activeScans.Add(1)
	var oneObject scanObject
	oneObject.Ports = g.PortList
	if isIPv4(object) {
		oneObject.IP = object
		targetsChannel <- oneObject
	} else if isHostname(object) {
		ip := hostnameToIP(object)
		if ip != "" {
			oneObject.IP = ip
			oneObject.Hostname = object
			targetsChannel <- oneObject
		} else {
			activeScans.Done()
		}
	} else if isIPv4(strings.Split(object, "/")[0]) {
		targetsChannel <- oneObject
	} else if isAddressRange(object) {
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
		if len(filteredPorts) == 0 {
			return
		}
	} else {
		filteredPorts = data.Ports
	}
	output.Ports = Correlate(filteredPorts, data.Cpes)
	output.Start = scanStarted
	output.End = time.Now()
	g.Increment(1)
	activeOutputs.Add(1)
	outputChannel <- output
}

func Init() {
	args, extra, invalid := ParseArgs()
	if invalid {
		os.Exit(1)
	}
	g.Args = args
	json.Unmarshal(db.NmapSigs, &Probes)
	json.Unmarshal(db.NmapTable, &Table)
	go scanner()
	go handleOutput()
	g.PortList = getPorts()
	if value, ok := g.Args["iL"]; ok {
		file, err := os.Open(value)
		if err != nil {
			os.Exit(1)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			createScanObjects(scanner.Text())
		}

		if err := scanner.Err(); err != nil {
			os.Exit(1)
		}
	} else {
		var activeObjects sync.WaitGroup
		threads := make(chan bool, 3)
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
	}
	activeScans.Wait()
	close(targetsChannel)
	activeOutputs.Wait()
	close(outputChannel)
	activeEnders.Wait()
}
