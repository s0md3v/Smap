package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	g "github.com/s0md3v/smap/internal/global"
)

var openedXmlFile *os.File
var shodanPortList = "0,7,11,13,15,17,19-26,37-38,43,49,51,53,69-70,79-92,95-100,102,104,106,110-111,113,119,121,123,129,131,135,137,139,143,154,161,175,179-180,195,199,211,221-222,225,263-264,311,340,389,443-445,447-450,465,491,500,502-503,515,520,522-523,541,548,554-555,587,593,623,626,631,636,646,666,675,685,771-772,777,789,800-801,805-806,808,830,843,873,880,888,902,943,990,992-995,999-1000,1010,1012,1022-1029,1050,1063,1080,1099,1110-1111,1119,1167,1177,1194,1200,1234,1250,1290,1311,1344,1355,1366,1388,1400,1433-1434,1471,1494,1500,1515,1521,1554,1588,1599,1604,1650,1660,1723,1741,1777,1800,1820,1830,1833,1883,1900-1901,1911,1935,1947,1950-1951,1962,1981,1990-1991,2000-2003,2006,2008,2010,2012,2018,2020-2022,2030,2048-2070,2077,2079-2083,2086-2087,2095-2096,2100,2111,2121-2123,2126,2150,2152,2181,2200-2202,2211,2220-2223,2225,2232-2233,2250,2259,2266,2320,2323,2332,2345,2351-2352,2375-2376,2379,2382,2404,2443,2455,2480,2506,2525,2548-2563,2566-2570,2572,2598,2601-2602,2626,2628,2650,2701,2709,2761-2762,2806,2985,3000-3002,3005,3048-3063,3066-3121,3128-3129,3200,3211,3221,3260,3270,3283,3299,3306-3307,3310-3311,3333,3337,3352,3386,3388-3389,3391,3400-3410,3412,3443,3460,3479,3498,3503,3521-3524,3541-3542,3548-3552,3554-3563,3566-3570,3671,3689-3690,3702,3749,3780,3784,3790-3794,3838,3910,3922,3950-3954,4000-4002,4010,4022,4040,4042-4043,4063-4064,4070,4100,4117-4118,4157,4190,4200,4242-4243,4282,4321,4369,4430,4433,4443-4445,4482,4500,4505-4506,4523-4524,4545,4550,4567,4643,4646,4664,4700,4730,4734,4747,4782,4786,4800,4808,4840,4848,4911,4949,4999-5010,5025,5050,5060,5070,5080,5090,5094,5122,5150,5172,5190,5201,5209,5222,5269,5280,5321,5353,5357,5400,5431-5432,5443,5446,5454,5494,5500,5542,5552,5555,5560,5567-5569,5577,5590-5609,5632,5672-5673,5683-5684,5800-5801,5822,5853,5858,5900-5901,5906-5910,5938,5984-5986,6000-6010,6036,6080,6102,6161,6262,6264,6308,6352,6363,6379,6443,6464,6503,6510-6512,6543,6550,6560-6561,6565,6580-6581,6588,6590,6600-6603,6605,6622,6650,6662,6664,6666-6668,6697,6748,6789,6881,6887,6955,6969,6998,7000-7005,7010,7014,7070-7071,7080-7081,7090,7170-7171,7218,7401,7415,7433,7443-7445,7465,7474,7493,7500,7510,7535,7537,7547-7548,7634,7654,7657,7676,7700,7776-7779,7788,7887,7979,7998-8058,8060,8064,8066,8069,8071-8072,8080-8112,8118,8123,8126,8139-8140,8143,8159,8180-8182,8184,8190,8200,8222,8236-8239,8241,8243,8248-8249,8251-8252,8282,8291,8333-8334,8383,8401-8433,8442-8448,8500,8513,8545,8553-8554,8585-8586,8590,8602,8621-8623,8637,8649,8663,8666,8686,8688,8700,8733,8765-8767,8779,8782,8784,8787-8791,8800-8881,8885,8887-8891,8899,8935,8969,8988-8991,8993,8999-9051,9070,9080,9082,9084,9088-9111,9119,9136,9151,9160,9189,9191,9199-9222,9251,9295,9299-9311,9389,9418,9433,9443-9445,9500,9527,9530,9550,9595,9600,9606,9633,9663,9682,9690,9704,9743,9761,9765,9861,9869,9876,9898-9899,9943-9944,9950,9955,9966,9981,9988,9990-9994,9997-10001,10134,10243,10250,10443,10554,11112,11211,11300,12000,12345,13579,14147,14265,14344,16010,16464,16992-16993,17000,18081,18245,20000,20087,20256,20547,21025,21379,22222,23023,23424,25105,25565,27015-27017,27036,28015,28017,30718,32400,32764,33060,33338,37215,37777,41794,44818,47808,48899,49152-49153,50000,50050,50070,50100,51106,51235,52869,53413,54138,54984,55442-55443,55553-55554,60001,60129,62078,64738"

func StartXML() {
	if g.XmlFilename != "-" {
		openedXmlFile = OpenFile(g.XmlFilename)
	}
	portsLen := 1237
	portsStr := shodanPortList
	if value, ok := g.Args["p"]; ok {
		portsLen = len(g.PortList)
		portsStr = value
	}
	startstr := ConvertTime(g.ScanStartTime, "nmap-file")
	Write(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<!-- Nmap 9.99 scan initiated %s as: %s -->
<nmaprun scanner="nmap" args="%s" start="%d" startstr="%s" version="9.99" xmloutputversion="1.04">
<scaninfo type="connect" protocol="tcp" numservices="%d" services="%s"/>
<verbose level="0"/>
<debugging level="0"/>
`, startstr, GetCommand(), GetCommand(), g.ScanStartTime.Unix(), startstr, portsLen, portsStr), g.XmlFilename, openedXmlFile)
}

func portToXML(port g.Port, result g.Output) string {
	thisString := fmt.Sprintf(`<port protocol="%s" portid="%d"><state state="open" reason="syn-ack" reason_ttl="0"/>`, port.Protocol, port.Port)
	if port.Service != "" {
		thisString += fmt.Sprintf(`<service name="%s"`, port.Service)
		if port.Product != "" {
			thisString += fmt.Sprintf(` product="%s"`, port.Product)
		}
		if port.Version != "" {
			thisString += fmt.Sprintf(` version="%s"`, port.Version)
		}
		if result.OS.Port == port.Port {
			thisString += fmt.Sprintf(` ostype="%s" method="probed" conf="8">`, result.OS.Name)
		} else if strings.HasSuffix(port.Service, "?") {
			thisString += ` method="table" conf="3">`
		} else {
			thisString += ` method="probed" conf="8">`
		}
		for _, cpe := range port.Cpes {
			thisString += fmt.Sprintf(`<cpe>%s</cpe>`, cpe)
		}
		thisString += "</service>"
	}
	thisString += "</port>\n"
	return thisString
}

func ContinueXML(result g.Output) {
	thisOutput := ""
	thisOutput += fmt.Sprintf(`<host starttime="%d" endtime="%d"><status state="up" reason="syn-ack" reason_ttl="0"/>
<address addr="%s" addrtype="ipv4"/>
<hostnames>
`, result.Start.Unix(), result.End.Unix(), result.IP)
	for _, hostname := range result.Hostnames {
		thisOutput += fmt.Sprintf("<hostname name=\"%s\" type=\"PTR\"/>\n", hostname)
	}
	if result.UHostname != "" {
		thisOutput += fmt.Sprintf("<hostname name=\"%s\" type=\"user\"/>\n", result.UHostname)
	}
	thisOutput += "</hostnames>\n<ports>"
	for _, port := range result.Ports {
		thisOutput += portToXML(port, result)
	}
	thisOutput += "</ports>\n<times srtt=\"247120\" rttvar=\"185695\" to=\"989900\"/>\n</host>\n"
	Write(thisOutput, g.XmlFilename, openedXmlFile)
}

func EndXML() {
	timestr := ConvertTime(g.ScanEndTime, "nmap-file")
	elapsed := fmt.Sprintf("%.2f", time.Since(g.ScanStartTime).Seconds())
	Write(fmt.Sprintf(`<runstats><finished time="%d" timestr="%s" elapsed="%s" summary="Nmap done at %s; %d IP addresses (%d hosts up) scanned in %s seconds" exit="success"/><hosts up="%d" down="%d" total="%d"/>
</runstats>
</nmaprun>
`, g.ScanEndTime.Unix(), timestr, elapsed, timestr, g.TotalHosts, g.AliveHosts, elapsed, g.AliveHosts, g.TotalHosts-g.AliveHosts, g.TotalHosts), g.XmlFilename, openedXmlFile)
	defer openedXmlFile.Close()
}
