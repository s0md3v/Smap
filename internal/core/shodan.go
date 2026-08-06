package core

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	g "github.com/s0md3v/smap/internal/global"
)

var client = &http.Client{
	Transport: &http.Transport{
		Dial: (&net.Dialer{
			Timeout: 8 * time.Second,
		}).Dial,
		TLSHandshakeTimeout:   3 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	},
}

var (
	internetDBURL = "https://internetdb.shodan.io/"
	shodanHostURL = "https://api.shodan.io/shodan/host/"
)

// shodanHostData mirrors one entry of the "data" array returned by
// GET https://api.shodan.io/shodan/host/{ip} - see
// https://developer.shodan.io/api
type shodanHostData struct {
	Cpe []string `json:"cpe"`
}

// shodanHostResponse mirrors the subset of the full Shodan Host API response
// (https://developer.shodan.io/api#host-information) that smap needs.
type shodanHostResponse struct {
	IP        string           `json:"ip_str"`
	Ports     []int            `json:"ports"`
	Hostnames []string         `json:"hostnames"`
	Tags      []string         `json:"tags"`
	Vulns     []string         `json:"vulns"`
	Data      []shodanHostData `json:"data"`
}

// Query fetches host data for ip. If a Shodan API key is configured (via
// --shodan-key, $SHODAN_API_KEY or the config file, see ConfigFilePath), it
// queries the full Shodan API at api.shodan.io. Otherwise it falls back to
// Shodan's free InternetDB endpoint, which needs no key. Either way the
// returned bytes are shaped like the respone struct.
func Query(ip string) []byte {
	if apiKey := shodanAPIKey(); apiKey != "" {
		return queryShodanAPI(ip, apiKey)
	}
	return queryInternetDB(ip)
}

func doRequest(reqURL string) ([]byte, int, error) {
	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", "smap/"+g.Version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	return content, resp.StatusCode, nil
}

func queryInternetDB(ip string) []byte {
	content, status, err := doRequest(internetDBURL + ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: InternetDB request failed for %s: %v\n", ip, err)
		return []byte{}
	}
	if status != http.StatusOK {
		message := strings.TrimSpace(string(content))
		if message != "" {
			fmt.Fprintf(os.Stderr, "Warning: InternetDB returned HTTP %d for %s: %s\n", status, ip, message)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: InternetDB returned HTTP %d for %s.\n", status, ip)
		}
		return []byte{}
	}
	if strings.HasPrefix(string(content), `{"error":`) {
		fmt.Fprintf(os.Stderr, "Warning: InternetDB returned an error response for %s.\n", ip)
		return []byte{}
	}

	return content
}

func queryShodanAPI(ip string, apiKey string) []byte {
	reqURL, err := url.Parse(shodanHostURL + ip)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to build Shodan API request for %s: %v\n", ip, err)
		return []byte{}
	}
	query := reqURL.Query()
	query.Set("key", apiKey)
	reqURL.RawQuery = query.Encode()

	content, status, err := doRequest(reqURL.String())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Shodan API request failed for %s: %v\n", ip, err)
		return []byte{}
	}
	if status != http.StatusOK {
		message := strings.TrimSpace(string(content))
		if message != "" {
			fmt.Fprintf(os.Stderr, "Warning: Shodan API returned HTTP %d for %s: %s\n", status, ip, message)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: Shodan API returned HTTP %d for %s.\n", status, ip)
		}
		return []byte{}
	}

	var host shodanHostResponse
	if err := json.Unmarshal(content, &host); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Shodan API returned an unexpected response for %s: %v\n", ip, err)
		return []byte{}
	}

	seenCpes := map[string]bool{}
	cpes := []string{}
	for _, entry := range host.Data {
		for _, cpe := range entry.Cpe {
			if !seenCpes[cpe] {
				seenCpes[cpe] = true
				cpes = append(cpes, cpe)
			}
		}
	}

	normalized, err := json.Marshal(respone{
		Cpes:      cpes,
		Hostnames: host.Hostnames,
		IP:        host.IP,
		Ports:     host.Ports,
		Tags:      host.Tags,
		Vulns:     host.Vulns,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to normalize Shodan API response for %s: %v\n", ip, err)
		return []byte{}
	}
	return normalized
}
