package core

import (
	"fmt"
	"io"
	"net"
	"net/http"
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

var internetDBURL = "https://internetdb.shodan.io/"

func Query(ip string) []byte {
	url := internetDBURL + ip
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return []byte{}
	}
	req.Header.Set("User-Agent", "smap/"+g.Version)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: InternetDB request failed for %s: %v\n", ip, err)
		return []byte{}
	}
	defer resp.Body.Close()
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		return []byte{}
	}
	if resp.StatusCode != http.StatusOK {
		message := strings.TrimSpace(string(content))
		if message != "" {
			fmt.Fprintf(os.Stderr, "Warning: InternetDB returned HTTP %d for %s: %s\n", resp.StatusCode, ip, message)
		} else {
			fmt.Fprintf(os.Stderr, "Warning: InternetDB returned HTTP %d for %s.\n", resp.StatusCode, ip)
		}
		return []byte{}
	}
	if strings.HasPrefix(string(content), `{"error":`) {
		fmt.Fprintf(os.Stderr, "Warning: InternetDB returned an error response for %s.\n", ip)
		return []byte{}
	}

	return content
}
