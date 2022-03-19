package core

import (
	"net"
	"time"

	"io/ioutil"
	"net/http"
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

func Query(ip string) []byte {
	url := "https://internetdb.shodan.io/" + ip
	req, err := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return []byte{}
	}
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return []byte{}
	}
	req.Close = true
	defer resp.Body.Close()
	return content
}
