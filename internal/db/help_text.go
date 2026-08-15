package db

import (
	"fmt"
	g "github.com/s0md3v/smap/internal/global"
)

var HelpText = fmt.Sprintf(`Smap %s
Usage: smap <targets here>
TARGET SPECIFICATION:
  Valid targets are hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, 192.168.0.1, 192.168.0.0/24, 192.168.0.10-20
  -iL <filename>: Input from list of hosts/networks. Use - as filename to use stdin input.
  --nmap: Run Nmap against the original targets using Shodan's reported port union.
  --concurrency <n>: Number of workers for target expansion and queries. Default 3.
OUTPUT:
  Nmap's normal format is written to stdout by default.
  Specify a file to write the output or use - as filename to write it to stdout (terminal).
  Ex: -oX <filename>
  -oX XML
  -oG Greppable
  -oN Nmap
  -oA All 3 above
  -oJ JSON
  -oS Smap format
  -oP ip:port pairs
  --append-output: Append to output files instead of truncating them.
  Note: With --nmap, Nmap handles its output options and writes the output directly.
`, g.Version)
