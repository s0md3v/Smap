package db

import (
  "fmt"
  g "github.com/s0md3v/smap/internal/global"
)

var HelpText = fmt.Sprintf(`Smap %s
Usage: smap <targets here>
TARGET SPECIFICATION:
  Valid targets are hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1
  -iL <filename>: Input from list of hosts/networks. Use - as filename to use stdin input.
OUTPUT:
  Specify a file to write the output or use - as filename to write it to stdout (terminal).
  Ex: -oX <filename>
  -oX XML
  -oG Greppable
  -oN Nmap
  -oA All 3 above
  -oJ JSON
  -oS Smap format
  -oP ip:port pairs
`, g.Version)