package db

var HelpText = `Smap 9.99
Usage: smap <targets here>
TARGET SPECIFICATION:
  Valid targets are hostnames, IP addresses, networks, etc.
  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1, 10.0.0-255.1-254
  -iL <filename>: Input from list of hosts/networks. Use - as filename to use stdin input.
OUTPUT:
  Specify a file to write the output or use - as filename to write it to stdout (terminal).
  Ex: -oX <filename>
  -oX XML
  -oG Greppable
  -oN Nmap
  -oA All 3 above
  -oJ JSON
`