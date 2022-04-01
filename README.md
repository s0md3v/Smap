<h1 align="center">
  <br>
  <a href="https://github.com/s0md3v/smap"><img src="/static/smap-logo.png" alt="Smap logo"></a>
</h1>

<h4 align="center">passive Nmap like scanner built with shodan.io</h4>

<p align="center">
  <a href="https://github.com/s0md3v/Smap/releases">
    <img src="https://img.shields.io/github/release/s0md3v/Smap.svg?label=version">
  </a>
  <a href="https://github.com/s0md3v/Smap/releases">
    <img src="https://img.shields.io/github/downloads/s0md3v/Smap/total">
  </a>
  <a href="https://github.com/s0md3v/SMap/issues?q=is%3Aissue+is%3Aclosed">
      <img src="https://img.shields.io/github/issues-closed-raw/s0md3v/Smap?color=dark-green&label=issues%20fixed">
  </a>
  <a href="https://travis-ci.com/s0md3v/Smap">
      <img src="https://img.shields.io/travis/com/s0md3v/Smap.svg?color=dark-green&label=tests">
  </a>
</p>

<p align="center"><img src="/static/smap-demo.png" alt="Smap demo"></p>

---

Smap is a replica of Nmap which uses shodan.io's free API for port scanning. It takes same command line arguments as Nmap and produces the same output which makes it a drop-in replacement for Nmap.

## Features
- Scans 200 hosts per second
- Vulnerability detection
- Supports all nmap's output formats
- Service and version fingerprinting
- Makes no contact to the targets
- Doesn't require any account/api key

## Installation
```
go install -v github.com/s0md3v/smap/cmd/smap@latest
```

## Usage
Smap takes the same arguments as Nmap but options other than `-p`, `-h`, `-o*`, `-iL` are ignored. If you are unfamiliar with Nmap, here's how to use Smap.

### Specifying targets
```
smap -sV 127.0.0.1 127.0.0.2
```
You can also use a list of targets, seperated by newlines.
```
smap -iL targets.txt
```
**Supported formats**

```
1.1.1.1         // IPv4 address
example.com     // hostname
178.23.56.0/8   // CIDR
```

### Output
SMap supports Nmap's 3 major output formats

```
smap example.com -oX output.xml
```
If you want to print the output to terminal, use hyphen (`-`) as filename.

**Supported formats**
```
oX    // nmap's xml format
oG    // nmap's greppable format
oN    // nmap's default format
oA    // output in all 3 formats above at once
oP    // IP:PORT pairs seperated by newlines
oS    // custom smap format
```

> Note: Since Nmap doesn't scan/display vulnerabilities and tags, that data is not available in nmap's formats. Use `-oS` to view that info.

### Specifying ports
SMap scans these [1237 ports](https://api.shodan.io/shodan/ports) by default. If you want to display results for certain ports, use the `-p` option.

```
smap -p21-30,80,443 -iL targets.txt
```

## Considerations
Since Smap simply fetches existent port data from shodan.io, it is super fast but there's more to it. You should use Smap if:

#### You want
- vulnerability detection
- a super fast port scanner
- results for most common ports (top 1237)
- no connections to be made to the targets

#### You are okay with
- not being able to scan IPv6 addresses
- results being up to 7 days old
- a few false negatives
