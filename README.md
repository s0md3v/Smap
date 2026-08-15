<h4 align="center">
  <a href="https://github.com/s0md3v/smap"><img src="/static/smap-logo.png" alt="Smap logo"></a>
</h4>

<h4 align="center">nmap alternative powered by shodan.io</h4>

<p align="center"><img src="/static/smap-demo.png" alt="Smap demo"></p>

Smap is a passive port scanner built with shodan.io's free API. It takes the same command line arguments as Nmap and produces the same output, which makes it a drop-in replacement for Nmap.

## Features
- Scans 200 hosts per second
- Doesn't require any account/api key
- Vulnerability detection
- Supports nmap's output formats
- Service and version fingerprinting
- Makes no contact to the targets in passive mode
- Optional nmap acceleration using Shodan's reported ports

## Installation
### Binaries
You can download a pre-built binary from [here](https://github.com/s0md3v/Smap/releases) and use it right away.

### Manual
`go install -v github.com/s0md3v/smap/cmd/smap@latest`

Confused or something not working? For more detailed instructions, [click here](https://github.com/s0md3v/Smap/wiki/FAQ#how-do-i-install-smap)
### AUR package
Smap is available on AUR as [smap-git](https://aur.archlinux.org/packages/smap-git) (builds from source) and [smap-bin](https://aur.archlinux.org/packages/smap-bin) (pre-built binary).

### Homebrew/Mac
Smap is also available on [Homebrew](https://formulae.brew.sh/formula/smap).

```
brew update
brew install smap
```

## Usage
Smap takes the same arguments as Nmap, but options other than `-p`, `-h`, `-V`, `-o*`, `-iL`, `--concurrency`, and `--append-output` are ignored in passive mode. Use `--nmap` to pass Nmap options to a real Nmap scan after passive port discovery. If you are unfamiliar with Nmap, here's how to use Smap.

### Specifying targets
```
smap 127.0.0.1 127.0.0.2
```
You can also use a list of targets, separated by newlines.
```
smap -iL targets.txt
```
**Supported formats**

```
1.1.1.1         // IPv4 address
example.com     // hostname
178.23.56.0/8   // CIDR
1.1.1.1-20      // IPv4 range
```

### Output
Smap supports 7 output formats which can be used with `-o*` as follows:
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
oP    // IP:PORT pairs separated by newlines
oS    // custom smap format
oJ    // json
```

> Note: Since Nmap doesn't scan/display vulnerabilities and tags, that data is not available in nmap's formats. Use `-oS` to view that info.

### Specifying ports
Smap scans these [~4000 ports](https://api.shodan.io/shodan/ports) by default. If you want to display results for certain ports, use the `-p` option.

```
smap -p21-30,80,443 -iL targets.txt
```

### Nmap acceleration
Use `--nmap` to narrow a scan with your local `nmap`. Smap first collects the union of ports reported by Shodan and then runs Nmap once against the original targets with that smaller port range.

```
smap --nmap -Pn -sV --version-light 1.1.1.1
```

Except for `--nmap` and `--concurrency`, the supplied arguments are passed to Nmap. Smap replaces the port range with the Shodan candidates; if you specify `-p`, it first limits the candidates to that range. Nmap handles the scan and output directly, so its options and output formats behave normally. Host-only operations such as `-sL` and `-sn` are passed through without passive port discovery.

Smap's custom output formats are passive-mode features; with `--nmap`, output options have their normal Nmap meanings. If Shodan reports no candidate ports, Nmap is not run.

This can save time if passive data is good enough for your use case.

### Controlling concurrency
Smap defaults to `3` workers to avoid hitting Shodan too aggressively. You can change that with `--concurrency`.

```
smap --concurrency 5 -iL targets.txt
```

## Considerations
Since Smap simply fetches existent port data from shodan.io, it is super fast but there's more to it. You should use Smap if:

#### You want
- vulnerability detection
- a super fast port scanner
- no connections to be made to the targets

#### You are okay with
- not being able to scan IPv6 addresses
- results being up to 7 days old
- some rare unreliable software detection in passive mode

> Note: if you use `--nmap`, Smap will run `nmap` against the target and make active connections. Because Shodan's data can be stale or incomplete, using it as a port filter can miss open ports.
