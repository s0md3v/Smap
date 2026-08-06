<h1 align="center">
  <br>
  <a href="https://github.com/dylan1501/Smap"><img src="/static/smap-logo.png" alt="Smap logo"></a>
</h1>

<h4 align="center">passive Nmap like scanner built with shodan.io</h4>

<p align="center">
  <a href="https://github.com/dylan1501/Smap/releases">
    <img src="https://img.shields.io/github/release/dylan1501/Smap.svg?label=version">
  </a>
  <a href="https://github.com/dylan1501/Smap/releases">
    <img src="https://img.shields.io/github/downloads/dylan1501/Smap/total">
  </a>
  <a href="https://github.com/dylan1501/Smap/issues?q=is%3Aissue+is%3Aclosed">
      <img src="https://img.shields.io/github/issues-closed-raw/dylan1501/Smap?color=dark-green&label=issues%20fixed">
  </a>
  <a href="https://github.com/dylan1501/Smap/actions/workflows/go.yml">
      <img src="https://img.shields.io/github/actions/workflow/status/dylan1501/Smap/go.yml?branch=main&label=tests">
  </a>
</p>

<p align="center"><img src="/static/smap-demo.png" alt="Smap demo"></p>

---

Smap is a port scanner built with shodan.io's free API. It takes same command line arguments as Nmap and produces the same output which makes it a drop-in replacament for Nmap.

## Features
- Scans 200 hosts per second
- Doesn't require any account/api key
- Vulnerability detection
- Supports nmap's output formats
- Service and version fingerprinting
- Makes no contact to the targets
- Optional active verification with nmap

## Installation
### Binaries
You can download a pre-built binary from [here](https://github.com/dylan1501/Smap/releases) and use it right away.

### Manual
`go install -v github.com/dylan1501/smap/cmd/smap@latest`

Confused or something not working? For more detailed instructions, [click here](https://github.com/dylan1501/Smap/wiki/FAQ#how-do-i-install-smap)
### AUR pacakge
Smap is available on AUR as [smap-git](https://aur.archlinux.org/packages/smap-git) (builds from source) and [smap-bin](https://aur.archlinux.org/packages/smap-bin) (pre-built binary).

### Homebrew/Mac
Smap is also avaible on [Homebrew](https://formulae.brew.sh/formula/smap).

```
brew update
brew install smap
```

## Usage
Smap takes the same arguments as Nmap but options other than `-p`, `-h`, `-o*`, `-iL`, `--concurrency`, `--append-output`, `--active`, `--shodan-key`, `--config` are ignored. If you are unfamiliar with Nmap, here's how to use Smap.

### Specifying targets
```
smap 127.0.0.1 127.0.0.2
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
1.1.1.1-20      // IPv4 range
```

### Output
Smap supports 6 output formats which can be used with the `-o* ` as follows
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
oJ    // json
```

> Note: Since Nmap doesn't scan/display vulnerabilities and tags, that data is not available in nmap's formats. Use `-oS` to view that info.

### Specifying ports
Smap scans these [~4000 ports](https://api.shodan.io/shodan/ports) by default. If you want to display results for certain ports, use the `-p` option.

```
smap -p21-30,80,443 -iL targets.txt
```

### Active verification
Use `--active` to make Smap verify passive hits with your local `nmap`. It will first collect passive hits from InternetDB and then run `nmap` only on the hosts and ports it found open.

```
smap --active -Pn -sV --version-light 1.1.1.1
```

This mode forwards nmap-compatible flags to `nmap` and keeps Smap-specific ones for itself. `-oS`, `-oJ` and `-oP` are supported with `--active` only when they write to a file, not stdout.

If you use NSE scripts, `-oJ` and `-oX` keep the structured script data.

This can save time if passive data is good enough for your use case.

### Controlling concurrency
Smap defaults to `3` workers to avoid hitting Shodan too aggressively. You can change that with `--concurrency`.

```
smap --concurrency 5 -iL targets.txt
```

### Using the full Shodan API
By default Smap queries Shodan's free [InternetDB](https://internetdb.shodan.io) endpoint, which needs no account. If you have a [Shodan API key](https://account.shodan.io/), Smap can query the full [Host API](https://developer.shodan.io/api#host-information) at `api.shodan.io` instead, which returns richer data (org/ISP/geo info, per-service banners, etc.) at the cost of query credits.

Smap looks for a key in this order:
1. `--shodan-key <key>`
2. `$SHODAN_API_KEY` environment variable
3. A JSON config file

```
smap --shodan-key YOUR_API_KEY example.com
```

**Config file**

Copy [`configs/smap.example.json`](configs/smap.example.json) to your config directory and fill in your key:

```json
{
  "shodan_api_key": "YOUR_SHODAN_API_KEY_HERE"
}
```

Without `--config`, Smap looks for `config.json` in the OS-standard per-user config directory:

| OS | Default path |
|----|---------------|
| Windows | `%AppData%\smap\config.json` |
| Linux | `~/.config/smap/config.json` |
| macOS | `~/Library/Application Support/smap/config.json` |

Use `--config <path>` (or the `$SMAP_CONFIG` environment variable) to point at a different file.

## Considerations
Since Smap simply fetches existent port data from shodan.io, it is super fast but there's more to it. You should use Smap if:

#### You want
- vulnerability detection
- a super fast port scanner
- no connections to be made to the targets

#### You are okay with
- not being able to scan IPv6 addresses
- results being up to 7 days old
- some rare unreliable software detection when not using `--active`

> Note: if you use `--active`, Smap will run `nmap` against the target and make active connections.
