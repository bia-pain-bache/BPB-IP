# BPB Proxy IP Scanner

A Go application for Linux VPSs. It collects Proxy IPs from different sources, deduplicates, scans them and updates a specified Cloudflare domain's A/AAAA records.  
A manually uploaded file, URLs and domains are supported as sources.

## Install or Update

The installer detects the CPU architecture, installs dependencies if missing, downloads and verifies the matching binary, installs `bpb-ip` service and starts an initial scan.  
Running the installer again gets the scanner updated while preserving configs.

```sh
curl -fsSL https://github.com/bia-pain-bache/BPB-IP/releases/latest/download/install.sh | sudo bash
```

On first install, it interactively asks for the Cloudflare zone ID, dedicated DNS hostname, and API token.
Create a Cloudflare API token with **DNS: Edit** permission scoped to that zone.

- The service updates only A/AAAA records at the configured hostname, sets them DNS-only, and leaves other record types untouched.
- A failed or empty source is logged while other inputs are used.
- If no proxy IPs are collected from sources, scanning is skipped.
- If none pass, the run fails without modifying DNS records.
- The installer supports Linux `386`, `amd64`, `ARMv5/6/7`, `arm64`, `loong64`, `MIPS/MIPSLE`, `MIPS64/MIPS64LE`, `ppc64`, `ppc64le`, `riscv64`, and `s390x`.

> [!WARNING]
> It requires systemd; non-systemd hosts need an equivalent service manager configured manually.

## Configuration

Configuration file is accessible at `/opt/bpb-ip/config.json`.  
Changes are applied by manually restarting service or waiting for the next scan interval to be automatically reloaded by the scanner itself. Please do not touch any fields except `scanInterval`, `sourceUrls` and `sourceDomains` unless you are a pro user.

## Status and Logs

```sh
sudo systemctl status bpb-ip.service
sudo journalctl -u bpb-ip.service
sudo tail -f /var/log/bpb-ip.log
```

## Development

For local development with Go 1.27.3 or newer:

```sh
go test ./...
go vet ./...
go build .
```

Special thanks to [NiREvil](https://github.com/NiREvil)
