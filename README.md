# BPB Proxy IP Scanner

A Go application for Linux VPSs. It collects Proxy IPs from different sources, deduplicates, scans them and updates a specified Cloudflare domain's A/AAAA records.  
A manually uploaded file, URLs and domains are supported as sources.

## Install or Update

The installer detects the CPU architecture, installs dependencies if missing, downloads and verifies the matching release, then installs and enables the service without starting it on a fresh install.  
Running it again updates the binary and service unit without changing your existing configuration; a running service is restarted, while a stopped service stays stopped.

```sh
curl -fsSL https://github.com/bia-pain-bache/BPB-IP/releases/latest/download/install.sh | sudo bash
```

After a fresh install, configure `/opt/bpb-ip/config.json` with at least one source URL or domain, along with the Cloudflare zone ID, hostname, and API token. Alternatively, add port 443 Proxy IPs to `/opt/bpb-ip/list.txt`.  
Create a Cloudflare API token with `DNS: Edit` permission scoped to that zone.

Then start the service:

```sh
sudoedit /opt/bpb-ip/config.json
sudo systemctl enable --now bpb-ip.service
```

- The service updates only A/AAAA records at the configured hostname, sets them DNS-only, and leaves other record types untouched.
- A failed or empty source is logged while other inputs are used.
- If no proxy IPs are collected from sources, scanning is skipped.
- Before updating DNS, the service counts zone records outside the managed hostname and uses the remaining slots (up to 200) for the fastest healthy IPs.
- If none pass, the run fails without modifying DNS records.
- Each scan writes a `results-YYYY-MM-DD--HH-mm-ss.csv` file to `/opt/bpb-ip/results/`, with `IP`, `Status`, `Speed`, and `Error` columns. Speed is shown in MiB/s for passed IPs only; passed IPs are sorted fastest-first, failed IPs follow in scan order, and removed DNS IPs are listed last as `deleted`.
- The installer supports Linux `386`, `amd64`, `ARMv5/6/7`, `arm64`, `loong64`, `MIPS/MIPSLE`, `MIPS64/MIPS64LE`, `ppc64`, `ppc64le`, `riscv64` and `s390x`.

> [!WARNING]
> It requires systemd; non-systemd hosts need an equivalent service manager configured manually.

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
