#!/usr/bin/env bash
set -Eeuo pipefail

cat <<'BANNER'
 _____ _____ _____
| __  |  _  | __  |
| __ -|   __| __ -|
|_____|__|  |_____| BPB IP
BANNER

readonly REPOSITORY="bia-pain-bache/BPB-IP"
readonly INSTALL_DIR="/opt/bpb-ip"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly SERVICE_FILE="${SYSTEMD_DIR}/bpb-ip.service"
readonly RELEASE_URL="https://github.com/${REPOSITORY}/releases/latest/download"

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

install_download_dependencies() {
  local packages=()
  command -v curl >/dev/null 2>&1 || packages+=(curl)
  command -v sha256sum >/dev/null 2>&1 || packages+=(coreutils)
  command -v unzip >/dev/null 2>&1 || packages+=(unzip)
  if ((${#packages[@]} == 0)); then
    return 0
  fi

  printf 'Installing required packages: %s\n' "${packages[*]}"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y --no-install-recommends "${packages[@]}"
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y "${packages[@]}"
  elif command -v yum >/dev/null 2>&1; then
    yum install -y "${packages[@]}"
  elif command -v apk >/dev/null 2>&1; then
    apk add --no-cache "${packages[@]}"
  elif command -v zypper >/dev/null 2>&1; then
    zypper --non-interactive install "${packages[@]}"
  elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm --needed "${packages[@]}"
  else
    fail "Cannot install missing dependencies automatically: no supported package manager found."
  fi

  command -v curl >/dev/null 2>&1 || fail "curl installation failed."
  command -v sha256sum >/dev/null 2>&1 || fail "coreutils (sha256sum) installation failed."
  command -v unzip >/dev/null 2>&1 || fail "unzip installation failed."
}

[[ "${EUID}" -eq 0 ]] || fail "Run as root, for example: curl -fsSL https://github.com/${REPOSITORY}/releases/latest/download/install.sh | sudo bash"
install_download_dependencies
command -v systemctl >/dev/null 2>&1 || fail "This installer requires systemd."
[[ -d /run/systemd/system ]] || fail "systemd is not running on this host."

machine="$(uname -m)"
case "$machine" in
  x86_64|amd64) asset_arch="amd64" ;;
  i386|i486|i586|i686|x86) asset_arch="386" ;;
  armv5*) asset_arch="armv5" ;;
  armv6*) asset_arch="armv6" ;;
  armv7*|armv8l) asset_arch="armv7" ;;
  aarch64|arm64) asset_arch="arm64" ;;
  loongarch64) asset_arch="loong64" ;;
  mips64el|mips64le) asset_arch="mips64le" ;;
  mips64) asset_arch="mips64" ;;
  mipsel|mipsle) asset_arch="mipsle" ;;
  mips) asset_arch="mips" ;;
  ppc64le|powerpc64le) asset_arch="ppc64le" ;;
  ppc64|powerpc64) asset_arch="ppc64" ;;
  riscv64) asset_arch="riscv64" ;;
  s390x) asset_arch="s390x" ;;
  *) fail "Unsupported Linux architecture: ${machine}" ;;
esac

asset="bpb-ip-linux-${asset_arch}.zip"
temporary_dir="$(mktemp -d)"
trap 'rm -rf "$temporary_dir"' EXIT

printf 'Downloading %s from the latest GitHub release...\n' "$asset"
for release_file in "$asset" SHA256SUMS; do
  curl --fail --location --silent --show-error \
    "${RELEASE_URL}/${release_file}" -o "${temporary_dir}/${release_file}"
done

verify_checksum() {
  local filename="$1"
  local expected_hash
  local actual_hash
  expected_hash="$(awk -v name="$filename" '$2 == name { print $1 }' "${temporary_dir}/SHA256SUMS")"
  actual_hash="$(sha256sum "${temporary_dir}/${filename}" | awk '{ print $1 }')"
  [[ -n "$expected_hash" && "$actual_hash" == "$expected_hash" ]] ||
    fail "Checksum verification failed for ${filename}."
}
verify_checksum "$asset"
unzip -tq "${temporary_dir}/${asset}" >/dev/null ||
  fail "Archive validation failed for ${asset}."
mkdir "${temporary_dir}/package"
unzip -q "${temporary_dir}/${asset}" bpb-ip bpb-ip.service config.json \
  -d "${temporary_dir}/package" ||
  fail "Could not extract required files from ${asset}."
for package_file in bpb-ip bpb-ip.service config.json; do
  [[ -f "${temporary_dir}/package/${package_file}" ]] ||
    fail "Release archive is missing ${package_file}."
done

if systemctl cat bpb-ip.service >/dev/null 2>&1; then
  [[ -d "$INSTALL_DIR" && -f "${INSTALL_DIR}/config.json" ]] ||
    fail "The bpb-ip service exists, but its installation or config is missing from ${INSTALL_DIR}."
  install -o root -g root -m 0755 "${temporary_dir}/package/bpb-ip" "${INSTALL_DIR}/bpb-ip"
  install -o root -g root -m 0644 "${temporary_dir}/package/bpb-ip.service" "$SERVICE_FILE"
  systemctl daemon-reload
  if systemctl is-active --quiet bpb-ip.service; then
    systemctl restart bpb-ip.service
    printf 'Updated bpb-ip (%s) and restarted the service. Existing configuration was preserved.\n' "$asset_arch"
  else
    printf 'Updated bpb-ip (%s). Existing configuration was preserved; the service remains stopped.\n' "$asset_arch"
    printf 'Configure sources and start the service with: systemctl start bpb-ip.service\n'
  fi
  printf 'Logs: journalctl -u bpb-ip.service\n'
  exit 0
fi

install -d -m 0755 "$INSTALL_DIR"
install -d "$SYSTEMD_DIR"
install -d -m 0755 "${INSTALL_DIR}/results"
touch /var/log/bpb-ip.log
chmod 0640 /var/log/bpb-ip.log
install -o root -g root -m 0755 "${temporary_dir}/package/bpb-ip" "${INSTALL_DIR}/bpb-ip"
if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
  install -o root -g root -m 0600 "${temporary_dir}/package/config.json" "${INSTALL_DIR}/config.json"
fi
if [[ ! -f "${INSTALL_DIR}/list.txt" ]]; then
  install -o root -g root -m 0644 /dev/null "${INSTALL_DIR}/list.txt"
fi

chown root:root "${INSTALL_DIR}/config.json"
chmod 0600 "${INSTALL_DIR}/config.json"
install -o root -g root -m 0644 "${temporary_dir}/package/bpb-ip.service" "$SERVICE_FILE"

systemctl daemon-reload
printf 'Installed bpb-ip (%s). The service is not enabled or started until you configure it.\n' "$asset_arch"
printf 'Edit %s and populate sourceUrls, sourceDomains, and Cloudflare settings, or add endpoints to %s.\n' \
  "${INSTALL_DIR}/config.json" "${INSTALL_DIR}/list.txt"
printf 'Enable and start the service with: systemctl enable --now bpb-ip.service\n'
printf 'Logs: journalctl -u bpb-ip.service\n'
printf 'Log file: /var/log/bpb-ip.log.\n'
