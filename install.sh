#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY="bia-pain-bache/BPB-IP"
readonly INSTALL_DIR="/opt/bpb-ip"
readonly SERVICE_USER="bpb-ip"
readonly SERVICE_GROUP="bpb-ip"
readonly SYSTEMD_DIR="/etc/systemd/system"
readonly SERVICE_FILE="${SYSTEMD_DIR}/bpb-ip.service"
readonly RELEASE_URL="https://github.com/${REPOSITORY}/releases/latest/download"

fail() {
  printf 'Error: %s\n' "$*" >&2
  exit 1
}

prompt_value() {
  local prompt="$1"
  local variable="$2"
  local value=""
  [[ -r /dev/tty ]] || fail "An interactive terminal is required to configure Cloudflare."
  read -r -p "$prompt: " value < /dev/tty
  [[ -n "$value" ]] || fail "$prompt cannot be empty."
  printf -v "$variable" '%s' "$value"
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

if ! getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
  if command -v groupadd >/dev/null 2>&1; then
    groupadd --system "$SERVICE_GROUP"
  elif command -v addgroup >/dev/null 2>&1; then
    addgroup --system "$SERVICE_GROUP"
  else
    fail "Neither groupadd nor addgroup is available."
  fi
fi

if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  if command -v useradd >/dev/null 2>&1; then
    no_login="$(command -v nologin || printf '/bin/false')"
    useradd --system --gid "$SERVICE_GROUP" --home-dir "$INSTALL_DIR" --shell "$no_login" "$SERVICE_USER"
  elif command -v adduser >/dev/null 2>&1; then
    adduser --system --no-create-home --home "$INSTALL_DIR" --shell /bin/false \
      --ingroup "$SERVICE_GROUP" "$SERVICE_USER"
  else
    fail "Neither useradd nor adduser is available."
  fi
fi

install -d -m 0755 "$INSTALL_DIR"
install -d "$SYSTEMD_DIR"
install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "${INSTALL_DIR}/results"
touch /var/log/bpb-ip.log
chown "$SERVICE_USER":"$SERVICE_GROUP" /var/log/bpb-ip.log
chmod 0640 /var/log/bpb-ip.log
install -o root -g root -m 0755 "${temporary_dir}/package/bpb-ip" "${INSTALL_DIR}/bpb-ip"
if [[ ! -f "${INSTALL_DIR}/config.json" ]]; then
  install -o root -g "$SERVICE_GROUP" -m 0640 "${temporary_dir}/package/config.json" "${INSTALL_DIR}/config.json"
fi
if [[ ! -f "${INSTALL_DIR}/list.txt" ]]; then
  install -o root -g root -m 0644 /dev/null "${INSTALL_DIR}/list.txt"
fi

if ! grep -Eq '"zoneId"[[:space:]]*:[[:space:]]*"[^"]+"' "${INSTALL_DIR}/config.json" ||
   ! grep -Eq '"recordName"[[:space:]]*:[[:space:]]*"[^"]+"' "${INSTALL_DIR}/config.json" ||
   ! grep -Eq '"apiToken"[[:space:]]*:[[:space:]]*"[^"]+"' "${INSTALL_DIR}/config.json"; then
  prompt_value "Cloudflare zone ID" CLOUDFLARE_ZONE_ID
  prompt_value "Dedicated DNS hostname (for example proxy.example.com)" CLOUDFLARE_RECORD_NAME
  [[ "$CLOUDFLARE_RECORD_NAME" =~ ^([A-Za-z0-9][A-Za-z0-9-]*\.)+[A-Za-z0-9][A-Za-z0-9-]*$ ]] ||
    fail "Enter a valid fully-qualified DNS hostname."
  [[ -r /dev/tty ]] || fail "An interactive terminal is required to enter the API token."
  read -r -s -p "Cloudflare API token: " CLOUDFLARE_API_TOKEN < /dev/tty
  printf '\n' > /dev/tty
  [[ -n "$CLOUDFLARE_API_TOKEN" ]] || fail "Cloudflare API token cannot be empty."
  [[ "$CLOUDFLARE_API_TOKEN" != *$'\n'* && "$CLOUDFLARE_API_TOKEN" != *$'\r'* ]] ||
    fail "The API token must be a single line."
  printf '\nThis will manage only DNS-only A/AAAA records for %s in zone %s.\n' \
    "$CLOUDFLARE_RECORD_NAME" "$CLOUDFLARE_ZONE_ID"
  read -r -p "Continue? [y/N] " answer < /dev/tty
  [[ "$answer" == "y" || "$answer" == "Y" ]] || fail "Installation cancelled."
  printf '%s\n%s\n%s\n' "$CLOUDFLARE_ZONE_ID" "$CLOUDFLARE_RECORD_NAME" "$CLOUDFLARE_API_TOKEN" |
    "${INSTALL_DIR}/bpb-ip" --config "${INSTALL_DIR}/config.json" --configure-cloudflare
fi

chown root:"$SERVICE_GROUP" "${INSTALL_DIR}/config.json"
chmod 0640 "${INSTALL_DIR}/config.json"
install -o root -g root -m 0644 "${temporary_dir}/package/bpb-ip.service" "$SERVICE_FILE"
rm -f /etc/logrotate.d/bpb-ip

if [[ -f "${SYSTEMD_DIR}/bpb-ip.timer" ]]; then
  if systemctl is-active --quiet bpb-ip.timer; then
    systemctl stop bpb-ip.timer
  fi
  if systemctl is-enabled --quiet bpb-ip.timer 2>/dev/null; then
    systemctl disable bpb-ip.timer
  fi
  rm -f "${SYSTEMD_DIR}/bpb-ip.timer"
fi
rm -f /etc/bpb-ip/bpb-ip.env

systemctl daemon-reload
systemctl enable bpb-ip.service
systemctl restart bpb-ip.service
printf 'Installed bpb-ip (%s). The service scans immediately and follows scanInterval in config.json.\n' "$asset_arch"
printf 'Edit %s to change URL/domain sources. Logs: journalctl -u bpb-ip.service\n' "${INSTALL_DIR}/config.json"
printf 'Log file: /var/log/bpb-ip.log (kept without automatic rotation).\n'
