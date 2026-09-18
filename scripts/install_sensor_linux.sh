#!/usr/bin/env bash
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root." >&2
  exit 1
fi

: "${FADS_ENROLLMENT_KEY:?Set FADS_ENROLLMENT_KEY for one-time enrollment}"
: "${FADS_COUNTRY:?Set FADS_COUNTRY to the protected asset two-letter country code}"
: "${FADS_REGION:?Set FADS_REGION to the protected asset region}"
FADS_ASSET_ID="${FADS_ASSET_ID:-$(hostname)}"
FADS_REF="${FADS_VERSION_REF:-e5c47d6f9521cc1ad574ee3face37044d148fccb}"
BASE="/opt/918-fads"
STATE="/etc/918"
TOKEN_FILE="${STATE}/fads.asset"

install -d -m 0755 "${BASE}"
install -d -m 0700 "${STATE}"

python3 -m venv "${BASE}/venv"
"${BASE}/venv/bin/python" -m pip install --upgrade pip
"${BASE}/venv/bin/python" -m pip install "git+https://github.com/918Tech/FADS-GATE.git@${FADS_REF}"

FADS_ENROLLMENT_KEY="${FADS_ENROLLMENT_KEY}" "${BASE}/venv/bin/fads-enroll-asset" --asset-id "${FADS_ASSET_ID}" --country "${FADS_COUNTRY}" --region "${FADS_REGION}" --platform linux --output "${TOKEN_FILE}"
chmod 0600 "${TOKEN_FILE}"

cat > /etc/systemd/system/918-fads-universal-sensor.service <<EOF
[Unit]
Description=918 Technologies FADS Universal Sensor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${BASE}/venv/bin/fads-universal-sensor --token-file ${TOKEN_FILE} --interval 60
Restart=always
RestartSec=10
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadOnlyPaths=/
ReadWritePaths=${STATE}
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now 918-fads-universal-sensor.service
unset FADS_ENROLLMENT_KEY
echo "918 FADS Universal Sensor installed and running."
systemctl --no-pager --full status 918-fads-universal-sensor.service || true
