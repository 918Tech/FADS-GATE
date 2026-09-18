#!/usr/bin/env bash
set -euo pipefail
if [ "$(id -u)" -ne 0 ]; then
  echo "Run as root." >&2
  exit 1
fi
systemctl disable --now 918-fads-universal-sensor.service 2>/dev/null || true
rm -f /etc/systemd/system/918-fads-universal-sensor.service
systemctl daemon-reload
rm -rf /opt/918-fads
echo "Sensor binaries removed. Enrollment token remains at /etc/918/fads.asset unless you delete it explicitly."
