#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
install_root=${FERROCRATE_INSTALL_ROOT:-/usr/local/bin}
config_root=${FERROCRATE_CONFIG_ROOT:-/etc/ferrocrate}
state_root=${FERROCRATE_STATE_ROOT:-/var/lib/ferrocrate}
runtime_group=${FERROCRATE_RUNTIME_GROUP:-ferrocrate}

for binary in ferrocrate ferro-mgr ferro-agent ferro-netd; do
  if [[ ! -x "$install_root/$binary" ]]; then
    echo "missing installed binary: $install_root/$binary" >&2
    exit 1
  fi
done

getent group "$runtime_group" >/dev/null || groupadd --system "$runtime_group"
for user in ferro-mgr ferro-agent; do
  id -u "$user" >/dev/null 2>&1 || useradd --system --gid "$runtime_group" --home-dir /nonexistent --shell /usr/sbin/nologin "$user"
done

install -d -m 0750 -o ferro-mgr -g "$runtime_group" "$state_root"
install -d -m 0770 -o ferro-agent -g "$runtime_group" /run/ferrocrate
install -d -m 0750 -o root -g "$runtime_group" "$config_root"
for unit in ferrocrate ferro-mgr ferro-agent ferro-netd; do
  install -m 0644 "$repo_root/packaging/systemd/$unit.service" "/etc/systemd/system/$unit.service"
done

for env_file in manager.env agent.env netd.env; do
  if [[ ! -e "$config_root/$env_file" ]]; then
    install -m 0640 -o root -g "$runtime_group" /dev/null "$config_root/$env_file"
    echo "created $config_root/$env_file; populate it before starting services"
  fi
done

systemctl daemon-reload
echo "units installed; populate $config_root/{manager,agent,netd}.env then enable the required services"
