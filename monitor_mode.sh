#!/usr/bin/env bash
# monitor-mode.sh
# Usage:
#   sudo ./monitor-mode.sh start [iface]
#   sudo ./monitor-mode.sh stop  [monitor_iface]
#
# - start: finds a wireless interface if none provided, kills interfering processes, and enables monitor mode.
# - stop: disables the specified monitor interface (or tries to detect it) and restores networking.

set -euo pipefail

# Helpers
die() { echo "ERROR: $*" >&2; exit 1; }
require_root() { [ "$(id -u)" -eq 0 ] || die "This script must be run as root (sudo)."; }

# Find a wireless (physical) interface via `iw dev`
find_wireless_iface() {
  local ifs
  ifs=$(iw dev 2>/dev/null | awk '/Interface/ {print $2}')
  if [ -z "$ifs" ]; then
    die "No wireless interfaces found (no output from 'iw dev')."
  fi
  # prefer first interface that is not already monitor (type check)
  for i in $ifs; do
    # check if this interface is managed type
    local typ
    typ=$(iw dev "$i" info 2>/dev/null | awk '/type/ {print $2; exit}')
    if [ "$typ" != "monitor" ]; then
      echo "$i"
      return 0
    fi
  done
  # fallback to first interface found
  echo "$ifs" | awk '{print $1}'
}

# Determine currently existing monitor interfaces
list_monitor_ifaces() {
  iw dev 2>/dev/null | awk '/Interface/ {iface=$2} /type monitor/ {print iface}'
}

action=${1:-}
arg=${2:-}

require_root

if [ -z "$action" ]; then
  die "No action provided. Usage: sudo $0 start [iface] | stop [monitor_iface]"
fi

case "$action" in
  start)
    iface=${arg:-$(find_wireless_iface)}
    echo "Selected wireless interface: $iface"

    # Kill processes that commonly interfere with airmon-ng
    if command -v airmon-ng >/dev/null 2>&1; then
      echo "Running: airmon-ng check kill"
      airmon-ng check kill || true
      echo "Starting monitor mode on $iface with airmon-ng..."
      airmon-ng start "$iface"
      echo "Waiting briefly for interface to appear..."
      sleep 1
      mons=$(list_monitor_ifaces)
      if [ -z "$mons" ]; then
        echo "No monitor interface detected via 'iw dev'. If airmon-ng created a monitor interface with a different naming scheme, list of interfaces:"
        ip link show
        exit 0
      fi
      echo "Monitor interfaces now present:"
      echo "$mons"
      exit 0
    else
      # fallback using ip/iw: create a monitor interface named <iface>-mon
      mon="${iface}mon"
      echo "airmon-ng not found. Creating monitor interface '$mon' with ip/iw..."
      ip link set "$iface" down
      iw "$iface" set type monitor || die "Failed to set type monitor on $iface"
      ip link set "$iface" up
      echo "Interface $iface moved to monitor mode (may be visible as the same name). Verify with 'iw dev'."
      exit 0
    fi
    ;;
  stop)
    monitor_if=${arg:-}
    if [ -z "$monitor_if" ]; then
      # try to detect monitor iface(s)
      mons=$(list_monitor_ifaces)
      if [ -z "$mons" ]; then
        die "No monitor interface supplied and none detected."
      fi
      # if multiple, pick first
      monitor_if=$(echo "$mons" | head -n1)
      echo "Auto-detected monitor interface: $monitor_if"
    fi

    if command -v airmon-ng >/dev/null 2>&1; then
      echo "Stopping monitor mode with airmon-ng on $monitor_if..."
      airmon-ng stop "$monitor_if" || true
      echo "Attempting to restart network services (NetworkManager, wpa_supplicant)..."
      systemctl restart NetworkManager || true
      echo "Done."
      exit 0
    else
      # fallback: set the underlying interface back to managed
      echo "airmon-ng not found. Attempting to set interface type back to managed."
      # try to find underlying phy interface for this monitor interface
      # This is best-effort; user may need to reboot or re-run network manager
      ip link set "$monitor_if" down || true
      iw "$monitor_if" set type managed || true
      ip link set "$monitor_if" up || true
      echo "Requested stop completed (best-effort). Verify with 'iw dev' and restart NetworkManager if required."
      exit 0
    fi
    ;;
  *)
    die "Unknown action: $action. Use start or stop."
    ;;
esac
