#!/usr/bin/env bash
# tune-nic.sh -- NIC tuning for high-speed packet capture.
# Usage: tune-nic.sh <interface>

set -euo pipefail

IFACE="${1:?Usage: $0 <interface>}"

echo "Tuning NIC: ${IFACE}"

# Increase RX/TX ring buffer to maximum supported values.
ethtool -G "${IFACE}" rx 4096 tx 4096 2>/dev/null || echo "WARN: failed to set ring buffer size"

# Set RSS queue count to match available CPU cores.
NCPU=$(nproc)
ethtool -L "${IFACE}" combined "${NCPU}" 2>/dev/null || echo "WARN: failed to set RSS queues"

# Disable flow control to avoid back-pressure stalls.
ethtool -A "${IFACE}" rx off tx off 2>/dev/null || echo "WARN: failed to disable flow control"

# Disable hardware offloads so the kernel sees full packets.
ethtool -K "${IFACE}" gro off lro off tso off gso off 2>/dev/null || echo "WARN: failed to disable offloads"

# Increase socket receive buffer and network backlog.
sysctl -w net.core.rmem_max=134217728        # 128 MiB
sysctl -w net.core.rmem_default=16777216      # 16 MiB
sysctl -w net.core.netdev_max_backlog=50000

echo "NIC tuning complete for ${IFACE}"
