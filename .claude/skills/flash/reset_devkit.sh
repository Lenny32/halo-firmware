#!/bin/sh
# Hard-reset a wired Halo Dev Kit over SE-UART with the Alif SETOOLS
# maintenance tool (Device Control -> Device reset), for a dev kit that has
# stopped responding, without a power cycle.
#
# Usage: reset_devkit.sh [setools-dir]
#   setools-dir defaults to $SETOOLS_DIR. It must hold the `maintenance`
#   binary and an isp_config_data.cfg naming the SE-UART port (set it once
#   with `./maintenance -d`).
set -e

SETOOLS_DIR=${1:-$SETOOLS_DIR}
if [ -z "$SETOOLS_DIR" ] || [ ! -x "$SETOOLS_DIR/maintenance" ]; then
	echo "usage: $0 <setools-dir> (or set SETOOLS_DIR); no maintenance tool found" >&2
	exit 2
fi

cd "$SETOOLS_DIR"
# Menu: 1 Device Control -> 3 Device reset, then Enter twice to back out
out=$(printf '1\n3\n\n\n' | ./maintenance 2>&1)
if echo "$out" | grep -q "Device connected"; then
	echo "Reset sent over $(awk '/^comport/ {print $2}' isp_config_data.cfg)"
else
	echo "$out" >&2
	echo "Could not reach the SE over SE-UART" >&2
	exit 1
fi
