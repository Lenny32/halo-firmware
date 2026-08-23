#!/usr/bin/env bash
# S-0006 regression gate: exits non-zero while any bundled anti-pattern is present.
# Run from the repo root:   security/S-0006/code/check_hardening.sh
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null || echo .)"

fail=0

chk() {
    local id="$1" desc="$2" pat="$3" file="$4"
    if grep -n "$pat" "$file" >/dev/null 2>&1; then
        echo "[FAIL] $id: $desc"
        grep -n "$pat" "$file" | sed 's/^/         /'
        fail=1
    else
        echo "[ok]   $id: $desc"
    fi
}

SEC=modules/halo/src/ble_security.c
CONN=modules/halo/src/ble_connection.c

chk L1 "pairing_lvl hardcoded AUTH for Just Works bonds" \
      "GAP_PAIRING_BOND_AUTH" "$SEC"

chk L2 "Numeric Compare auto-accepted (must need confirmation)" \
      "gapc_pairing_numeric_compare_rsp(conidx, true)" "$CONN"

chk L3 "SE-failure fallback installs fixed address suffix 0x11 0x22 0x33" \
      "eui48\[3\] = 0x11" "$CONN"

chk L4 "mis-gated '#ifdef MCU_BOOT' (elsewhere: CONFIG_MCUBOOT)" \
      "^#ifdef MCU_BOOT" "$CONN"

if [ "$fail" -ne 0 ]; then
    echo
    echo "S-0006 hardening issues present — see security/S-0006/ticket.md"
    exit 1
fi
echo
echo "S-0006 clear."
