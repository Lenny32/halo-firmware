# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial>=3.5"]
# ///
"""
Capture a wired Halo Dev Kit's console UART (115200 8N1) with a timestamp on
every line, to stdout or appended to a file. Unlike fetch_logs.py this needs
no BLE link and no FS log backend, so it keeps logging across resets.

    uv run uart_console.py                      # autodetect, print
    uv run uart_console.py --out console.log    # append to a file
    uv run uart_console.py --port /dev/cu.usbserial-XXXX

The dev kit enumerates two USB serial ports: SE-UART (used by the SETOOLS
maintenance tool) and the console. Autodetect picks the one that is not the
SE-UART named in $SETOOLS_DIR/isp_config_data.cfg; pass --port if that
guess is wrong (the console is silent until the firmware logs something).
"""
import argparse
import glob
import os
import sys
import time

import serial


def se_uart_port():
    cfg = os.path.join(os.environ.get("SETOOLS_DIR", ""), "isp_config_data.cfg")
    try:
        with open(cfg) as f:
            for line in f:
                if line.startswith("comport"):
                    return line.split()[1]
    except OSError:
        pass
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    parser.add_argument("--port", help="console serial port (default: autodetect)")
    parser.add_argument("--baud", type=int, default=115200)
    parser.add_argument("--out", help="append to this file instead of stdout")
    args = parser.parse_args()

    port = args.port
    if port is None:
        se = se_uart_port()
        ports = [p for p in sorted(glob.glob("/dev/cu.usbserial-*") + glob.glob("/dev/ttyUSB*")) if p != se]
        if len(ports) != 1:
            sys.exit(f"can't pick a console port from {ports} (SE-UART: {se}); pass --port")
        port = ports[0]

    out = open(args.out, "a", buffering=1) if args.out else sys.stdout
    print(f"console: {port} @ {args.baud}", file=sys.stderr)
    s = serial.Serial(port, args.baud, timeout=0.5)
    line = b""
    while True:
        for b in s.read(4096):
            if b == 0x0A:
                text = line.decode(errors="replace").rstrip("\r")
                out.write(f"{time.strftime('%H:%M:%S')} {text}\n")
                out.flush()
                line = b""
            else:
                line += bytes([b])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
