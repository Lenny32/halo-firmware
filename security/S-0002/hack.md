# How to exploit S-0002 — overwrite a bonded peer's slot by spoofing its address

Goal: clone a bonded peer's identity address on the attack adapter, connect, and
re-pair. On vulnerable firmware the victim's LTK/IRK in that slot get replaced with the
attacker's. Verify afterwards that the victim can no longer reconnect.

## Preconditions

- Halo with **at least one bond whose identity address is public or static-random**.
  Easiest setup: pair a Linux/macOS laptop as the "victim" first (it will typically
  bond with its public address). iPhones (RPA) do NOT reproduce this ticket.
- The victim's identity address value. Get it from:
  - `btmon` on the Halo side (dev kit UART logs / shell), or
  - a raw BLE sniffer capture of the victim's CONNECT_IND to the Halo, or
  - on the victim Linux laptop itself: `btmgmt info | grep addr` — address type
    "public" or "static" is what lands in the Halo slot.
- Attack host with **two BLE adapters** strongly recommended (`hci0` = attack with
  spoofed address, `hci1` = clean control adapter). One adapter works if you restore
  its address at the end.
- Adapter whose address can be rewritten: most CSR8510 clones (`bdaddr`), Intel via
  `btmgmt public-addr` (firmware-dependent), Blowstacks/nRF via private address config
  is NOT what you want — you need the *identity* address rewritten. Check yours:

  ```bash
  sudo btmgmt -i hci0 public-addr AA:BB:CC:DD:EE:FF   # exits 0 = supported
  sudo btmgmt -i hci0 info | grep "current settings"
  ```

- Victim device **off or out of range** while attacking (single-connection peripheral;
  first come, first served).

## Steps

```bash
cd security/S-0002/code
VICTIM=AA:BB:CC:DD:EE:FF      # bonded peer's identity address (public/static)
HALO=C0:59:94:11:22:33        # glasses' static address (see S-0004: never changes)

sudo uv run takeover.py --victim $VICTIM --halo $HALO --adapter hci0
```

What the script does (each step maps to a firmware line — cited in its output):

1. Powers down `hci0`, rewrites its identity address to `--victim`, powers up
   (`btmgmt public-addr`, fallback `bdaddr`).
2. Connects to the Halo. Firmware: `halo_ble_sec_on_connection_req()` →
   `find_slot_by_addr()` **memcmp match** → `active_slot = victim_slot` →
   `known_device_connected()` issues an LTK encryption request we cannot answer.
3. **Immediately** sends an SMP Pairing Request on the unencrypted link, racing the
   encryption failure. Firmware: `on_gapc_pairing_req()` **auto-accepts**
   (`ble_connection.c:1148`). BlueZ on our side does this from its own policy; the
   script also forces `Pair()` explicitly. Retries up to N times — the race is
   winnable within a few attempts (encryption-failure disconnect takes ~100 ms+;
   our pairing request is in the first GATT round-trip).
4. On `on_paired`, firmware takes the "known peer refresh" branch
   (`ble_security.c:626-633`) and **persists our keys over the victim's slot**.
5. Disconnects cleanly, restores the adapter address, reconnects once **as the
   attacker** — encrypted link comes up with the new keys, Lua REPL ping proves
   privileged access.

## Expected (vulnerable)

```
[*] Adapter hci0 identity address set to AA:BB:CC:DD:EE:FF
[*] Attempt 1: connect to C0:59:94:11:22:33
[*] Forcing immediate SMP pairing (racing encryption failure)
[+] Pairing completed
[+] Victim slot overwritten: active-slot keys replaced with ours, persisted
[+] Attacker reconnect: encrypted, REPL ping ok: fw 25.x.y
[VULNERABLE] Bond slot takeover succeeded; victim AA:BB:CC:DD:EE:FF is locked out
```

Then verify the damage:

- Try to connect with the real victim laptop → Halo requests encryption → victim
  answers with its (now stale) LTK → `Encrypt Failed` → disconnect, **bond kept** →
  victim permanently unable to reconnect (log line "Encryption failed ... bond kept"
  on the Halo console confirms you hit `on_encrypt_failed`, not a factory issue).

## Expected (patched)

Every attempt fails at step 3 — pairing rejected, connection dropped — and the victim
laptop still reconnects fine at the end (slot intact).

## Troubleshooting the race

- `Adapter does not support public-addr change`: use a CSR8510 clone with `bdaddr`,
  or make the *victim* the spoofable one (pair the victim on a laptop whose address you
  control anyway and replay that scenario).
- `Connection dropped before pairing request`: the encryption-failure timer won.
  Decrease latency: dedicate the adapter, `btmgmt power off` all other adapters, run
  with `--attempts 50`. Or patch locally to use raw D-Bus `dev.Pair()` in the
  InterfacesAdded callback — fastest possible.
- Never leave the spoofed address on your adapter: the script restores it in `finally`.

## Cleanup after testing

The glasses now trust your attack host. Factory reset (hold button 15 s) or pair 5
fresh devices to LRU-evict your slot before returning the unit to normal use.
