# How to exploit S-0001 — silent Just Works bonding + full pairing MITM

Goal: prove that pairing a phone to Halo gives **no authentication**, by (A) silently
bonding an attacker host during the pairing window, and optionally (B) relaying a full
victim pairing through that host (active MITM).

## Preconditions

- Halo powered on. Production firmware, `REQUIRE_PAIRING=y` (default `prj.conf`) — the
  attack works *because of*, not despite, the production config.
- You can put the glasses in pairing mode: **hold the button 5 s** → pairing LED state,
  window open 60 s (`CONFIG_HALO_BLE_PAIRING_WINDOW_SEC`).
- Attack host: Linux + BlueZ, Python 3.10+, `uv`.
- Scenario B only: second BLE adapter (e.g. `hci1`) or an nRF52 dongle.

## Scenario A — one-liner silent bond (minimal, proves no-auth pairing)

This is the attacker endpoint of the MITM: if this works with *zero user verification on
either side*, then nothing about the pairing distinguishes your laptop from the victim's
phone.

```bash
cd security/S-0001/code
uv run silent_bond.py --name "Halo"
```

The script: scans for the Halo advertisement, waits for the pairing window (or
zero-bond state), connects, issues `Pair()` over BlueZ, then proves privileged access by
pinging the Lua REPL after encryption comes up.

**Pairing window trigger**: hold the Halo button 5 s when prompted by the script.

### Expected (vulnerable)

```
[+] Found Halo C0:59:94:xx:xx:xx name="Halo 9A"
[*] Hold the Halo button for 5 s now (pairing window)...
[+] Connected
[+] Pairing (Just Works)
[+] Pair succeeded — bonded with NO user verification on either side
[+] Link encrypted; REPL ping: fw 25.x.y
[VULNERABLE] Unauthenticated bond acquired; attacker host now trusted permanently
```

Also confirm in `btmon` (run in parallel): `SMP Pairing Request/Response` shows
`AuthReq: Bonding, MITM protection not requested` and the association proceeds with
Just Works (`Confirm value` exchanged but never displayed/typed anywhere).

### Expected (patched)

Pairing aborts with `SMP Pairing Failed (Confirm Value failed / passkey entry failed)`
on the MITM-shaped attempt, or requires the HUD passkey — script exits
`PAIRING PROTECTED`.

## Scenario B — full MITM of a victim's pairing (impact demonstration)

Relayed victim flow: victim's phone pairs with what it thinks is the Halo; attacker
forwards everything. Fastest reliable route is **btlejuice** (public tool) on two
adapters, with this repo's script driving the Halo-facing side.

1. Hold the Halo button 5 s (window opens).
2. Terminal 1 (Halo-facing, real adapter `hci0`): run `silent_bond.py` — bonds the
   attacker to the glasses via Just Works (as in A).
3. Terminal 2: stand up the fake-Halo peripheral with btlejuice:

   ```bash
   docker run --net=host --privileged -ti btlejuice/btlejuice
   # inside: proxy with hci1 as the victim-facing interface
   ```

   Or with `btlejuice` npm install: `sudo btlejuice -u <webui-ip> -w` then select the
   "Halo xx" target and let it clone the advertisement using the victim-facing adapter.

4. Victim opens nRF Connect / the Halo app, sees "Halo", taps **Pair** → iOS/Android
   shows **no passkey dialog** (Just Works both legs) → pairing completes.
5. Use the web UI to watch/record/replay the victim's GATT traffic (ANCS setup, Lua
   REPL writes — full app traffic) while your log shows leg 2 terminating on the real
   glasses.

### Expected (vulnerable)

- No passkey/number shown on *any* device at any point.
- Both pairings complete; traffic flows through the attacker.
- The attacker's bond from step 2 **persists after the victim leaves** → recurring
  privileged access whenever back in range.

### Expected (patched)

Step 4 demands a 6-digit passkey displayed on the glasses' HUD; btlejuice cannot
supply it; MITM chain breaks; victim's app shows pairing failure instead.

## Notes / constraints

- "Zero bonds exist" (factory-new glasses, or after factory reset) is permanently
  pairable — the easiest variant of Scenario A, no button press needed. Also true for
  a *user's first ever pairing* — the highest-value intercept point.
- AS MITM you must keep both links alive simultaneously; keep the intermediary
  physically between phone and glasses and stay within ~10 m of both.
- The bond you steal in Scenario A counts toward `CONFIG_HALO_BLE_MAX_BONDS` (5).
  Cleanup after testing: factory reset (15 s hold) or evict via 5 fresh bonds, else the
  glasses stay trusting your laptop.
