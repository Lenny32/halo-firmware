# S-0006 — hack.md

These four are source-level hardening items, not runtime exploits: there is no
device-side "run this against the glasses" step. Instead:

1. **Confirm presence** — run the check script from the repo root:

   ```bash
   security/S-0006/code/check_hardening.sh
   ```

   Each finding prints the offending file:line today.

2. **Understand the attach surface each one guards** (why they matter despite "Low"):

   - **L1 (`pairing_lvl = GAP_PAIRING_BOND_AUTH`)**: security metadata lies about how
     the bond was established. It is written by *unauthenticated* Just Works pairing
     (S-0001). Any future authorization check that trusts this field inherits
     a priv-esc bug with no attacker-visible signal. Verify on hardware with
     `btmon`: pair today and observe pairing completes with no MITM exchange, then
     read back the persisted pairing level (S-0005 dump → `keys` blob pairing_lvl
     byte) — it claims AUTH.
   - **L2 (NC auto-true)**: only exploitable *after* the S-0001 fix raises the IO
     capability — i.e. it turns the security fix into a potential no-op. Test during
     S-0001 verification: with Passkey Display enabled, a Numeric Comparison initiated
     by a test central (btlejack/btlejuice crafted pairing request with matching IO
     caps) must fail unless confirmed on-device.
   - **L3 (`11:22:33` fallback)**: needs an SE failure, which you can't force on
     healthy hardware — correct to fix by code inspection + unit-level fault
     injection (mock `se_system_get_eui_extension` to return zeros in a test build;
     two such builds must then show *distinct* addresses).
   - **L4 (`#ifdef MCU_BOOT`)**: pure build verification — compile an MCUBOOT app
     image, then:

     ```bash
     grep -n "MCU_BOOT" modules/halo/src/ble_connection.c
     # L4 present := '#ifdef MCU_BOOT' (no CONFIG_ prefix) at the addr[4]=58 block
     ```

3. **After patching**, the check script must exit 0. Re-run it in CI on every
   BLE-stack change.
