# ipad — an SGP.32 v1.3 IoT Profile Assistant

`ipad` fetches and runs what an eIM (the fleet's eSIM manager) queues for a
device, following GSMA SGP.32 v1.3. It works with two kinds of card:

- **An IoT eUICC.** The card implements SGP.32 itself and signs its own
  results. ipad passes the ES10 functions through.
- **An ordinary SGP.22 consumer eUICC.** ipad emulates the SGP.32 functions
  the card lacks: eIM configuration, replay counters, stored results,
  rollback, fallback and immediate enable. It keeps that state in a file per
  EID and signs the results with a **device key**. The eIM learns that key
  from an import file (`ipad export`) and then verifies every result, as it
  would for an IoT eUICC.

C99, mbedTLS built in statically, no other dependencies. Written for
embedded Linux (OpenWrt), where [wwand](https://github.com/ddimension/wwand)
runs it as a plugin.

## What it implements

Section numbers are SGP.32 v1.3.

| Area | Status |
|---|---|
| eIM Package retrieval (3.1.1.1) | `GetEimPackage`, including `notifyStateChange` + cause and rPLMN |
| eUICC Packages (3.3.1) | every PSMO (enable ± rollback, disable, delete, listProfileInfo, getRAT, configureImmediateEnable, set/unsetFallbackAttribute, setDefaultDpAddress) and eCO (add/update/delete/listEim); results acknowledged and removed |
| Profile Rollback (3.3.2) | when the connection does not come back after a profile change, the rollback's result replaces the package's |
| IPA/eUICC data (2.11.1.2) | every tag in the tag list, search criteria, `incorrectTagList` |
| Indirect download (3.2.3.2) | through the eIM, BPP loaded in the SGP.22 segments, CancelSession (3.2.3.3) |
| Direct download (3.2.3.1) | the host's ES9+ client (lpac) downloads; ipad reports the PIR as `ProfileDownloadTriggerResult` |
| Notifications (3.7) | delivered through `ESipa.HandleNotification`, removed once the eIM has them |
| Connectivity parameters (5.9.24) | APN, PDP type and credentials of the enabled profile, handed to the host. An emulated SGP.22 card has none. |
| Transport (6.1.1) | HTTPS with the ASN.1 binding. The trust anchor comes from the eIM configuration (`trustedPublicKeyDataTls`: a pinned key, the eIM's certificate or its CA), otherwise the system CAs. |

Every message ipad sends or receives in the test suite is decoded with the
eIM's own ASN.1 types and re-encoded byte-identically (`tools/esipa-check.sh`).

## Usage

The card is reached through the host over stdin/stdout (`src/host.h`):
APDUs in lpac's stdio protocol, plus three events that only the host can
handle (`profile_changed`, `download`, `connectivity`).

```
ipad [options] poll | provision <file> | export <file> | connectivity | notify | info
```

- `provision` stores the eIM configuration. It takes the file `eimctl
  eim-config` writes.
- `export` writes the `eim-euicc-import/1` file for the eIM
  (`eimctl euicc import`).
- `poll` runs everything the eIM has queued.

See `ipad -h` for the options.

## Build and test

```sh
tools/fetch-mbedtls.sh            # mbedTLS 3.6.7 LTS, checksum-verified
cmake -S . -B build && cmake --build build
(cd build && ctest)               # unit + procedure tests (simulated card, scripted eIM)
tools/esipa-check.sh              # every ESipa message against the eIM's ASN.1 types
tools/e2e-eim.sh ../../eim        # end to end against a real eIM (needs its postgres)
```

`tools/counterproof.sh` removes a guard, rebuilds and runs a test, to show
that the test fails without it.

## License

GPL-2.0-only. mbedTLS is Apache-2.0 OR GPL-2.0-or-later.
