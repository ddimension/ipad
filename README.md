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

**Documentation:**

- [docs/sgp22-emulation.md](docs/sgp22-emulation.md): how an SGP.22 consumer
  eUICC is used for SGP.32. What ipad emulates, the state per EID, the
  device key and how the eIM learns it, the SGP.32 → SGP.22 mapping,
  downloads, notifications, and what the card guarantees versus ipad's
  state;
- [docs/howto.md](docs/howto.md): ipad on its own. Build, try it against the
  simulated card, provision, export, poll, recover a lost key,
  troubleshooting;
- on a router: wwand-ipa's [how-to](https://github.com/ddimension/wwand-ipa/blob/main/docs/howto.md)
  and [operation guide](https://github.com/ddimension/wwand-ipa/blob/main/docs/operation.md).

## What it implements

Section numbers are SGP.32 v1.3.

| Area | Status |
|---|---|
| eIM Package retrieval (3.1.1.1) | `GetEimPackage`, including `notifyStateChange` + cause and rPLMN |
| eUICC Packages (3.3.1) | every PSMO (enable ± rollback, disable, delete, listProfileInfo, getRAT, configureImmediateEnable, set/unsetFallbackAttribute, setDefaultDpAddress) and eCO (add/update/delete/listEim); results acknowledged and removed |
| Profile Rollback (3.3.2) | when the connection does not come back after a profile change, the rollback's result replaces the package's |
| IPA/eUICC data (2.11.1.2) | every tag in the tag list, search criteria, `incorrectTagList` |
| Indirect download (3.2.3.2) | through the eIM, BPP loaded in the SGP.22 segments, CancelSession (3.2.3.3); `eimDownloadDataHandling` (4.1): an empty trigger is followed, the activation code stays with the eIM and `smdpAddress` is never sent (2.11.1.3, 5.14.1) |
| Direct download (3.2.3.1) | the host's ES9+ client (lpac) downloads; ipad reports the PIR as `ProfileDownloadTriggerResult` (step 13), then has the host send it to the SM-DP+ over ES9+ (step 14), retried on later runs until the SM-DP+ has it |
| Notifications (3.7) | delivered through `ESipa.HandleNotification`, removed once the eIM has them; one the eIM refuses stays and, on an emulated card, is offered again after a backoff (1 h doubling to 1 day); a direct download's PIR over ES9+ through the host (3.7 [2a]) |
| Connectivity parameters (5.9.24) | APN, PDP type and credentials of the enabled profile, handed to the host. An emulated SGP.22 card has none. |
| Transport (6.1.1) | HTTPS with the ASN.1 binding. The trust anchor comes from the eIM configuration (`trustedPublicKeyDataTls`: a pinned key, the eIM's certificate or its CA), otherwise the system CAs; an anchor that cannot be used is logged. SNI carries host names only (no IP literals, no trailing dot, RFC 6066 3). The response reader is strict about framing (RFC 9112: chunked as the final coding, no Content-Length beside it) and stops where the framing ends, even when a load balancer keeps the connection open. An IP-literal URL (`https://[::1]/…`) needs an iPAddress SAN; hosts like `127.1` or `0x7f.1` are refused. |

Every message ipad sends or receives in the test suite is decoded with the
eIM's own ASN.1 types and re-encoded byte-identically (`tools/esipa-check.sh`).

## Usage

The card is reached through the host over stdin/stdout (`src/host.h`):
APDUs in lpac's stdio protocol, plus four events that only the host can
handle (`profile_changed`, `download`, `notify`, `connectivity`) and two that tell it
what ipad did: `info` at the start of a run and for `info` (EID, backend,
device key, and for an emulated card the binding and the counter), and
`summary` at the end of `poll` and `provision` (exit code, packages,
acknowledged results, binding, and the last error when the run failed).

```
ipad [options] poll | provision <file> | export <file> | connectivity | notify | info | reset <EID>|all
```

- `provision` stores the eIM configuration. It takes the file `eimctl
  eim-config` writes, or an `eim-ipad-provision/1` bundle (`eimctl ipad
  bundle`, eIM decision D-69): configuration and device key in one file. The
  key replaces the generated one (0600), the file is deleted once stored, and
  the next `poll` binds the card first (`POST /ipad/v1/bind`, same host and
  TLS as ESipa): 204/409 bound, 403 refused — `poll` then exits 4 until an
  operator acts —, 429/5xx/no answer tried again on the next poll; 400/413
  are errors, the binding stays pending. A 429 with `Retry-After` in
  seconds (at most a day) is honoured: until then `poll` does not ask the
  eIM and ends as a retry (exit 1, `binding deferred` in the summary). `info` reports `bind` (none,
  pending, done, refused) and the eIM `counter`.
  - The reader takes the bundle as the eIM writes it and nothing else: one
    flat object, string and integer values without escapes, each field
    once, nothing after it, at most 16 KiB. An expired bundle, another
    format, a field twice, a negative counter are refused, and a refused
    bundle is left in place (it holds the key: delete it or retry).
  - The binding is sent only while the emulation's counter is the bundle's
    start counter, which the eIM requires; the file is the one `export`
    writes, for the eIM the IPA polls.
- `reset <EID>` forgets that card's eIM configuration and state; the device
  key and the binding stay, because every card in the state directory shares
  them. `reset all` forgets every card's, the device key and the binding, so
  a new bundle or a re-key starts from nothing. A bare `reset` is refused.
  No card is needed.
- `export` writes the `eim-euicc-import/1` file for the eIM
  (`eimctl euicc import`).
- `poll` runs everything the eIM has queued.

See `ipad -h` for the options.

### A lost device key

The eIM refuses a second import of a card unless it is told to replace the key
(`eimctl euicc import --replace-key`), and even then only when the file's
`counter` is **above** the counter the eIM holds for the card
(`replace_ipa_key` refuses `counter <= stored`): a replayed old file, or old
packages, must not be accepted again. `export` writes the counter the
emulation holds, so the emulation has to be started above the eIM's counter
before exporting — and the import has to come before the first poll: the
eIM's next package would carry N+1, which the emulation refuses, and would
leave the eIM's counter at N+1, above the file's:

```sh
eimctl euicc show <EID>                        # eIM: its counter N
ipad -s DIR reset all                          # device: key, every state, binding gone
eimctl eim-config cfg.der --fqdn … --counter <N+1>
ipad -s DIR provision cfg.der
ipad -s DIR export device.json
eimctl euicc import device.json --replace-key  # eIM, before any poll
ipad -s DIR poll                               # the eIM's next package is N+2
```

A lost `<EID>.state` with the key intact needs no re-key: provision a
configuration at the eIM's counter N itself (the next package is N+1).
`reset all` clears the whole state directory — every card on the device. The
cases (key unreadable, key gone, state gone) are in
[docs/howto.md](docs/howto.md#recover-from-a-lost-device-key).

## Build and test

```sh
tools/fetch-mbedtls.sh            # mbedTLS 3.6.7 LTS, checksum-verified
cmake -S . -B build && cmake --build build
(cd build && ctest)               # unit + procedure tests (simulated card, scripted eIM);
                                  # cli: provision/bind/reset of a bundle against a stand-in eIM
tools/esipa-check.sh              # every ESipa message against the eIM's ASN.1 types
tools/e2e-eim.sh ../../eim        # end to end against a real eIM (needs its postgres)
```

`tools/counterproof.sh` removes a guard, rebuilds and runs a test, to show
that the test fails without it.

## License

GPL-2.0-only. mbedTLS is Apache-2.0 OR GPL-2.0-or-later.
