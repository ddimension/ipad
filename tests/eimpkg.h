/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef IPAD_EIMPKG_H
#define IPAD_EIMPKG_H
#include <stdbool.h>
#include "der.h"
#include "crypto.h"

/* EimConfigurationData { 80 id, 81 fqdn, 83 counter, [84 -1], A5 { A0 key } } */
void eimpkg_cfg(dbuf *b, const char *id, int64_t counter, crypto_key *k, bool want_token);
/* the same with a chosen FQDN (NULL: none) and trustedEimPkTls (NULL: none) */
void eimpkg_cfg_ex(dbuf *b, const char *id, const char *fqdn, int64_t counter, crypto_key *k,
                   bool want_token, crypto_key *tls);
/* BF51 { 30 {80 id, 5A eid, 81 counter, 82 txid, A0|A1 ops}, 5F37 sig } */
void eimpkg_package(dbuf *b, const char *id, const uint8_t *eid, int64_t counter, uint32_t list,
                    const dbuf *ops, crypto_key *signer, int64_t token, bool corrupt);
/* one PSMO carrying an ICCID (enable A3 / disable A4 / delete A5), rollbackFlag */
void eimpkg_op(dbuf *ops, uint32_t tag, const char *iccid, bool rollback);
#endif
