/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The eIM's provisioning bundle, `eim-ipad-provision/1` (eIM decision D-69):
 * one flat JSON object with the eIM configuration and the device key, issued
 * for a card whose EID is not known yet, and the self-binding that registers
 * the card on first contact (POST /ipad/v1/bind).
 *
 * The bundle is a SECRET: it carries an unencrypted private key. It is read,
 * stored where the key belongs (device.key, 0600) and deleted; nothing of it
 * is ever logged.
 */
#ifndef IPAD_BUNDLE_H
#define IPAD_BUNDLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>
#include "der.h"

#define BUNDLE_FORMAT "eim-ipad-provision/1"

typedef struct {
	char issuance_id[64];
	dbuf eim_config;        /* DER AddInitialEimRequest, as eimctl eim-config writes it */
	dbuf device_key;        /* PKCS#8 DER, unencrypted: zeroed by bundle_free */
	long long counter;      /* the start counter the eIM expects at binding */
	char expires_at[40];    /* RFC 3339, as issued */
} bundle;

/* true when the file content is a bundle rather than a bare DER or hex
 * configuration: D-69 tells them apart by the first byte ('{' vs 0x30/0xBF) */
bool bundle_is(const uint8_t *p, size_t len);

/* Parse the flat object. The eIM writes string and integer values only, in a
 * fixed order and with nothing that needs escaping (D-69) — anything else is
 * refused rather than guessed at. 0, or -1 with err set. */
int bundle_parse(const uint8_t *p, size_t len, bundle *b, char *err, size_t errlen);
void bundle_free(bundle *b);

/* RFC 3339 date-time (Z or ±hh:mm, optional fraction) to UTC seconds */
int rfc3339_time(const char *s, time_t *out);

/* Binding outcome of an HTTP status (D-69):
 *   BIND_DONE     204 bound, 409 already registered — poll from now on
 *   BIND_REFUSED  403: stop polling this card until an operator acts
 *   BIND_RETRY    429, 5xx, no answer: again with the poll backoff
 *   BIND_BAD      400/413/anything else: our request is wrong — kept pending,
 *                 but said as an error, not as a retry */
typedef enum { BIND_DONE, BIND_REFUSED, BIND_RETRY, BIND_BAD } bind_outcome;

bind_outcome bind_outcome_of(int http_status);

/* https://host[:port]/ipad/v1/bind from the ESipa URL the IPA uses
 * (https://host[:port]/gsma/rsp2/asn1): same host, same TLS. -1 when the URL
 * has no host part. */
int bind_url(const char *esipa_url, char *out, size_t cap);

#endif
