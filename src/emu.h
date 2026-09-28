/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * A virtual SGP.32 ISD-R in front of an SGP.22 consumer eUICC.
 *
 * The functions SGP.32 adds to ES10b are answered here, following SGP.32
 * v1.3 as closely as an SGP.22 card allows; everything else goes to the card
 * unchanged. What an IoT eUICC would keep on the card, the eIM configuration,
 * the replay counters, the stored eUICC Package Results and the rollback,
 * fallback and immediate-enable state, is kept in a state file per EID.
 *
 * Results are signed with the IPA's device key instead of SK.EUICC.ECDSA,
 * over the same bytes (section 2.11: euiccPackageResultDataSigned ||
 * associationToken, likewise for the error). The eIM verifies them with the
 * key it learned from the import file (`ipad export`), so the signature is
 * real where onomondo-ipa's emulation carried a placeholder.
 *
 * What an SGP.22 card cannot provide is reported as such, never faked:
 * GetConnectivityParameters answers parametersNotAvailable, GetCerts an
 * error, the emergency profile ecallNotAvailable.
 */
#ifndef IPAD_EMU_H
#define IPAD_EMU_H

#include <stdbool.h>
#include "card.h"
#include "crypto.h"

typedef struct emu emu;

typedef struct {
	const char *state_path;    /* per-EID state file, written atomically; copied */
	crypto_key *key;           /* the device key: signs EPR / EPE */
	/* NOT NORMATIVE. SGP.32 3.4.6 requires the fallbackAllowed metadata,
	 * which SGP.22 profiles do not carry; set this to treat every profile
	 * as allowed. Off: setFallbackAttribute answers fallbackNotAllowed. */
	bool fallback_allowed;
} emu_config;

/* The EID is read from the card and the state is bound to it: a state file
 * written for another card is refused, not reused. NULL on failure. */
emu *emu_open(card *c, const emu_config *cfg);
void emu_close(emu *e);

int emu_es10(emu *e, const uint8_t *req, size_t len, dbuf *resp);

/* What the eIM import file states for an eIM (eim_id NULL: the first one):
 * the replay counter the emulation holds and its associationToken. -1 when
 * no such eIM is configured. */
int emu_eim_state(const emu *e, const char *eim_id, int64_t *counter, bool *has_token, int64_t *token);

/* Backoff for Notifications the eIM answers without taking them (a PIR it
 * cannot attribute, an old consumer-card notification). SGP.32 3.7 has the
 * IPA remove only what the eIM acknowledged, so they stay on the card; what
 * changes is how often they are offered: an hour after the first refusal,
 * doubling up to a day. Kept in the state, so a poll every few minutes does
 * not send them each time; forgotten when the eIM configuration changes,
 * since another eIM, or the same one updated, may take them. now: seconds
 * (time()). emu_notif_keep: the seqNumbers still on the card, after a
 * complete run; the record of any other is dropped. */
bool emu_notif_due(emu *e, int64_t seq, int64_t now);
int64_t emu_notif_refused(emu *e, int64_t seq, int64_t now);   /* the next delay */
void emu_notif_keep(emu *e, const int64_t *seqs, int n);

#define EMU_NB_FIRST 3600
#define EMU_NB_CAP 86400

/* The sequence numbers the emulation gives its eUICC Package Results start
 * here: far above the card's own notification numbers, so that
 * RemoveNotificationFromList can tell whose a number is, and still
 * increasing, as the eIM requires (section 3.3.1 step 11). */
#define EMU_SEQ_BASE 0x40000000

#endif
