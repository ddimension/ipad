/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * Backoff for Notifications the eIM answers without taking them (a PIR it
 * cannot attribute, an old consumer-card notification). SGP.32 3.7 has the
 * IPA remove only what the eIM acknowledged, so they stay on the card; what
 * changes is how often they are offered: an hour after the first refusal,
 * doubling up to a day.
 *
 * Kept per EID in a file of its own (<EID>.nbo next to <EID>.es9), not in
 * the emulation's state: an IoT eUICC keeps refused notifications just the
 * same, and has no state of ipad's to put the records in. One code path for
 * both backends.
 *
 * A record holds for one notification, not for its seqNumber alone: it
 * carries a fingerprint of the notification's NotificationMetadata, so a
 * seqNumber that comes back for another notification (a card reset, another
 * card under the same EID file) does not inherit the backoff. All records
 * hold for one set of eIM configurations, fingerprinted too: another eIM,
 * or the same one updated, may take them, so a change forgets them all.
 *
 * The file is an optimisation: one that cannot be read or written costs
 * extra offers, never a notification.
 */
#ifndef IPAD_NBO_H
#define IPAD_NBO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define NBO_FIRST 3600    /* seconds after the first refusal */
#define NBO_CAP 86400     /* the longest delay */
#define NBO_MAX 32

typedef struct {
	int64_t seq, due, delay;
	uint8_t fp[8];
} nbo_rec;

typedef struct {
	const char *path;   /* NULL: kept for this run only */
	uint8_t eims[8];    /* the eIM configurations the records hold for */
	bool has_eims;
	nbo_rec r[NBO_MAX];
	int n;
} nbo;

/* the first 8 octets of SHA-256 over der */
void nbo_fp(const uint8_t *der, size_t len, uint8_t out[8]);

/* Reads path (a missing or damaged file is no record). */
void nbo_load(nbo *b, const char *path);

/* The eIM configurations now (nbo_fp of GetEimConfigurationData's list):
 * a change from the recorded ones forgets every record. */
void nbo_eims(nbo *b, const uint8_t fp[8]);

/* Whether notification seq (fingerprint fp) is due at now (seconds). A due
 * date more than NBO_CAP ahead means the clock went back (a router sets it
 * late): due, rather than held for longer than the cap. */
bool nbo_due(const nbo *b, int64_t seq, const uint8_t fp[8], int64_t now);

/* The eIM did not take it: records the refusal, returns the next delay. */
int64_t nbo_refused(nbo *b, int64_t seq, const uint8_t fp[8], int64_t now);

/* seqs: every seqNumber still on the card, after a list read to its end;
 * the records of all others are dropped. */
void nbo_keep(nbo *b, const int64_t *seqs, int n);

#endif
