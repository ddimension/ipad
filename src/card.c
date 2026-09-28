/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include <string.h>
#include "card.h"

/* SGP.22 v2.7 2.2.3: the ISD-R AID */
const uint8_t ISDR_AID[16] = { 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
                               0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00 };

/* The reads a run repeats, answered from the cache. Only exact requests:
 * another tag list is another answer. */
static const uint8_t *const CACHED_REQ[CARD_CACHED] = {
	(const uint8_t[]){ 0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A },                /* GetEUICCData {EID} */
	(const uint8_t[]){ 0xBF, 0x2D, 0x05, 0x5C, 0x03, 0x5A, 0x9F, 0x70 },    /* GetProfilesInfo {ICCID, state} */
};
static const size_t CACHED_LEN[CARD_CACHED] = { 6, 8 };

void card_init(card *c, const card_ops *ops, void *ctx)
{
	int i;

	c->ops = ops;
	c->ctx = ctx;
	c->channel = -1;
	c->sw = 0;
	for (i = 0; i < CARD_CACHED; i++) {
		db_init(&c->cache[i]);
		c->cached[i] = false;
	}
}

void card_forget(card *c)
{
	int i;

	for (i = 0; i < CARD_CACHED; i++) {
		db_free(&c->cache[i]);
		c->cached[i] = false;
	}
}

/* Functions that change nothing a cached answer holds (SGP.22 5.7, SGP.32
 * 5.9): the reads, and GetEUICCChallenge, whose challenge is no part of them. Any
 * other request, one that does not parse (a BPP segment) included, may
 * change the profiles, and forgets the cache: in doubt, forget. */
static bool is_read(const uint8_t *req, size_t len)
{
	uint16_t tag;

	if (len < 2 || req[0] != 0xBF)
		return false;
	tag = (uint16_t)(req[0] << 8 | req[1]);
	switch (tag) {
	case 0xBF20:   /* GetEUICCInfo1 */
	case 0xBF22:   /* GetEUICCInfo2 */
	case 0xBF28:   /* ListNotification */
	case 0xBF2B:   /* RetrieveNotificationsList */
	case 0xBF2D:   /* GetProfilesInfo */
	case 0xBF2E:   /* GetEUICCChallenge */
	case 0xBF3C:   /* EuiccConfiguredAddresses */
	case 0xBF3E:   /* GetEUICCData */
	case 0xBF43:   /* GetRAT */
	case 0xBF55:   /* GetEimConfigurationData (SGP.32 5.9.18), the probe */
	case 0xBF56:   /* GetCerts (SGP.32 5.9.10) */
		return true;
	}
	return false;
}

uint8_t card_cla(uint8_t base, int channel)
{
	if (channel <= 3)
		return (uint8_t)((base & 0x80) | channel);
	return (uint8_t)((base & 0x80) | 0x40 | (channel - 4));
}

int card_open(card *c)
{
	int ch;

	if (c->channel >= 0)
		return 0;

	ch = c->ops->open(c->ctx, ISDR_AID, sizeof(ISDR_AID));
	if (ch < 1 || ch > 19)
		return -1;   /* 0 is the basic channel, never one handed out for an AID */
	c->channel = ch;
	return 0;
}

void card_close(card *c)
{
	if (c->channel >= 0)
		c->ops->close(c->ctx, c->channel);
	c->channel = -1;
	card_forget(c);
}

static uint16_t sw_of(const dbuf *r)
{
	return r->len >= 2 ? (uint16_t)(r->d[r->len - 2] << 8 | r->d[r->len - 1]) : 0;
}

/* send one APDU; append its data to resp; follow 61xx (GET RESPONSE) and
 * 6Cxx (resend with the right Le) until the card ends the exchange. Returns
 * the final SW, or 0 on a transport error. */
static uint16_t xfer(card *c, uint8_t *apdu, size_t len, dbuf *resp)
{
	dbuf r;
	uint16_t sw = 0;
	int rounds;

	for (rounds = 0; rounds < 64; rounds++) {
		db_init(&r);
		if (c->ops->transmit(c->ctx, apdu, len, &r) < 0 || r.err || r.len < 2) {
			db_free(&r);
			return 0;
		}
		sw = sw_of(&r);
		db_put(resp, r.d, r.len - 2);
		db_free(&r);

		if ((sw & 0xFF00) == 0x6100) {
			/* GET RESPONSE on the same channel, Le = what the card announced.
			 * CLA '80' like lpac (euicc/euicc.c:13,42, v2.3.0), not the
			 * interindustry '00': the proven form, kept rather than second-guessed */
			uint8_t gr[5] = { card_cla(0x80, c->channel), 0xC0, 0x00, 0x00, (uint8_t)sw };

			memcpy(apdu, gr, 5);
			len = 5;
			continue;
		}
		if ((sw & 0xFF00) == 0x6C00 && len >= 5) {
			apdu[len - 1] = (uint8_t)sw;   /* wrong Le: resend with the right one */
			continue;
		}
		return sw;
	}
	return 0;
}

static int es10(card *c, const uint8_t *req, size_t len, dbuf *resp);

int card_es10(card *c, const uint8_t *req, size_t len, dbuf *resp)
{
	size_t start = resp->len;
	int i, rc;

	for (i = 0; i < CARD_CACHED; i++)
		if (len == CACHED_LEN[i] && !memcmp(req, CACHED_REQ[i], len))
			break;
	if (i < CARD_CACHED && c->cached[i]) {
		c->sw = 0x9000;
		db_put(resp, c->cache[i].d, c->cache[i].len);
		return resp->err ? -1 : 0;
	}
	if (i == CARD_CACHED && !is_read(req, len))
		card_forget(c);
	rc = es10(c, req, len, resp);
	if (rc == 0 && i < CARD_CACHED) {
		c->cache[i].len = 0;
		db_put(&c->cache[i], resp->d + start, resp->len - start);
		c->cached[i] = !c->cache[i].err;
	}
	return rc;
}

static int es10(card *c, const uint8_t *req, size_t len, dbuf *resp)
{
	uint8_t apdu[5 + 255 + 1];
	size_t off = 0;
	int block = 0;

	if (card_open(c) < 0)
		return -1;

	/* STORE DATA (SGP.22 5.7.2): 255-octet blocks, P1 '11' for more blocks
	 * and '91' for the last, P2 the block number; the response data comes
	 * with the last block */
	do {
		size_t n = len - off > 255 ? 255 : len - off;
		bool last = off + n == len;
		dbuf discard;
		uint16_t sw;

		apdu[0] = card_cla(0x80, c->channel);
		apdu[1] = 0xE2;
		apdu[2] = last ? 0x91 : 0x11;
		apdu[3] = (uint8_t)block;
		apdu[4] = (uint8_t)n;
		memcpy(apdu + 5, req + off, n);

		/* Case 3, no Le, and the answer fetched through 61xx: what lpac sends
		 * (euicc/euicc.c:63, v2.3.0), the form proven over QMI UIM, MBIM UICC
		 * and AT CGLA on the hardware wwand runs on */
		if (last) {
			sw = xfer(c, apdu, 5 + n, resp);
		} else {
			db_init(&discard);
			sw = xfer(c, apdu, 5 + n, &discard);
			db_free(&discard);
		}
		c->sw = sw;

		if (sw != 0x9000 && (sw & 0xFF00) != 0x9100)
			return -1;

		off += n;
		block++;
	} while (off < len);

	return resp->err ? -1 : 0;
}
