/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include <string.h>
#include "card.h"

/* SGP.22 v2.7 2.2.3: the ISD-R AID */
const uint8_t ISDR_AID[16] = { 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF,
                               0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00 };

void card_init(card *c, const card_ops *ops, void *ctx)
{
	c->ops = ops;
	c->ctx = ctx;
	c->channel = -1;
	c->sw = 0;
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

int card_es10(card *c, const uint8_t *req, size_t len, dbuf *resp)
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
