/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The card below the IPA: a logical channel to the ISD-R and the ES10
 * transport over it (STORE DATA, SGP.22 v2.7 section 5.7.2).
 *
 * The APDU backend is pluggable. In wwand it is the host process on stdio
 * (lpac's protocol, relayed by esim_bridge over the modem's QMI UIM / MBIM
 * UICC / AT channel); in tests it is a simulated card in the same process.
 * A backend may complete GET RESPONSE itself (a modem does) or hand back
 * 61xx; both are handled here.
 */
#ifndef IPAD_CARD_H
#define IPAD_CARD_H

#include <stddef.h>
#include <stdint.h>
#include "der.h"

typedef struct {
	int (*open)(void *ctx, const uint8_t *aid, size_t aid_len);   /* -> channel >= 1, or < 0 */
	int (*transmit)(void *ctx, const uint8_t *apdu, size_t len, dbuf *rapdu);  /* R-APDU incl. SW */
	int (*close)(void *ctx, int channel);
} card_ops;

typedef struct {
	const card_ops *ops;
	void *ctx;
	int channel;    /* open ISD-R channel, -1 when none */
	uint16_t sw;    /* last status word, for the error a caller reports */
} card;

extern const uint8_t ISDR_AID[16];

void card_init(card *c, const card_ops *ops, void *ctx);
int card_open(card *c);   /* the ISD-R; idempotent */
void card_close(card *c);

/* One ES10 function: req is the complete command data object (e.g. BF51...),
 * resp receives the complete response data object. 0 on success, -1 on a
 * transport or status word error (c->sw holds the last SW). */
int card_es10(card *c, const uint8_t *req, size_t len, dbuf *resp);

/* CLA for a logical channel (ISO/IEC 7816-4 5.4.1): 0-3 in bits 1-2 of the
 * first interindustry coding, 4-19 in the further coding (bit 7 set,
 * channel-4 in bits 1-4); bit 8 (proprietary class) is taken from `base` */
uint8_t card_cla(uint8_t base, int channel);

#endif
