/* SPDX-License-Identifier: GPL-2.0-only
 * A simulated card behind card_ops, for the tests: it opens the ISD-R on a
 * chosen channel, reassembles STORE DATA blocks (checking CLA, P1 and the
 * block numbering), hands the complete command to a handler and returns the
 * handler's answer in 61xx / GET RESPONSE portions, as a real card does. */
#ifndef IPAD_SIMCARD_H
#define IPAD_SIMCARD_H
#include "card.h"

typedef struct simcard simcard;
/* the ES10 function: command data object in, response data object out;
 * return a status word (0x9000 for success) */
typedef uint16_t (*sim_handler)(simcard *s, const uint8_t *req, size_t len, dbuf *resp);

struct simcard {
	int channel;          /* handed out on open */
	sim_handler handler;
	void *user;
	size_t chunk;         /* GET RESPONSE portion size (<= 256) */
	/* observed */
	int opens, closes, blocks, bad_cla, bad_seq;
	dbuf req, pending;
	int expect_block;
};

extern const card_ops SIMCARD_OPS;
void simcard_init(simcard *s, int channel, sim_handler h, void *user);
void simcard_free(simcard *s);
#endif
