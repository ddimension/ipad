/* SPDX-License-Identifier: GPL-2.0-only */
#include <string.h>
#include "simcard.h"

static int sc_open(void *ctx, const uint8_t *aid, size_t len)
{
	simcard *s = ctx;

	if (len != sizeof(ISDR_AID) || memcmp(aid, ISDR_AID, len))
		return -1;
	s->opens++;
	s->dead = 0;
	return s->channel;
}

static int sc_close(void *ctx, int ch)
{
	simcard *s = ctx;

	(void)ch;
	s->closes++;
	return 0;
}

static void sw_out(dbuf *r, uint16_t sw)
{
	uint8_t b[2] = { (uint8_t)(sw >> 8), (uint8_t)sw };

	db_put(r, b, 2);
}

/* hand out the next portion of the pending answer */
static void portion(simcard *s, size_t want, dbuf *r)
{
	size_t n = s->pending.len;

	if (want == 0 || want > s->chunk)
		want = s->chunk;
	if (n > want)
		n = want;
	db_put(r, s->pending.d, n);
	memmove(s->pending.d, s->pending.d + n, s->pending.len - n);
	s->pending.len -= n;
	if (s->pending.len)
		sw_out(r, (uint16_t)(0x6100 | (s->pending.len >= 256 ? 0 : s->pending.len)));
	else
		sw_out(r, 0x9000);
}

static int sc_transmit(void *ctx, const uint8_t *a, size_t len, dbuf *r)
{
	simcard *s = ctx;

	if (len < 4)
		return -1;

	if (s->dead) {
		s->stale++;
		sw_out(r, 0x6881);
		return 0;
	}

	if (a[1] == 0xC0) {   /* GET RESPONSE */
		if (a[0] != card_cla(0x80, s->channel))
			s->bad_cla++;
		portion(s, len >= 5 ? a[4] : 0, r);
		return 0;
	}

	if (a[1] != 0xE2 || len < 5 || (size_t)a[4] + 5 != len) {
		sw_out(r, 0x6D00);
		return 0;
	}
	if (a[0] != card_cla(0x80, s->channel))
		s->bad_cla++;
	if (a[3] != s->expect_block)
		s->bad_seq++;

	s->blocks++;
	s->expect_block++;
	db_put(&s->req, a + 5, a[4]);

	if (a[2] == 0x11) {
		sw_out(r, 0x9000);
		return 0;
	}

	/* last block: run the function, answer via 61xx */
	{
		dbuf resp;
		uint16_t sw;

		db_init(&resp);
		sw = s->handler(s, s->req.d, s->req.len, &resp);
		s->req.len = 0;
		s->expect_block = 0;

		if (sw != 0x9000) {
			sw_out(r, sw);
		} else if (resp.len == 0) {
			sw_out(r, 0x9000);
		} else {
			s->pending.len = 0;
			db_put(&s->pending, resp.d, resp.len);
			sw_out(r, (uint16_t)(0x6100 | (resp.len >= 256 ? 0 : resp.len)));
		}
		db_free(&resp);
	}
	return 0;
}

const card_ops SIMCARD_OPS = { sc_open, sc_transmit, sc_close };

void simcard_reset(simcard *s)
{
	s->dead = 1;
	s->req.len = 0;
	s->pending.len = 0;
	s->expect_block = 0;
}

void simcard_init(simcard *s, int channel, sim_handler h, void *user)
{
	memset(s, 0, sizeof(*s));
	s->channel = channel;
	s->handler = h;
	s->user = user;
	s->chunk = 256;
	db_init(&s->req);
	db_init(&s->pending);
}

void simcard_free(simcard *s)
{
	db_free(&s->req);
	db_free(&s->pending);
}
