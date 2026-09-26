/* SPDX-License-Identifier: GPL-2.0-only
 * card.c: STORE DATA chaining, 61xx collection and the CLA for the channel,
 * against the simulated card. */
#include "check.h"
#include "simcard.h"

/* echo the command back, repeated `user` times, so the answer can be made
 * longer than one GET RESPONSE */
static uint16_t echo(simcard *s, const uint8_t *req, size_t len, dbuf *resp)
{
	int i, n = *(int *)s->user;

	for (i = 0; i < n; i++)
		db_put(resp, req, len);
	return 0x9000;
}

static uint16_t refuse(simcard *s, const uint8_t *req, size_t len, dbuf *resp)
{
	(void)s; (void)req; (void)len; (void)resp;
	return 0x6A88;
}

int main(void)
{
	uint8_t big[700];
	simcard s;
	card c;
	dbuf r;
	int times = 1, i;

	for (i = 0; i < (int)sizeof(big); i++)
		big[i] = (uint8_t)i;

	OK(card_cla(0x80, 1) == 0x81 && card_cla(0x80, 3) == 0x83, "cla: channels 1-3 in bits 1-2");
	OK(card_cla(0x80, 4) == 0xC0 && card_cla(0x80, 19) == 0xCF, "cla: channels 4-19 in the further coding");

	/* one block, short answer */
	simcard_init(&s, 2, echo, &times);
	card_init(&c, &SIMCARD_OPS, &s);
	db_init(&r);
	OK(card_es10(&c, big, 10, &r) == 0, "es10: one block");
	EQ_HEX(r.d, r.len, big, 10, "es10: the answer comes back whole");
	db_free(&r);

	/* 700 octets = three blocks; the answer 3 x 700 = 2100 octets through
	 * many GET RESPONSEs; channel 5 exercises the further CLA coding */
	card_close(&c);
	s.channel = 5;
	s.chunk = 200;
	times = 3;
	db_init(&r);
	OK(card_es10(&c, big, sizeof(big), &r) == 0, "es10: three blocks");
	OK(s.blocks == 1 + 3, "es10: 255 + 255 + 190");
	OK(r.len == 2100 && !memcmp(r.d, big, 700) && !memcmp(r.d + 1400, big, 700),
	   "es10: a long answer is reassembled from its GET RESPONSE portions");
	OK(s.bad_cla == 0 && s.bad_seq == 0, "es10: every APDU on the ISD-R channel, blocks numbered");
	db_free(&r);

	/* the card refuses: an error with its SW, nothing claimed */
	s.handler = refuse;
	db_init(&r);
	OK(card_es10(&c, big, 10, &r) < 0 && c.sw == 0x6A88, "es10: a refusal reports its status word");
	db_free(&r);

	card_close(&c);
	OK(s.opens == 2 && s.closes == 2, "channel: opened once per use and closed");
	simcard_free(&s);

	DONE("test_card");
}
