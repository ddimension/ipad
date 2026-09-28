/* SPDX-License-Identifier: GPL-2.0-only
 * card.c: STORE DATA chaining, 61xx collection and the CLA for the channel,
 * against the simulated card. */
#include <string.h>

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

/* counts its calls; answers the command back */
static uint16_t counted(simcard *s, const uint8_t *req, size_t len, dbuf *resp)
{
	(*(int *)s->user)++;
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

	/* the reads a run repeats come from the cache until anything else,
	 * or a close, may have changed the card */
	{
		static const uint8_t eid[] = { 0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A };
		static const uint8_t st[] = { 0xBF, 0x2D, 0x05, 0x5C, 0x03, 0x5A, 0x9F, 0x70 };
		static const uint8_t other[] = { 0xBF, 0x2D, 0x03, 0x5C, 0x01, 0x5A };
		static const uint8_t list[] = { 0xBF, 0x28, 0x00 };
		static const uint8_t enable[] = { 0xBF, 0x31, 0x00 };
		static const uint8_t seg[] = { 0x86, 0x01, 0x00 };   /* a BPP segment: no ES10 tag */
		int calls = 0;

		simcard_init(&s, 1, counted, &calls);
		card_init(&c, &SIMCARD_OPS, &s);
		db_init(&r);
		card_es10(&c, eid, sizeof(eid), &r);
		card_es10(&c, st, sizeof(st), &r);
		r.len = 0;
		OK(card_es10(&c, eid, sizeof(eid), &r) == 0 && card_es10(&c, st, sizeof(st), &r) == 0 && calls == 2,
		   "cache: GetEID and GetProfilesInfo {5A 9F70} asked once");
		OK(r.len == sizeof(eid) + sizeof(st) && !memcmp(r.d, eid, sizeof(eid)) &&
		   !memcmp(r.d + sizeof(eid), st, sizeof(st)), "cache: the answers as the card gave them, appended");
		card_es10(&c, other, sizeof(other), &r);
		card_es10(&c, list, sizeof(list), &r);
		card_es10(&c, st, sizeof(st), &r);
		OK(calls == 4, "cache: another tag list is no hit, and a read forgets nothing");
		card_es10(&c, enable, sizeof(enable), &r);
		card_es10(&c, st, sizeof(st), &r);
		OK(calls == 6, "cache: an EnableProfile forgets it");
		card_es10(&c, seg, sizeof(seg), &r);
		card_es10(&c, eid, sizeof(eid), &r);
		OK(calls == 8, "cache: a request without an ES10 tag forgets it");
		card_close(&c);
		card_es10(&c, eid, sizeof(eid), &r);
		OK(calls == 9, "cache: a close forgets it (the host may use the card)");
		s.handler = refuse;
		card_forget(&c);
		OK(card_es10(&c, eid, sizeof(eid), &r) < 0, "cache: a refused read");
		s.handler = counted;
		card_es10(&c, eid, sizeof(eid), &r);
		OK(calls == 10, "cache: a refused read is not kept");
		db_free(&r);
		card_close(&c);
		simcard_free(&s);
	}

	DONE("test_card");
}
