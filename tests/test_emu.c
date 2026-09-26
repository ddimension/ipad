/* SPDX-License-Identifier: GPL-2.0-only
 * emu.c, the virtual SGP.32 ISD-R over a simulated SGP.22 card, driven the
 * way an eIM drives an IoT eUICC: packages signed with a real eIM key, results
 * verified with the device key. Section numbers are SGP.32 v1.3. */
#include <stdlib.h>
#include <unistd.h>
#include "check.h"
#include "fake22.h"
#include "emu.h"
#include "euicc.h"
#include "hex.h"
#include "eimpkg.h"

static crypto_key *eim_key, *dev_key;
static const char *EIM = "eim.test.example";
static uint8_t EID[16];

/* the result's kind (A0 signed result, A1 signed error, A2 unsigned error),
 * and for signed ones whether the device key's signature over data ||
 * associationToken holds */
static uint32_t epr_kind(const dbuf *r, bool *sig_ok, der_tlv *data)
{
	der_tlv top, k, sig;
	dbuf in;

	*sig_ok = false;
	if (der_parse(r->d, r->len, &top) < 0 || top.tag != 0xBF51 || der_parse(top.val, top.len, &k) < 0)
		return 0;
	if (k.tag == 0xA2)
		return k.tag;
	if (der_find(k.val, k.len, 0x30, data) < 0 || der_find(k.val, k.len, 0x5F37, &sig) < 0)
		return 0;
	db_init(&in);
	db_put(&in, data->raw, data->raw_len);
	der_put_int(&in, 0x84, 0);
	*sig_ok = crypto_verify(dev_key, in.d, in.len, sig.val, sig.len) == 0;
	db_free(&in);
	return k.tag;
}

static int64_t int_in(const der_tlv *d, uint32_t tag)
{
	der_tlv x;
	int64_t v = -999;

	if (der_find(d->val, d->len, tag, &x) == 0)
		der_get_int(&x, &v);
	return v;
}

/* the results SEQUENCE of a signed EPR */
static der_tlv results_of(const der_tlv *data)
{
	der_tlv r;

	memset(&r, 0, sizeof(r));
	der_find(data->val, data->len, 0x30, &r);
	return r;
}

int main(void)
{
	char state[] = "/tmp/ipad-test-emu-XXXXXX";
	int fd = mkstemp(state);
	simcard s;
	fake22 f;
	card c;
	emu_config cfg;
	emu *e;
	dbuf req, resp, ops;
	der_tlv data, res, x;
	bool ok;
	int64_t counter = 5;
	uint8_t eid_other[16];

	close(fd);
	unlink(state);   /* no state yet: a fresh card */

	eim_key = crypto_key_generate();
	dev_key = crypto_key_generate();

	fake22_init(&f);
	memcpy(EID, f.eid, 16);
	fake22_add(&f, "98001032547698103214", 1);   /* A: enabled */
	fake22_add(&f, "98001032547698103224", 0);   /* B */
	fake22_add(&f, "98001032547698103234", 0);   /* C */
	simcard_init(&s, 2, fake22_handler, &f);
	card_init(&c, &SIMCARD_OPS, &s);

	memset(&cfg, 0, sizeof(cfg));
	cfg.state_path = state;
	cfg.key = dev_key;
	e = emu_open(&c, &cfg);
	OK(e != NULL, "open: EID read from the card");

	/* --- AddInitialEim (3.5.2), then GetEimConfigurationData --- */
	db_init(&req);
	db_init(&resp);
	{
		size_t m = der_begin(&req, 0xBF57), l = der_begin(&req, 0xA0);

		eimpkg_cfg(&req, EIM, 4, eim_key, false);
		der_end(&req, l);
		der_end(&req, m);
	}
	OK(emu_es10(e, req.d, req.len, &resp) == 0, "addInitialEim: answered");
	{
		uint8_t want[] = { 0xBF, 0x57, 0x04, 0xA0, 0x02, 0x05, 0x00 };

		EQ_HEX(resp.d, resp.len, want, sizeof(want), "addInitialEim: addOk");
	}
	resp.len = 0;
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && resp.len >= 3 &&
	   resp.d[resp.len - 3] == 0x81 && resp.d[resp.len - 1] == 2,
	   "addInitialEim: a second one is associatedEimAlreadyExists (3.5.2 step 2)");

	req.len = resp.len = 0;
	{
		uint8_t g[] = { 0xBF, 0x55, 0x00 };

		OK(emu_es10(e, g, sizeof(g), &resp) == 0 && der_parse(resp.d, resp.len, &x) == 0 &&
		   x.tag == 0xBF55, "getEimConfigurationData: answered");
		OK(der_find(x.val, x.len, 0xA0, &x) == 0 && der_find(x.val, x.len, 0x30, &x) == 0,
		   "getEimConfigurationData: one configuration");
	}

	/* --- enable B: a signed result, applied after signing (3.3.1 8b) --- */
	db_init(&ops);
	eimpkg_op(&ops, 0xA3, "98001032547698103224", false);
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, EID, counter, 0xA0, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0, "enable: answered");
	OK(epr_kind(&resp, &ok, &data) == 0xA0 && ok, "enable: signed EPR, device key verifies");
	res = results_of(&data);
	OK(int_in(&res, 0x83) == 0, "enable: enableResult ok");
	OK(int_in(&data, 0x81) == counter, "enable: the package's counterValue");
	OK(int_in(&data, 0x83) >= EMU_SEQ_BASE, "enable: sequence number in the emulation's range");
	OK(fake22_enabled(&f) == 1 && f.last_refresh == 0, "enable: B is enabled on the card, without REFRESH");

	/* the same package again: replay (5.9.1), as a SIGNED error */
	resp.len = 0;
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA1 && ok &&
	   int_in(&data, 0x02) == 4, "replay: signed error replayError(4)");

	/* a bad signature: unsigned error, nothing done */
	counter++;
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, EID, counter, 0xA0, &ops, eim_key, 0, true);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA2,
	   "bad signature: unsigned error");

	/* another EID: invalidEid(3), signed */
	memcpy(eid_other, EID, 16);
	eid_other[15] ^= 1;
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, eid_other, counter, 0xA0, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA1 && ok &&
	   int_in(&data, 0x02) == 3, "eid: signed error invalidEid(3)");

	/* an unknown eIM: unsigned */
	req.len = resp.len = 0;
	eimpkg_package(&req, "other.example", EID, counter, 0xA0, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA2,
	   "unknown eIM: unsigned error");

	/* the first failure stops the list: enable B again (already enabled),
	 * then delete C, which must NOT happen (3.3.1 step 5) */
	ops.len = 0;
	eimpkg_op(&ops, 0xA3, "98001032547698103224", false);
	eimpkg_op(&ops, 0xA5, "98001032547698103234", false);
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, EID, ++counter, 0xA0, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA0 && ok,
	   "stop: answered with a signed result");
	res = results_of(&data);
	OK(int_in(&res, 0x83) == 2 && int_in(&res, 0x85) == -999, "stop: profileNotInDisabledState, delete not run");
	OK(f.deletes == 0, "stop: the card saw no delete");

	/* enable C with rollback, then ProfileRollback goes back to B */
	ops.len = 0;
	eimpkg_op(&ops, 0xA3, "98001032547698103234", true);
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, EID, ++counter, 0xA0, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && fake22_enabled(&f) == 2, "rollback: C enabled");
	resp.len = 0;
	{
		uint8_t rb[] = { 0xBF, 0x58, 0x03, 0x80, 0x01, 0x00 };
		der_tlv t, epr;

		OK(emu_es10(e, rb, sizeof(rb), &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
		   int_in(&t, 0x02) == 0, "rollback: cmdResult ok");
		OK(der_find(t.val, t.len, 0xBF51, &epr) == 0, "rollback: with a new eUICC Package Result");
		OK(fake22_enabled(&f) == 1, "rollback: B is enabled again");
		{
			/* the enabling package's result is gone (3.3.2 NOTE1): of the
			 * stored EPRs, none carries its counter any more */
			uint8_t rq[] = { 0xBF, 0x2B, 0x04, 0xA0, 0x02, 0x82, 0x00 };
			der_tlv tt, list, one, sg, dd;
			const uint8_t *p;
			bool found = false;
			dbuf r2;

			db_init(&r2);
			emu_es10(e, rq, sizeof(rq), &r2);
			if (der_parse(r2.d, r2.len, &tt) == 0 && der_find(tt.val, tt.len, 0xA2, &list) == 0)
				for (p = list.val; p < list.val + list.len && der_next(&p, list.val + list.len, &one) == 0; )
					if (der_parse(one.val, one.len, &sg) == 0 && sg.tag == 0xA0 &&
					    der_find(sg.val, sg.len, 0x30, &dd) == 0 && int_in(&dd, 0x81) == counter) {
						der_tlv rs = results_of(&dd);

						if (int_in(&rs, 0x83) == 0)
							found = true;
					}
			OK(!found, "rollback: the enabling package's result is discarded");
			db_free(&r2);
		}
		resp.len = 0;
		OK(emu_es10(e, rb, sizeof(rb), &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
		   int_in(&t, 0x02) == 1, "rollback: only once (rollbackNotAllowed)");
	}

	/* delete C (disabled): marked, applied */
	ops.len = 0;
	eimpkg_op(&ops, 0xA5, "98001032547698103234", false);
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, EID, ++counter, 0xA0, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA0, "delete: answered");
	res = results_of(&data);
	OK(int_in(&res, 0x85) == 0 && f.deletes == 1, "delete: ok, and the card deleted it");

	/* eCO: addEim asking for a token (-1), then listEim */
	ops.len = 0;
	{
		dbuf c2;
		der_tlv w;

		db_init(&c2);
		eimpkg_cfg(&c2, "second.example", 0, eim_key, true);
		der_parse(c2.d, c2.len, &w);
		der_put(&ops, 0xA8, w.val, w.len);   /* addEim [8], implicitly tagged */
		der_put(&ops, 0xAB, NULL, 0);        /* listEim */
		db_free(&c2);
	}
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, EID, ++counter, 0xA1, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA0 && ok, "eco: answered");
	res = results_of(&data);
	OK(der_find(res.val, res.len, 0xA8, &x) == 0 && der_find(x.val, x.len, 0x84, &x) == 0,
	   "addEim: a generated associationToken (A8 { 84 .. })");
	OK(der_find(res.val, res.len, 0xAB, &x) == 0 && der_find(x.val, x.len, 0xA0, &x) == 0,
	   "listEim: AB { A0 {...} }, automatic tag as the pycrate vector has it");
	{
		/* GetEimConfigurationData renders, it does not echo (5.9.18) */
		int64_t gen = -2, shown = -3;
		der_tlv t, c, v;
		uint8_t g[] = { 0xBF, 0x55, 0x12, 0xA0, 0x10, 0x80, 0x0E, 's', 'e', 'c', 'o', 'n', 'd', '.',
		                'e', 'x', 'a', 'm', 'p', 'l', 'e' };

		if (der_find(res.val, res.len, 0xA8, &x) == 0 && der_find(x.val, x.len, 0x84, &v) == 0)
			der_get_int(&v, &gen);
		resp.len = 0;
		OK(emu_es10(e, g, sizeof(g), &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
		   der_find(t.val, t.len, 0xA0, &t) == 0 && der_find(t.val, t.len, 0x30, &c) == 0,
		   "getEimConfigurationData: the second eIM by eimId");
		if (der_find(c.val, c.len, 0x84, &v) == 0)
			der_get_int(&v, &shown);
		OK(shown == gen && gen > 0, "getEimConfigurationData: the GENERATED associationToken, not -1");
		OK(der_find(c.val, c.len, 0x83, &v) < 0, "getEimConfigurationData: no counterValue (SHALL NOT)");
		{
			const uint8_t *p = c.val, *end = c.val + c.len;
			uint32_t prev = 0;
			bool sorted = true;

			while (p < end && der_next(&p, end, &v) == 0) {
				if ((v.tag & 0x1F) < (prev & 0x1F))
					sorted = false;
				prev = v.tag;
			}
			OK(sorted, "getEimConfigurationData: components in declaration order");
		}
	}

	/* the stored EPRs, then removing one */
	{
		uint8_t rq[] = { 0xBF, 0x2B, 0x04, 0xA0, 0x02, 0x82, 0x00 };
		der_tlv t, list, first;
		int64_t seq = -1;

		resp.len = 0;
		OK(emu_es10(e, rq, sizeof(rq), &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
		   der_find(t.val, t.len, 0xA2, &list) == 0 && der_parse(list.val, list.len, &first) < 0,
		   "notifications: EPRs as A2, more than one kept");
		{
			const uint8_t *p = list.val;
			der_tlv sg, dd;

			der_next(&p, list.val + list.len, &first);
			if (der_parse(first.val, first.len, &sg) == 0 && der_find(sg.val, sg.len, 0x30, &dd) == 0)
				seq = int_in(&dd, 0x83);
		}
		{
			dbuf rm;
			size_t m;

			db_init(&rm);
			m = der_begin(&rm, 0xBF30);
			der_put_int(&rm, 0x80, seq);
			der_end(&rm, m);
			resp.len = 0;
			OK(emu_es10(e, rm.d, rm.len, &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
			   int_in(&t, 0x80) == 0, "remove: the delivered EPR is deleted");
			resp.len = 0;
			OK(emu_es10(e, rm.d, rm.len, &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
			   int_in(&t, 0x80) == 1, "remove: a second time, nothingToDelete");
			db_free(&rm);
		}
	}

	/* what an SGP.22 card cannot have is said so */
	{
		uint8_t gcp[] = { 0xBF, 0x5F, 0x00 }, want[] = { 0xBF, 0x5F, 0x03, 0x81, 0x01, 0x01 };

		resp.len = 0;
		OK(emu_es10(e, gcp, sizeof(gcp), &resp) == 0, "connectivity: answered");
		EQ_HEX(resp.d, resp.len, want, sizeof(want), "connectivity: parametersNotAvailable");
	}

	/* the state survives a restart: the old package is still a replay */
	emu_close(e);
	e = emu_open(&c, &cfg);
	OK(e != NULL, "reopen: state loaded");
	ops.len = 0;
	eimpkg_op(&ops, 0xA4, "98001032547698103224", false);
	req.len = resp.len = 0;
	eimpkg_package(&req, EIM, EID, counter, 0xA0, &ops, eim_key, 0, false);
	OK(emu_es10(e, req.d, req.len, &resp) == 0 && epr_kind(&resp, &ok, &data) == 0xA1 &&
	   int_in(&data, 0x02) == 4, "reopen: the counter survived, replay refused");

	/* a state file of another card is refused */
	emu_close(e);
	f.eid[0] ^= 0x10;
	OK(emu_open(&c, &cfg) == NULL, "state: another card's file is not reused");

	/* the probe: an SGP.22 card does not know GetEimConfigurationData */
	f.eid[0] ^= 0x10;
	OK(euicc_probe(&c) == EUICC_EMU, "probe: an SGP.22 card is driven through the emulation");

	unlink(state);
	db_free(&req);
	db_free(&resp);
	db_free(&ops);
	simcard_free(&s);
	crypto_key_free(eim_key);
	crypto_key_free(dev_key);
	DONE("test_emu");
}
