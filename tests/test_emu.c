/* SPDX-License-Identifier: GPL-2.0-only
 * emu.c, the virtual SGP.32 ISD-R over a simulated SGP.22 card, driven the
 * way an eIM drives an IoT eUICC: packages signed with a real eIM key, results
 * verified with the device key. Section numbers are SGP.32 v1.3. */
#include <stdlib.h>
#include <unistd.h>
#include "check.h"
#include "fake22.h"
#include "emu.h"
#include "emu_int.h"   /* test_fallback sets a rollback record directly */
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

/* --- the card's real answers (two-phase LoadEuiccPackage) ------------------- */

typedef struct {
	fake22 f;
	simcard s;
	card c;
	emu_config cfg;
	emu *e;
	char state[64];
	char snap[80];      /* the state file as it was when the card was about to change */
	int snaps;
	int64_t counter;
} rig;

static void snapshot(void *arg)
{
	rig *r = arg;
	char cmd[200];

	snprintf(cmd, sizeof(cmd), "cp '%s' '%s' 2>/dev/null", r->state, r->snap);
	r->snaps += system(cmd) == 0;
}

/* a card with profiles A (enabled) and nmore disabled ones, an emulation with
 * the test eIM configured at counter 4 */
static int rig_open(rig *r, int nmore)
{
	int fd, i;
	dbuf req, resp;
	size_t m, l;

	memset(r, 0, sizeof(*r));
	snprintf(r->state, sizeof(r->state), "/tmp/ipad-test-emu2-XXXXXX");
	fd = mkstemp(r->state);
	close(fd);
	unlink(r->state);
	snprintf(r->snap, sizeof(r->snap), "%s.snap", r->state);

	fake22_init(&r->f);
	fake22_add(&r->f, "98001032547698103214", 1);
	for (i = 0; i < nmore; i++) {
		char ic[32];

		/* B = ...3224, C = ...3234, as in main() */
		snprintf(ic, sizeof(ic), "98001032547698103%d%d4", 2 + (i + 2) / 10, (i + 2) % 10);
		fake22_add(&r->f, ic, 0);
	}
	simcard_init(&r->s, 2, fake22_handler, &r->f);
	card_init(&r->c, &SIMCARD_OPS, &r->s);
	r->cfg.state_path = r->state;
	r->cfg.key = dev_key;
	if (!(r->e = emu_open(&r->c, &r->cfg)))
		return -1;

	db_init(&req);
	db_init(&resp);
	m = der_begin(&req, 0xBF57);
	l = der_begin(&req, 0xA0);
	eimpkg_cfg(&req, EIM, 4, eim_key, false);
	der_end(&req, l);
	der_end(&req, m);
	i = emu_es10(r->e, req.d, req.len, &resp);
	db_free(&req);
	db_free(&resp);
	r->counter = 4;
	return i;
}

static void rig_close(rig *r)
{
	emu_close(r->e);
	simcard_free(&r->s);
	fake22_free(&r->f);
	unlink(r->state);
	unlink(r->snap);
}

/* run a psmoList at the next counter; the results SEQUENCE of the signed
 * EPR in *res (its bytes in resp), false when the answer is no signed EPR */
static bool rig_run(rig *r, const dbuf *ops, dbuf *resp, der_tlv *res)
{
	dbuf req;
	der_tlv data;
	bool ok = false;

	db_init(&req);
	resp->len = 0;
	eimpkg_package(&req, EIM, EID, ++r->counter, 0xA0, ops, eim_key, 0, false);
	if (emu_es10(r->e, req.d, req.len, resp) == 0 && epr_kind(resp, &ok, &data) == 0xA0 && ok)
		*res = results_of(&data);
	else
		ok = false;
	db_free(&req);
	return ok;
}

static int64_t rollback_code(rig *r)
{
	uint8_t rb[] = { 0xBF, 0x58, 0x03, 0x80, 0x01, 0x00 };
	dbuf resp;
	der_tlv t;
	int64_t v = -999;

	db_init(&resp);
	if (emu_es10(r->e, rb, sizeof(rb), &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0)
		v = int_in(&t, 0x02);
	db_free(&resp);
	return v;
}

static void test_card_outcomes(void)
{
	rig r;
	dbuf ops, resp;
	der_tlv res;
	int i;

	db_init(&ops);
	db_init(&resp);

	/* a refused enable: the card's disallowedByPolicy(3) is the result, not
	 * ok; nothing changed, and no rollback is granted for it */
	OK(rig_open(&r, 2) == 0, "outcome: rig");
	r.f.refuse_enable = 3;
	eimpkg_op(&ops, 0xA3, "98001032547698103224", true);
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 3,
	   "outcome: a refused enable is the card's disallowedByPolicy(3), signed");
	OK(fake22_enabled(&r.f) == 0, "outcome: A still enabled on the card");
	OK(rollback_code(&r) == 1, "outcome: no rollback granted for a refused enable (rollbackNotAllowed)");

	/* the refusal stops the list (3.3.1 step 5): the delete after it is not run */
	ops.len = 0;
	eimpkg_op(&ops, 0xA3, "98001032547698103224", false);
	eimpkg_op(&ops, 0xA5, "98001032547698103234", false);
	r.f.deletes = 0;
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 3 && int_in(&res, 0x85) == -999 &&
	   r.f.deletes == 0, "outcome: a refused enable stops the list");

	/* SGP.22's wrongProfileReenabling(4) has no number in SGP.32's
	 * EnableProfileResult: undefinedError */
	r.f.refuse_enable = 4;
	ops.len = 0;
	eimpkg_op(&ops, 0xA3, "98001032547698103224", false);
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 127,
	   "outcome: wrongProfileReenabling(4) becomes undefinedError(127)");
	r.f.refuse_enable = 0;

	/* a refused disable: catBusy(5) exists in DisableProfileResult */
	r.f.refuse_disable = 5;
	ops.len = 0;
	eimpkg_op(&ops, 0xA4, "98001032547698103214", false);
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x84) == 5 && fake22_enabled(&r.f) == 0,
	   "outcome: a refused disable is the card's catBusy(5), A stays enabled");
	r.f.refuse_disable = 0;

	/* a refused delete: disallowedByPolicy(3) passes, catBusy(5) is not a
	 * DeleteProfileResult and becomes undefinedError */
	r.f.refuse_delete = 3;
	ops.len = 0;
	eimpkg_op(&ops, 0xA5, "98001032547698103234", false);
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x85) == 3 && r.f.p[2].present,
	   "outcome: a refused delete is the card's disallowedByPolicy(3), the profile stays");
	r.f.refuse_delete = 5;
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x85) == 127,
	   "outcome: catBusy(5) on a delete becomes undefinedError(127)");
	r.f.refuse_delete = 0;

	/* disable A, then enable B with rollbackFlag: A is the profile "marked
	 * to be disabled" (3.4.1 step 2), so the rollback goes back to A */
	ops.len = 0;
	eimpkg_op(&ops, 0xA4, "98001032547698103214", false);
	eimpkg_op(&ops, 0xA3, "98001032547698103224", true);
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x84) == 0 && int_in(&res, 0x83) == 0 &&
	   fake22_enabled(&r.f) == 1, "outcome: disable A, enable B with rollback: both ok, B enabled");
	OK(rollback_code(&r) == 0 && fake22_enabled(&r.f) == 0,
	   "outcome: the rollback returns to A, disabled earlier in the same package");

	/* the counter is durable BEFORE the card changes: the state file as it
	 * stands when the card is about to act already has the package's
	 * counter, so a crash there cannot let the package run again */
	r.f.before_change = snapshot;
	r.f.before_arg = &r;
	ops.len = 0;
	eimpkg_op(&ops, 0xA3, "98001032547698103224", false);
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 0 && r.snaps == 1,
	   "crash window: the card was switched once");
	r.f.before_change = NULL;
	{
		emu_config sc = r.cfg;
		emu *e2;
		int64_t cnt = -1, tok;
		bool has;

		sc.state_path = r.snap;
		e2 = emu_open(&r.c, &sc);
		OK(e2 && emu_eim_state(e2, EIM, &cnt, &has, &tok) == 0 && cnt == r.counter,
		   "crash window: the package's counter was saved before the card was switched");
		emu_close(e2);
	}
	rig_close(&r);

	/* more deletes than the old fixed capacity of 8: every one is carried
	 * out and answered with the card's result, none is an ok for nothing */
	OK(rig_open(&r, 10) == 0, "deletes: rig with 10 disabled profiles");
	ops.len = 0;
	for (i = 1; i <= 10; i++) {
		char ic[21];

		hex_encode(r.f.p[i].iccid, 10, ic);
		eimpkg_op(&ops, 0xA5, ic, false);
	}
	OK(rig_run(&r, &ops, &resp, &res), "deletes: answered");
	{
		const uint8_t *p = res.val, *end = res.val + res.len;
		der_tlv x;
		int n = 0, oks = 0;

		while (p < end && der_next(&p, end, &x) == 0) {
			int64_t v = -1;

			n++;
			if (x.tag == 0x85 && der_get_int(&x, &v) == 0 && v == 0)
				oks++;
		}
		OK(n == 10 && oks == 10, "deletes: ten deleteResult ok");
	}
	for (i = 1; i <= 10; i++)
		if (r.f.p[i].present)
			break;
	OK(i == 11 && r.f.deletes == 10, "deletes: all ten gone from the card");
	rig_close(&r);

	db_free(&ops);
	db_free(&resp);
}

/* ExecuteFallbackMechanism (execute) or ReturnFromFallback, refreshFlag
 * FALSE; the result code */
static int64_t fallback_code(rig *r, bool execute)
{
	uint8_t rq[] = { 0xBF, 0x5D, 0x03, 0x01, 0x01, 0x00 };
	dbuf resp;
	der_tlv t;
	int64_t v = -999;

	if (!execute)
		rq[1] = 0x5E;
	db_init(&resp);
	if (emu_es10(r->e, rq, sizeof(rq), &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
	    t.tag == (execute ? 0xBF5Du : 0xBF5Eu))
		v = int_in(&t, 0x80);
	db_free(&resp);
	return v;
}

/* setFallbackAttribute (3.4.6) in a package; its result code */
static int64_t set_fallback(rig *r, const char *iccid)
{
	dbuf ops, resp;
	der_tlv res;
	int64_t v = -999;

	db_init(&ops);
	db_init(&resp);
	eimpkg_op(&ops, 0xA8, iccid, false);
	if (rig_run(r, &ops, &resp, &res))
		v = int_in(&res, 0x8D);
	db_free(&ops);
	db_free(&resp);
	return v;
}

static void test_fallback(void)
{
	static const char *B = "98001032547698103224", *C = "98001032547698103234";
	rig r;
	dbuf ops, resp;
	der_tlv res;

	db_init(&ops);
	db_init(&resp);

	/* fallbackAllowed is not in SGP.22's default tag list: the emulation
	 * has to ask for 9F67 by name to see it (3.4.6 step 4) */
	OK(rig_open(&r, 2) == 0, "fallback: rig");
	r.f.p[2].fallback_allowed = 2;   /* C: FALSE */
	OK(set_fallback(&r, C) == 2, "fallback: fallbackAllowed FALSE is fallbackNotAllowed(2)");
	r.f.p[1].fallback_allowed = 1;   /* B: TRUE */
	OK(set_fallback(&r, B) == 0, "fallback: fallbackAllowed TRUE on the card, the attribute is set");

	/* not in fallback: fallbackNotAvailable(6), not commandError (5.9.21) */
	OK(fallback_code(&r, false) == 6, "return: not in fallback is fallbackNotAvailable(6)");

	/* 5.9.20 resets a granted rollback: C enabled with rollbackFlag, then
	 * the fallback; the rollback must not leave B for A any more */
	eimpkg_op(&ops, 0xA3, C, true);
	OK(rig_run(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 0 && fake22_enabled(&r.f) == 2,
	   "fallback: C enabled with rollbackFlag");
	OK(fallback_code(&r, true) == 0 && fake22_enabled(&r.f) == 1, "execute: ok, B (the fallback) enabled");
	OK(rollback_code(&r) == 1 && fake22_enabled(&r.f) == 1,
	   "execute: the rollback authorisation is gone (rollbackNotAllowed), B stays");
	OK(fallback_code(&r, false) == 0 && fake22_enabled(&r.f) == 2, "return: ok, back to C");

	/* the card changed under the emulation (a switch through lpac): the
	 * fallback profile is no longer the enabled one, whatever the record
	 * says, and C must not be enabled over A */
	OK(fallback_code(&r, true) == 0 && fake22_enabled(&r.f) == 1, "execute: B again");
	r.f.p[1].enabled = 0;
	r.f.p[0].enabled = 1;
	r.f.enables = 0;
	OK(fallback_code(&r, false) == 6 && fake22_enabled(&r.f) == 0 && r.f.enables == 0,
	   "return: A enabled on the card, not the fallback: fallbackNotAvailable(6), nothing switched");

	/* no enabled profile: commandError(7) (5.9.20), the fallback not enabled */
	r.f.p[0].enabled = 0;
	OK(fallback_code(&r, true) == 7 && fake22_enabled(&r.f) == -1 && r.f.enables == 0,
	   "execute: no enabled profile is commandError(7), nothing switched");

	/* 5.9.21 resets a rollback authorisation too; the emulation grants none
	 * while in fallback, so it is set here as a state file written without
	 * the 5.9.20 reset would carry it */
	r.f.p[0].enabled = 1;
	OK(fallback_code(&r, true) == 0 && fake22_enabled(&r.f) == 1, "execute: A to B");
	r.e->rb_granted = true;
	memcpy(r.e->rb_iccid, r.f.p[2].iccid, 10);
	snprintf(r.e->rb_eim, sizeof(r.e->rb_eim), "%s", EIM);
	OK(fallback_code(&r, false) == 0 && fake22_enabled(&r.f) == 0, "return: B to A");
	OK(rollback_code(&r) == 1 && fake22_enabled(&r.f) == 0,
	   "return: the rollback authorisation is gone (rollbackNotAllowed), A stays");
	rig_close(&r);

	/* a card that refuses 9F67 in a tag list: the default list is asked
	 * instead, and the flag counts as absent */
	OK(rig_open(&r, 2) == 0, "fallback: rig, tag list refused");
	r.f.refuse_taglist = 1;
	r.f.p[1].fallback_allowed = 1;
	OK(set_fallback(&r, "98001032547698103244") == 1,
	   "fallback, tag list refused: the profiles are still read (iccidOrAidNotFound for an unknown one)");
	OK(set_fallback(&r, B) == 2, "fallback, tag list refused: fallbackAllowed absent, fallbackNotAllowed(2)");
	/* refused once, not asked again: on this run nor, from the state, the next */
	OK(r.f.taglist_refusals == 1 && !r.f.last_had_taglist,
	   "fallback, tag list refused: 9F67 remembered, the default list asked directly");
	emu_close(r.e);
	r.e = emu_open(&r.c, &r.cfg);
	OK(r.e && set_fallback(&r, B) == 2 && r.f.taglist_refusals == 1,
	   "fallback, tag list refused: remembered across a restart");
	rig_close(&r);

	/* no answer at all is no refusal: nothing remembered */
	OK(rig_open(&r, 2) == 0, "fallback: rig, card silent once");
	r.s.fail_next = 1;
	set_fallback(&r, B);
	OK(!(r.e->quirks & EMU_Q_NO_9F67), "fallback: a card that did not answer is asked with 9F67 again");
	rig_close(&r);

	db_free(&ops);
	db_free(&resp);
}

/* a PSMO list in one package; *res its results */
static bool run_ops(rig *r, dbuf *ops, dbuf *resp, der_tlv *res)
{
	bool ok = rig_run(r, ops, resp, res);

	ops->len = 0;
	return ok;
}

/* "is the Fallback Profile enabled" is the card's answer, in every PSMO that
 * asks it (3.4.3 step 2c, 3.4.6 step 6a, 3.4.7 step 1b) */
static void test_fallback_card_state(void)
{
	static const char *A = "98001032547698103214", *B = "98001032547698103224",
	                  *C = "98001032547698103234";
	rig r;
	dbuf ops, resp;
	der_tlv res;

	db_init(&ops);
	db_init(&resp);

	/* in fallback (A to B), then the eIM enables C: B is no longer enabled,
	 * so the attribute may move to C (3.4.6 step 6b), and the way back from
	 * fallback is gone (3.4.1 step 3) */
	OK(rig_open(&r, 2) == 0, "fb state: rig");
	r.f.p[1].fallback_allowed = r.f.p[2].fallback_allowed = 1;
	OK(set_fallback(&r, B) == 0 && fallback_code(&r, true) == 0 && fake22_enabled(&r.f) == 1,
	   "fb state: B the fallback, enabled by ExecuteFallbackMechanism");
	eimpkg_op(&ops, 0xA3, C, false);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 0 && fake22_enabled(&r.f) == 2,
	   "fb state: the eIM enables C");
	OK(set_fallback(&r, C) == 0, "fb state: B disabled by the eIM's enable, the attribute moves to C (6b)");
	OK(fallback_code(&r, false) == 6, "fb state: no return from fallback after the eIM's enable");
	rig_close(&r);

	/* the Fallback Profile enabled by an eIM enable, not by the mechanism:
	 * it is enabled all the same (6a, 3.4.7 1bii) */
	OK(rig_open(&r, 2) == 0, "fb state: rig 2");
	r.f.p[1].fallback_allowed = r.f.p[2].fallback_allowed = 1;
	OK(set_fallback(&r, B) == 0, "fb state: B the fallback");
	eimpkg_op(&ops, 0xA3, B, false);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 0 && fake22_enabled(&r.f) == 1,
	   "fb state: the eIM enables B");
	OK(set_fallback(&r, C) == 3, "fb state: set on C while B is enabled is fallbackProfileEnabled(3)");
	der_put(&ops, 0xA9, NULL, 0);   /* unsetFallbackAttribute */
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x8E) == 3,
	   "fb state: unset while B is enabled is fallbackProfileEnabled(3)");
	eimpkg_op(&ops, 0xA3, A, false);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x83) == 0, "fb state: the eIM enables A");
	der_put(&ops, 0xA9, NULL, 0);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x8E) == 0, "fb state: unset with B disabled: ok");

	/* a deleted Fallback Profile takes its attribute with it (3.4.3 NOTE:
	 * deleting the Fallback Profile is allowed) */
	OK(set_fallback(&r, C) == 0, "fb state: C the fallback");
	eimpkg_op(&ops, 0xA5, C, false);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x85) == 0, "fb state: C deleted");
	der_put(&ops, 0xA9, NULL, 0);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x8E) == 2,
	   "fb state: unset after the delete is noFallbackAttribute(2)");
	rig_close(&r);

	/* delete of the profile to return to (3.4.3 step 2c): refused only
	 * while the Fallback Profile is enabled on the card */
	OK(rig_open(&r, 2) == 0, "fb state: rig 3");
	r.f.p[1].fallback_allowed = 1;
	OK(set_fallback(&r, B) == 0 && fallback_code(&r, true) == 0, "fb state: A to B by the mechanism");
	eimpkg_op(&ops, 0xA5, A, false);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x85) == 21 && r.f.p[0].present,
	   "fb state: deleting A (the way back) while B is enabled is returnFallbackProfile(21)");
	r.f.p[1].enabled = 0;   /* switched on the card without ipad */
	r.f.p[2].enabled = 1;
	eimpkg_op(&ops, 0xA5, A, false);
	OK(run_ops(&r, &ops, &resp, &res) && int_in(&res, 0x85) == 0 && !r.f.p[0].present,
	   "fb state: with B no longer enabled, A may be deleted");
	rig_close(&r);

	db_free(&ops);
	db_free(&resp);
}

/* the listProfileInfo result of one package; its BF2D in *lst */
static bool list_psmo(rig *r, const uint8_t *req, size_t len, dbuf *resp, der_tlv *lst)
{
	dbuf ops;
	der_tlv res;
	bool ok;

	db_init(&ops);
	db_put(&ops, req, len);
	ok = rig_run(r, &ops, resp, &res) && der_find(res.val, res.len, 0xBF2D, lst) == 0 &&
	     der_find(lst->val, lst->len, 0xA0, lst) == 0;
	db_free(&ops);
	return ok;
}

/* the i-th ProfileInfo's member tags, in order, as hex ("5A 9F70 ...") */
static void members(const der_tlv *list, int i, char *out, size_t cap)
{
	const uint8_t *p = list->val, *end = list->val + list->len;
	der_tlv it, c;

	out[0] = 0;
	while (p < end && der_next(&p, end, &it) == 0)
		if (i-- == 0) {
			const uint8_t *q = it.val, *qe = it.val + it.len;

			while (q < qe && der_next(&q, qe, &c) == 0) {
				size_t l = strlen(out);

				snprintf(out + l, cap - l, "%s%X", l ? " " : "", (unsigned)c.tag);
			}
			return;
		}
}

/* PSMO listProfileInfo (2.11.1.1.3): SGP.32's default tag list, and the
 * fallbackAttribute the SGP.22 card cannot have, from the emulation */
static void test_list_profile_info(void)
{
	static const uint8_t none[] = { 0xBF, 0x2D, 0x00 };
	static const uint8_t no_iccid[] = { 0xBF, 0x2D, 0x05, 0x5C, 0x03, 0x9F, 0x26, 0x91 };
	static const uint8_t no_fb[] = { 0xBF, 0x2D, 0x05, 0x5C, 0x03, 0x5A, 0x9F, 0x70 };
	static const uint8_t dflt[] = { 0x5A, 0x4F, 0x9F, 0x70, 0x91, 0x92, 0x95, 0x9F, 0x7B, 0x9F, 0x67 };
	static const uint8_t dflt22[] = { 0x5A, 0x4F, 0x9F, 0x70, 0x91, 0x92, 0x95 };
	/* the list the eIM asked of a consumer card that refused it (router 245) */
	static const uint8_t eim_list[] = { 0xBF, 0x2D, 0x12, 0x5C, 0x10, 0x5A, 0x4F, 0x9F, 0x70, 0x90, 0x91, 0x92,
	                                    0x95, 0x99, 0x9F, 0x7B, 0xB7, 0x9F, 0x26, 0x9F, 0x67 };
	static const uint8_t eim_list22[] = { 0x5A, 0x4F, 0x9F, 0x70, 0x90, 0x91, 0x92, 0x95, 0x99, 0xB7 };
	rig r;
	dbuf resp;
	der_tlv lst;
	char m[128];
	int refusals;

	db_init(&resp);
	OK(rig_open(&r, 2) == 0, "listProfileInfo: rig");
	r.f.p[1].fallback_allowed = 1;
	OK(set_fallback(&r, "98001032547698103224") == 0, "listProfileInfo: B the fallback");

	/* no tag list: the card is sent SGP.32's default, less 9F26 */
	OK(list_psmo(&r, none, sizeof(none), &resp, &lst), "listProfileInfo: default, answered");
	EQ_HEX(r.f.last_taglist, r.f.last_taglist_len, dflt, sizeof(dflt),
	       "listProfileInfo: the card got SGP.32's default tag list, without 9F26");
	members(&lst, 1, m, sizeof(m));
	OK(!strcmp(m, "5A 9F70 91 9F26 9F67"), "listProfileInfo: B has 9F26 TRUE, before 9F67 (declaration order)");
	members(&lst, 0, m, sizeof(m));
	OK(!strcmp(m, "5A 9F70 91"), "listProfileInfo: A has no 9F26 (DEFAULT FALSE)");
	{
		der_tlv b, x;
		const uint8_t *p = lst.val;

		der_next(&p, lst.val + lst.len, &b);
		der_next(&p, lst.val + lst.len, &b);
		OK(der_find(b.val, b.len, 0x9F26, &x) == 0 && x.len == 1 && x.val[0] == 0xFF,
		   "listProfileInfo: 9F26 is DER TRUE (FF)");
	}

	/* a tag list without the ICCID: asked of the card, dropped again */
	OK(list_psmo(&r, no_iccid, sizeof(no_iccid), &resp, &lst), "listProfileInfo: 9F26 91, answered");
	members(&lst, 1, m, sizeof(m));
	OK(!strcmp(m, "91 9F26"), "listProfileInfo: only what was asked (91 9F26), no ICCID");
	members(&lst, 0, m, sizeof(m));
	OK(!strcmp(m, "91"), "listProfileInfo: A: 91 alone");

	/* a tag list without 9F26: none added */
	OK(list_psmo(&r, no_fb, sizeof(no_fb), &resp, &lst), "listProfileInfo: 5A 9F70, answered");
	members(&lst, 1, m, sizeof(m));
	OK(!strcmp(m, "5A 9F70"), "listProfileInfo: no 9F26 when not asked for");

	/* a card that refuses 9F7B / 9F67 is asked again without them */
	r.f.refuse_taglist = 1;
	OK(list_psmo(&r, none, sizeof(none), &resp, &lst), "listProfileInfo, tags refused: answered");
	EQ_HEX(r.f.last_taglist, r.f.last_taglist_len, dflt22, sizeof(dflt22),
	       "listProfileInfo, tags refused: asked again without 9F7B 9F67");
	members(&lst, 1, m, sizeof(m));
	OK(!strcmp(m, "5A 9F70 91 9F26"), "listProfileInfo, tags refused: 9F26 still on B");
	/* the package's own profile check was refused too (9F67), once */
	refusals = r.f.taglist_refusals;
	OK(refusals == 2, "listProfileInfo, tags refused: refused once each, the check and the PSMO");
	emu_close(r.e);
	r.e = emu_open(&r.c, &r.cfg);
	OK(r.e && list_psmo(&r, none, sizeof(none), &resp, &lst) && r.f.taglist_refusals == refusals,
	   "listProfileInfo, tags refused: not asked with them again, also after a restart");

	/* refused with profileInfoListError instead of a status word (a consumer
	 * card, for the eIM's list): asked again without 9F7B 9F67, never 9F26 */
	r.f.refuse_taglist = 2;
	OK(list_psmo(&r, eim_list, sizeof(eim_list), &resp, &lst),
	   "listProfileInfo, profileInfoListError: answered on the second try");
	EQ_HEX(r.f.last_taglist, r.f.last_taglist_len, eim_list22, sizeof(eim_list22),
	       "listProfileInfo, profileInfoListError: asked again without 9F7B 9F26 9F67");
	members(&lst, 1, m, sizeof(m));
	OK(!strcmp(m, "5A 9F70 91 9F26"), "listProfileInfo, profileInfoListError: 9F26 still on B");

	/* refused again: the card's error is the result */
	r.f.refuse_taglist = 3;
	/* list_psmo's failed search for A0 leaves lst on BF2D's last member */
	OK(!list_psmo(&r, eim_list, sizeof(eim_list), &resp, &lst) && lst.tag == 0x81 &&
	   lst.len == 1 && lst.val[0] == 1,
	   "listProfileInfo, refused twice: the card's profileInfoListError passed on");
	rig_close(&r);
	db_free(&resp);
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
	test_card_outcomes();
	test_fallback();
	test_fallback_card_state();
	test_list_profile_info();
	db_free(&req);
	db_free(&resp);
	db_free(&ops);
	simcard_free(&s);
	crypto_key_free(eim_key);
	crypto_key_free(dev_key);
	DONE("test_emu");
}
