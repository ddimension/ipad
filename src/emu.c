/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The ES10 functions of the virtual SGP.32 ISD-R (see emu.h). Section
 * numbers are SGP.32 v1.3 unless SGP.22 is named; the ASN.1 is
 * spec/SGP32Definitions.asn and spec/RSPDefinitions.asn (SGP.22 v2.7).
 */
#define _POSIX_C_SOURCE 200809L   /* strdup */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "emu_int.h"

/* --- small helpers ---------------------------------------------------------- */

static void put_seq(dbuf *b, uint32_t tag, const dbuf *content)
{
	der_put(b, tag, content->d, content->len);
}

/* an ES10 function on the SGP.22 card */
static int card_call(emu *e, const dbuf *req, dbuf *resp)
{
	return card_es10(e->card, req->d, req->len, resp);
}

/* the single INTEGER result inside a response like BF31 { 80 01 00 } */
static int result_of(const dbuf *resp, uint32_t tag, int64_t *v)
{
	der_tlv t, r;

	if (der_parse(resp->d, resp->len, &t) < 0 || t.tag != tag ||
	    der_find(t.val, t.len, 0x80, &r) < 0 || der_get_int(&r, v) < 0)
		return -1;
	return 0;
}

/* ES10c.EnableProfile / DisableProfile (SGP.22 5.7.16/5.7.17): refreshFlag
 * FALSE. The host resets the SIM after a change (wwand's apply after a
 * profile switch); a REFRESH here would reset it a second time under it. */
static int64_t card_switch(emu *e, uint32_t tag, const uint8_t iccid[10])
{
	dbuf req, resp;
	size_t m, c;
	int64_t v = 127;

	db_init(&req);
	db_init(&resp);
	m = der_begin(&req, tag);
	c = der_begin(&req, 0xA0);
	der_put(&req, 0x5A, iccid, 10);
	der_end(&req, c);
	der_put_bool(&req, 0x81, false);
	der_end(&req, m);

	if (card_call(e, &req, &resp) < 0 || result_of(&resp, tag, &v) < 0)
		v = 127;
	db_free(&req);
	db_free(&resp);
	return v;
}

static int64_t card_delete(emu *e, const uint8_t iccid[10])
{
	dbuf req, resp;
	size_t m;
	int64_t v = 127;

	db_init(&req);
	db_init(&resp);
	m = der_begin(&req, 0xBF33);   /* DeleteProfileRequest ::= [51] CHOICE, explicit */
	der_put(&req, 0x5A, iccid, 10);
	der_end(&req, m);

	if (card_call(e, &req, &resp) < 0 || result_of(&resp, 0xBF33, &v) < 0)
		v = 127;
	db_free(&req);
	db_free(&resp);
	return v;
}

/* --- the card's profiles ------------------------------------------------------ */

typedef struct {
	uint8_t iccid[10];
	bool enabled;
	bool fallback_allowed;
	bool gone;                       /* deleted by the package being run */
} prof;

#define MAX_PROF 32

/* Whether a GetProfilesInfo answer refused the tag list itself: a
 * profileInfoListError (SGP.22 5.7.15, ProfileInfoListResponse [1] under
 * AUTOMATIC TAGS: BF2D 81 01 xx), or SW 6A80, incorrect parameters in the
 * command data (ISO/IEC 7816-4 5.6, what SGP.22 5.7.20 answers to a tag list
 * it cannot serve). Only these may be remembered as a quirk: any other
 * status word (6F00, 6581 memory failure, 6985 conditions not satisfied) or
 * an answer that does not parse can be a one-off, and remembering it would
 * cost a card that knows 9F67 its fallbackAllowed for good. */
static bool taglist_refused(const card *c, int rc, const dbuf *resp)
{
	der_tlv t, x, ok;
	int64_t v;

	if (rc < 0)
		return c->sw == 0x6A80;
	/* The CHOICE holds one alternative: an answer carrying the list as
	 * well is garbage, not a refusal, and so is an error value the ASN.1
	 * does not name (ProfileInfoListError ::= INTEGER {
	 * incorrectInputValues(1), undefinedError(127)}); garbage must not
	 * set a quirk that lasts for good. */
	return der_parse(resp->d, resp->len, &t) == 0 && t.tag == 0xBF2D && der_find(t.val, t.len, 0xA0, &ok) < 0 &&
	       der_find(t.val, t.len, 0x81, &x) == 0 && der_get_int(&x, &v) == 0 && (v == 1 || v == 127);
}

/* GetProfilesInfo (SGP.22 5.7.15) as a parsed answer: 0 with *list set;
 * -2 when the card refused the tag list (taglist_refused); -1 for anything
 * else, no answer included: a failure for this call only */
static int profiles_query(emu *e, const uint8_t *req, size_t len, dbuf *resp, der_tlv *list)
{
	der_tlv t;
	int rc;

	resp->len = 0;
	e->card->sw = 0;
	rc = card_es10(e->card, req, len, resp);
	if (taglist_refused(e->card, rc, resp))
		return -2;
	if (rc < 0 || der_parse(resp->d, resp->len, &t) < 0 || t.tag != 0xBF2D || der_find(t.val, t.len, 0xA0, list) < 0)
		return -1;
	return 0;
}

/* the card refused something once: not asked again, the state remembers */
static void quirk(emu *e, int q)
{
	e->quirks |= q;
	emu_state_save(e);
}

/* The card's profiles, with state and fallbackAllowed.
 *
 * fallbackAllowed ('9F67') has to be asked for by name: the default tag
 * list ('BF2D 00') holds only the tags SGP.22 5.7.15 marks (*), and 9F67 is
 * not one of them, so a card that stores the flag still leaves it out of a
 * default answer, and every setFallbackAttribute (3.4.6 step 4) would be
 * fallbackNotAllowed. A card that does not know 9F67 may refuse the whole
 * tag list (SGP.22 5.7.20, GetEID, answers an unsupported tag list with an
 * error status word; 5.7.15 does not say), so the list without it is asked
 * next, and the flag then counts as absent, which is what 3.4.6 makes of an
 * absent flag anyway. A card that refused (taglist_refused), and answered
 * the list without it, is not asked with 9F67 again (EMU_Q_NO_9F67): each
 * such query cost a refused exchange on every run. Any other failure of the
 * query (no answer, 6F00, 6581, ...) falls back to the list without 9F67
 * for this call only.
 *
 * That list is { 5A 9F70 }, the very request ipa_enabled_iccid sends
 * before every package, so the card layer answers it from its cache (card.h)
 * and it costs no exchange of its own. The default list ('BF2D 00') is
 * asked only when that fails too: it carries every starred tag, icons
 * included (router 245: about 1.6 KB of GET RESPONSE), for two of them. */
static int profiles(emu *e, prof *out, int cap)
{
	static const uint8_t with_fb[] = {   /* 5C { 5A 9F70 9F67 } */
		0xBF, 0x2D, 0x07, 0x5C, 0x05, 0x5A, 0x9F, 0x70, 0x9F, 0x67
	};
	static const uint8_t no_fb[] = { 0xBF, 0x2D, 0x05, 0x5C, 0x03, 0x5A, 0x9F, 0x70 };
	static const uint8_t dflt[] = { 0xBF, 0x2D, 0x00 };
	dbuf resp;
	der_tlv list, it, x;
	const uint8_t *p, *end;
	int n = 0, rc = -2;

	db_init(&resp);
	if (!(e->quirks & EMU_Q_NO_9F67))
		rc = profiles_query(e, with_fb, sizeof(with_fb), &resp, &list);
	if (rc < 0) {
		if (profiles_query(e, no_fb, sizeof(no_fb), &resp, &list) < 0 &&
		    profiles_query(e, dflt, sizeof(dflt), &resp, &list) < 0) {
			db_free(&resp);
			return -1;
		}
		if (rc == -2 && !(e->quirks & EMU_Q_NO_9F67))
			quirk(e, EMU_Q_NO_9F67);
	}

	for (p = list.val, end = list.val + list.len; p < end && n < cap; ) {
		if (der_next(&p, end, &it) < 0 || it.tag != 0xE3)
			break;
		if (der_find(it.val, it.len, 0x5A, &x) < 0 || x.len != 10)
			continue;
		memcpy(out[n].iccid, x.val, 10);
		out[n].gone = false;
		out[n].enabled = der_find(it.val, it.len, 0x9F70, &x) == 0 && x.len == 1 && x.val[0] == 1;
		out[n].fallback_allowed = e->cfg.fallback_allowed ||
			(der_find(it.val, it.len, 0x9F67, &x) == 0 && x.len == 1 && x.val[0]);
		n++;
	}

	db_free(&resp);
	return n;
}

static prof *find_prof(prof *ps, int n, const uint8_t *iccid)
{
	int i;

	for (i = 0; i < n; i++)
		if (!ps[i].gone && !memcmp(ps[i].iccid, iccid, 10))
			return &ps[i];
	return NULL;
}

static prof *enabled_prof(prof *ps, int n)
{
	int i;

	for (i = 0; i < n; i++)
		if (!ps[i].gone && ps[i].enabled)
			return &ps[i];
	return NULL;
}

/* The Fallback Profile as the card has it: the profile carrying the
 * attribute, NULL when no profile does or it is no longer on the card. Its
 * state comes from the card's list (and, inside a package, from what the
 * package did to it), never from a record of what ipad last did: the card's
 * profiles also change through lpac, an eUICCMemoryReset or an eIM enable. */
static prof *fallback_prof(const emu *e, prof *ps, int np)
{
	return e->fb_set ? find_prof(ps, np, e->fb_iccid) : NULL;
}

/* --- ProfileInfo lists with the fallback attribute ----------------------------- */

/* An SGP.22 card has no fallbackAttribute ('9F26'); the emulation keeps it
 * and writes it into the card's ProfileInfo. ProfileInfo is a SEQUENCE, so
 * DER puts its members in declaration order (X.690 8.9.2 via 10): in
 * SGP32Definitions.asn only fallbackAllowed '9F67' and iotSpecificProfileInfo
 * 'BF64' follow fallbackAttribute, so 9F26 goes before the first of those. It
 * is DEFAULT FALSE, and DER omits a default value (X.690 11.5), so only the
 * Fallback Profile carries it, as TRUE. */
static void put_profile_info(dbuf *out, const der_tlv *it, bool add_fb, bool keep_iccid)
{
	size_t s = der_begin(out, 0xE3);
	const uint8_t *p = it->val, *end = it->val + it->len;
	der_tlv c;

	while (p < end && der_next(&p, end, &c) == 0) {
		if (add_fb && (c.tag == 0x9F67 || c.tag == 0xBF64)) {
			der_put_bool(out, 0x9F26, true);
			add_fb = false;
		}
		/* the ICCID was asked for only to find the Fallback Profile */
		if ((c.tag == 0x5A && !keep_iccid) || c.tag == 0x9F26)
			continue;
		db_put(out, c.raw, c.raw_len);
	}
	if (add_fb)
		der_put_bool(out, 0x9F26, true);
	der_end(out, s);
}

/* the card's ProfileInfoListResponse with 9F26 on the Fallback Profile when
 * with_fb; -1 when it is no list (an error the caller passes on as it is) */
static int put_profile_list(const emu *e, const dbuf *resp, bool with_fb, bool keep_iccid, dbuf *out)
{
	der_tlv top, list, it, x;
	const uint8_t *p, *end;
	size_t m, l;

	if (der_parse(resp->d, resp->len, &top) < 0 || top.tag != 0xBF2D ||
	    der_find(top.val, top.len, 0xA0, &list) < 0)
		return -1;

	m = der_begin(out, 0xBF2D);
	l = der_begin(out, 0xA0);
	for (p = list.val, end = list.val + list.len; p < end; ) {
		if (der_next(&p, end, &it) < 0)
			break;
		if (it.tag != 0xE3) {
			db_put(out, it.raw, it.raw_len);
			continue;
		}
		put_profile_info(out, &it, with_fb && e->fb_set &&
		                 der_find(it.val, it.len, 0x5A, &x) == 0 && x.len == 10 &&
		                 !memcmp(x.val, e->fb_iccid, 10), keep_iccid);
	}
	der_end(out, l);
	der_end(out, m);
	return 0;
}

/* the tags of a tag list ('5C' value) in order; their count */
static int tag_list(const uint8_t *v, size_t len, uint32_t *tags, int cap)
{
	const uint8_t *p = v, *end = v + len;
	int n = 0;

	while (p < end && n < cap) {
		uint32_t t = *p++;

		if ((t & 0x1F) == 0x1F)   /* multi-byte tag: more follow while b8 is set */
			while (p < end) {
				uint8_t b = *p++;

				t = t << 8 | b;
				if (!(b & 0x80))
					break;
			}
		tags[n++] = t;
	}
	return n;
}

static void put_tag(dbuf *b, uint32_t t)
{
	uint8_t o[4];
	size_t n = t > 0xFFFFFF ? 4 : t > 0xFFFF ? 3 : t > 0xFF ? 2 : 1, i;

	for (i = 0; i < n; i++)
		o[i] = (uint8_t)(t >> (8 * (n - 1 - i)));
	db_put(b, o, n);
}

static bool has_tag(const uint32_t *tags, int n, uint32_t t)
{
	int i;

	for (i = 0; i < n; i++)
		if (tags[i] == t)
			return true;
	return false;
}

/* PSMO listProfileInfo (2.11.1.1.3, 5.9.14): its result is a
 * ProfileInfoListResponse, which goes into the results as [45] itself.
 *
 * - Without a tag list SGP.32 has its own default (2.11.1.1.3: 5A 4F 9F70 91
 *   92 95 9F7B 9F26 9F67), not SGP.22's, which has 90 93 94 and none of the
 *   SGP.32 tags; so the card is always sent an explicit tag list.
 * - 9F26 is never asked of the card; it comes from the emulation's record,
 *   and only when the list (the eIM's or the default) contains it.
 * - The ICCID is always asked for, as the only way to find the Fallback
 *   Profile in the answer, and dropped again when the eIM did not ask.
 * - A card that refuses the list for an SGP.32 tag it does not know (9F7B,
 *   9F67), by status word or by profileInfoListError, is asked once more
 *   without them, and its answer to that one is passed on. Once it has
 *   refused (taglist_refused) and then answered, it is asked without them
 *   from the start (EMU_Q_NO_IOT_TAGS); any other failure of the first
 *   attempt is retried without them for this call only. A requested data object that a profile does not
 *   have is omitted (SGP.22 5.7.15), which is what an SGP.22 card's profile
 *   is for those tags.
 * searchCriteria and iotSpecificTagList go to the card as the eIM sent them. */
static int64_t list_profile_info(emu *e, const der_tlv *op, dbuf *res)
{
	static const uint32_t dflt[] = { 0x5A, 0x4F, 0x9F70, 0x91, 0x92, 0x95, 0x9F7B, 0x9F26, 0x9F67 };
	uint32_t want[64];
	int nwant, i, attempt, rc;
	der_tlv x;
	dbuf req, resp;
	bool with_fb, keep_iccid, strip, sent = false, first_refused = false;
	int64_t v = 0;

	if (der_find(op->val, op->len, 0x5C, &x) == 0) {
		nwant = tag_list(x.val, x.len, want, 64);
	} else {
		nwant = (int)(sizeof(dflt) / sizeof(dflt[0]));
		memcpy(want, dflt, sizeof(dflt));
	}
	with_fb = has_tag(want, nwant, 0x9F26);
	keep_iccid = has_tag(want, nwant, 0x5A);
	strip = has_tag(want, nwant, 0x9F7B) || has_tag(want, nwant, 0x9F67);

	db_init(&req);
	db_init(&resp);
	for (attempt = strip && (e->quirks & EMU_Q_NO_IOT_TAGS); attempt < (strip ? 2 : 1) && !sent; attempt++) {
		der_tlv top;
		size_t m, l;

		req.len = resp.len = 0;
		m = der_begin(&req, 0xBF2D);
		if (der_find(op->val, op->len, 0xA0, &x) == 0)
			db_put(&req, x.raw, x.raw_len);
		l = der_begin(&req, 0x5C);
		if (!keep_iccid)
			put_tag(&req, 0x5A);
		for (i = 0; i < nwant; i++)
			if (want[i] != 0x9F26 && !(attempt == 1 && (want[i] == 0x9F7B || want[i] == 0x9F67)))
				put_tag(&req, want[i]);
		der_end(&req, l);
		if (der_find(op->val, op->len, 0x5D, &x) == 0)
			db_put(&req, x.raw, x.raw_len);
		der_end(&req, m);
		e->card->sw = 0;
		rc = req.err ? -1 : card_call(e, &req, &resp);
		sent = rc == 0;
		/* SGP.22 only reserves 9F7B/9F67 (5.7.15) */
		if (sent && attempt == 0 && strip && der_parse(resp.d, resp.len, &top) == 0 &&
		    der_find(top.val, top.len, 0xA0, &x) < 0)
			sent = false;
		if (attempt == 1 && sent && first_refused)
			quirk(e, EMU_Q_NO_IOT_TAGS);
		/* only a refusal of the list is remembered; anything else asks
		 * without the tags for this call only */
		first_refused = attempt == 0 && !req.err && taglist_refused(e->card, rc, &resp);
	}

	if (!sent) {
		der_put_int(res, 0x02, 127);   /* processingTerminated undefinedError */
		v = 127;
	} else if (put_profile_list(e, &resp, with_fb, keep_iccid, res) < 0) {
		db_put(res, resp.d, resp.len);   /* the card's profileInfoListError */
	}
	db_free(&req);
	db_free(&resp);
	return v;
}

/* --- signed results -------------------------------------------------------- */

/* EuiccPackageResultDataSigned (2.11.2.1) signed with the device key and
 * wrapped: BF51 { A0 { 30 {data}, 5F37 sig } }. Also stored, with its
 * sequence number, until the IPA removes it after delivery (2.11.2). */
static int sign_epr(emu *e, const emu_eim *m, const char *eim_id, int64_t counter,
                    const uint8_t *txid, size_t txid_len, const dbuf *results, dbuf *out)
{
	dbuf data, input;
	uint8_t sig[CRYPTO_SIG_LEN];
	size_t d, a, r;
	int64_t seq = e->seq < EMU_SEQ_BASE ? EMU_SEQ_BASE : e->seq + 1;

	db_init(&data);
	d = der_begin(&data, 0x30);
	der_put_str(&data, 0x80, eim_id);
	der_put_int(&data, 0x81, counter);
	if (txid_len)
		der_put(&data, 0x82, txid, txid_len);
	der_put_int(&data, 0x83, seq);
	put_seq(&data, 0x30, results);
	der_end(&data, d);

	db_init(&input);
	db_put(&input, data.d, data.len);
	emu_assoc_do(m, &input);

	if (data.err || input.err || crypto_sign(e->cfg.key, input.d, input.len, sig) < 0) {
		db_free(&data);
		db_free(&input);
		return -1;
	}

	a = der_begin(out, 0xBF51);
	r = der_begin(out, 0xA0);
	db_put(out, data.d, data.len);
	der_put(out, 0x5F37, sig, sizeof(sig));
	der_end(out, r);
	der_end(out, a);
	db_free(&data);
	db_free(&input);

	if (out->err)
		return -1;

	e->seq = seq;

	/* keep it; at capacity the oldest goes, as 2.11.2 prescribes */
	if (e->neprs == EMU_MAX_EPRS) {
		db_free(&e->eprs[0]);
		memmove(&e->eprs[0], &e->eprs[1], sizeof(e->eprs[0]) * (EMU_MAX_EPRS - 1));
		memmove(&e->epr_seq[0], &e->epr_seq[1], sizeof(e->epr_seq[0]) * (EMU_MAX_EPRS - 1));
		e->neprs--;
	}
	db_init(&e->eprs[e->neprs]);
	db_put(&e->eprs[e->neprs], out->d, out->len);
	e->epr_seq[e->neprs++] = seq;
	return 0;
}

/* EuiccPackageErrorSigned: BF51 { A1 { 30 {80 id, 81 counter, 82 txid, 02 code}, 5F37 } } */
static int sign_epe(emu *e, const emu_eim *m, int64_t counter, const uint8_t *txid, size_t txid_len,
                    int64_t code, dbuf *out)
{
	dbuf data, input;
	uint8_t sig[CRYPTO_SIG_LEN];
	size_t d, a, r;
	int rc = -1;

	db_init(&data);
	d = der_begin(&data, 0x30);
	der_put_str(&data, 0x80, m->id);
	der_put_int(&data, 0x81, counter);
	if (txid_len)
		der_put(&data, 0x82, txid, txid_len);
	der_put_int(&data, 0x02, code);
	der_end(&data, d);

	db_init(&input);
	db_put(&input, data.d, data.len);
	emu_assoc_do(m, &input);

	if (!data.err && !input.err && crypto_sign(e->cfg.key, input.d, input.len, sig) == 0) {
		a = der_begin(out, 0xBF51);
		r = der_begin(out, 0xA1);
		db_put(out, data.d, data.len);
		der_put(out, 0x5F37, sig, sizeof(sig));
		der_end(out, r);
		der_end(out, a);
		rc = out->err ? -1 : 0;
	}
	db_free(&data);
	db_free(&input);
	return rc;
}

/* EuiccPackageErrorUnsigned: BF51 { A2 { 80 id, 82 txid, 84 token, 8F code } };
 * the token if and only if one is configured (5.9.1) */
static void unsigned_error(const char *eim_id, const emu_eim *m, const uint8_t *txid,
                           size_t txid_len, int64_t code, dbuf *out)
{
	size_t a = der_begin(out, 0xBF51), r = der_begin(out, 0xA2);

	der_put_str(out, 0x80, eim_id);
	if (txid_len)
		der_put(out, 0x82, txid, txid_len);
	if (m && m->has_token)
		der_put_int(out, 0x84, m->token);
	if (code >= 0)
		der_put_int(out, 0x8F, code);
	der_end(out, r);
	der_end(out, a);
}

/* --- ES10b.LoadEuiccPackage (5.9.1) ----------------------------------------- */

/* What one package run has done so far. An IoT eUICC marks profiles in step 5
 * of 3.3.1 and switches them in step 8b, after the result is signed, and can
 * do so because 5.9.1 makes the whole function atomic. An SGP.22 card is not
 * atomic and its answer is the only evidence of what it did, so here every
 * enable, disable and delete is run on the card as its PSMO is reached, and
 * the PSMO's result is the card's answer (see load_euicc_package). */
typedef struct {
	bool enable_done, disable_done;  /* one of each per package (3.4.1, 3.4.2) */
	/* the profile an earlier PSMO of this package disabled: 3.4.1 step 2
	 * counts a profile "marked to be disabled" as the one to roll back to */
	bool off_set;
	uint8_t off_iccid[10];
	bool grant_rb;                   /* an enable with rollbackFlag the card carried out */
	uint8_t rb_iccid[10];
	int del_eim;          /* index of an eIM deleted by deleteEim, applied after signing */
} pkgrun;

/* The SGP.22 card's result code (SGP.22 5.7.16-5.7.18, RSPDefinitions.asn
 * EnableProfileResponse / DisableProfileResponse / DeleteProfileResponse) as
 * the SGP.32 PSMO result (SGP32Definitions.asn EnableProfileResult /
 * DisableProfileResult / DeleteProfileResult). The values both define carry
 * the same meaning under the same number; what SGP.32 does not define for
 * that PSMO (SGP.22's wrongProfileReenabling(4), catBusy(5) on a delete, a
 * value outside either list, or no parsable answer) becomes undefinedError,
 * because the eIM decodes the value against SGP.32's list and an unknown
 * number there says nothing true. */
static int64_t psmo_code(uint32_t es10_tag, int64_t v)
{
	switch (v) {
	case 0:     /* ok */
	case 1:     /* iccidOrAidNotFound */
	case 2:     /* profileNotInDisabledState / profileNotInEnabledState */
	case 3:     /* disallowedByPolicy */
		return v;
	case 5:     /* catBusy: in EnableProfileResult and DisableProfileResult only */
		return es10_tag == 0xBF33 ? 127 : 5;
	}
	return 127;
}

/* one PSMO; returns its result code (0 ok), writes its EuiccResultData.
 * ps is the card's profile list, kept up to date with what this package
 * has done to the card */
static int64_t psmo(emu *e, pkgrun *k, prof *ps, int np, const der_tlv *op, dbuf *res)
{
	der_tlv x;
	prof *p, *en;
	int64_t v = 0;
	int i;

	switch (op->tag) {
	case 0xA3:   /* enable (3.4.1) */
		if (k->enable_done || der_find(op->val, op->len, 0x5A, &x) < 0 || x.len != 10) {
			v = 127;
		} else if (!(p = find_prof(ps, np, x.val))) {
			v = 1;   /* iccidOrAidNotFound */
		} else {
			bool rb = der_find(op->val, op->len, 0x05, &x) == 0;   /* rollbackFlag NULL */
			const uint8_t *back;

			en = enabled_prof(ps, np);
			back = en ? en->iccid : (k->off_set ? k->off_iccid : NULL);
			k->enable_done = true;
			if (p->enabled)
				v = 2;    /* profileNotInDisabledState */
			else if (rb && !back)
				v = 20;   /* rollbackNotAvailable */
			else if ((v = psmo_code(0xBF31, card_switch(e, 0xBF31, p->iccid))) == 0) {
				/* SGP.22 disables the enabled profile itself */
				for (i = 0; i < np; i++)
					ps[i].enabled = false;
				p->enabled = true;
				if (rb) {
					k->grant_rb = true;
					memcpy(k->rb_iccid, back, 10);
				}
				/* enabling clears the fallback reference (3.4.1 step 3) */
				e->fb_prev_set = false;
			}
		}
		der_put_int(res, 0x83, v);
		return v;

	case 0xA4:   /* disable (3.4.2) */
		if (k->enable_done || k->disable_done || der_find(op->val, op->len, 0x5A, &x) < 0 || x.len != 10)
			v = 127;
		else if (!(p = find_prof(ps, np, x.val)))
			v = 1;
		else if (!p->enabled)
			v = 2;    /* profileNotInEnabledState */
		else {
			k->disable_done = true;
			if ((v = psmo_code(0xBF32, card_switch(e, 0xBF32, p->iccid))) == 0) {
				p->enabled = false;
				k->off_set = true;
				memcpy(k->off_iccid, p->iccid, 10);
			}
		}
		der_put_int(res, 0x84, v);
		return v;

	case 0xA5:   /* delete (3.4.3) */
		if (der_find(op->val, op->len, 0x5A, &x) < 0 || x.len != 10)
			v = 127;
		else if (!(p = find_prof(ps, np, x.val)))
			v = 1;
		else if (p->enabled)
			v = 2;    /* profileNotInDisabledState */
		else if ((k->grant_rb && !memcmp(k->rb_iccid, p->iccid, 10)) ||
		         (e->rb_granted && !memcmp(e->rb_iccid, p->iccid, 10)))
			v = 20;   /* rollbackNotAvailable */
		else if ((en = fallback_prof(e, ps, np)) && en->enabled &&
		         e->fb_prev_set && !memcmp(e->fb_prev, p->iccid, 10))
			v = 21;   /* returnFallbackProfile: the way back from the enabled Fallback Profile */
		else if ((v = psmo_code(0xBF33, card_delete(e, p->iccid))) == 0)
			p->gone = true;
		der_put_int(res, 0x85, v);
		return v;

	case 0xBF2D:   /* listProfileInfo */
		return list_profile_info(e, op, res);

	case 0xA6: { /* getRAT: SGP.22 ES10b.GetRAT, the table itself as [6] */
		uint8_t req[] = { 0xBF, 0x43, 0x00 };
		dbuf resp;
		der_tlv t, rat;

		db_init(&resp);
		if (card_es10(e->card, req, sizeof(req), &resp) == 0 &&
		    der_parse(resp.d, resp.len, &t) == 0 && der_find(t.val, t.len, 0xA0, &rat) == 0) {
			der_put(res, 0xA6, rat.val, rat.len);
		} else {
			der_put_int(res, 0x02, 127);
			v = 127;
		}
		db_free(&resp);
		return v;
	}

	case 0xA7:   /* configureImmediateEnable (3.4.4) */
		e->ie_flag = der_find(op->val, op->len, 0x80, &x) == 0;
		if (der_find(op->val, op->len, 0x81, &x) == 0) {
			e->ie_oid.len = 0;
			db_put(&e->ie_oid, x.val, x.len);
		}
		if (der_find(op->val, op->len, 0x82, &x) == 0) {
			e->ie_addr.len = 0;
			db_put(&e->ie_addr, x.val, x.len);
		}
		der_put_int(res, 0x87, 0);
		return 0;

	case 0xA8:   /* setFallbackAttribute (3.4.6) */
		if (der_find(op->val, op->len, 0x5A, &x) < 0 || x.len != 10)
			v = 127;
		else if (!(p = find_prof(ps, np, x.val)))
			v = 1;
		else if (e->fb_set && !memcmp(e->fb_iccid, p->iccid, 10))
			v = 0;    /* already set: ok */
		else if (!p->fallback_allowed)
			v = 2;    /* fallbackNotAllowed */
		else if ((en = fallback_prof(e, ps, np)) && en->enabled)
			v = 3;    /* fallbackProfileEnabled (step 6a) */
		else {
			e->fb_set = true;
			memcpy(e->fb_iccid, p->iccid, 10);
		}
		der_put_int(res, 0x8D, v);
		return v;

	case 0xA9:   /* unsetFallbackAttribute (3.4.7) */
		if (!(en = fallback_prof(e, ps, np)))
			v = 2;    /* noFallbackAttribute: none set, or its profile deleted */
		else if (en->enabled)
			v = 3;    /* fallbackProfileEnabled */
		else
			e->fb_set = false;
		der_put_int(res, 0x8E, v);
		return v;

	case 0xBF65: { /* setDefaultDpAddress: SGP.22 ES10a.SetDefaultDpAddress (BF3F) */
		dbuf req, resp;
		size_t m;
		int64_t r = 127;

		if (der_find(op->val, op->len, 0x80, &x) < 0) {
			v = 127;
		} else {
			db_init(&req);
			db_init(&resp);
			m = der_begin(&req, 0xBF3F);
			der_put(&req, 0x80, x.val, x.len);
			der_end(&req, m);
			if (card_call(e, &req, &resp) < 0 || result_of(&resp, 0xBF3F, &r) < 0)
				r = 127;
			db_free(&req);
			db_free(&resp);
			v = r == 0 ? 0 : 127;
		}
		m = der_begin(res, 0xBF65);
		der_put_int(res, 0x80, v);
		der_end(res, m);
		return v;
	}
	}

	der_put_int(res, 0x02, 2);   /* processingTerminated unknownOrDamagedCommand */
	return 2;
}

/* rebuild a configuration: the stored one with the fields of an update laid
 * over it, in the SEQUENCE's field order (DER) */
static int merge_cfg(const dbuf *old, const uint8_t *upd, size_t ulen, dbuf *out)
{
	static const uint32_t order[] = { 0x80, 0x81, 0x82, 0x83, 0x84, 0xA5, 0xA6, 0x87, 0x88, 0x89, 0xAA };
	der_tlv o, t;
	size_t m, i;

	if (der_parse(old->d, old->len, &o) < 0)
		return -1;

	m = der_begin(out, 0x30);
	for (i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
		if (der_find(upd, ulen, order[i], &t) == 0 || der_find(o.val, o.len, order[i], &t) == 0)
			db_put(out, t.raw, t.raw_len);
	}
	der_end(out, m);
	return out->err ? -1 : 0;
}

/* one eCO (3.5.1); returns its result code, writes its EuiccResultData */
static int64_t eco(emu *e, pkgrun *k, const emu_eim *requester, const der_tlv *op, dbuf *res)
{
	der_tlv x;
	dbuf cfg;
	int64_t v = 0;
	size_t m;
	emu_eim *t;
	int i;

	switch (op->tag) {
	case 0xA8:   /* addEim: [8] EimConfigurationData, implicitly tagged */
	case 0xAA: { /* updateEim */
		char id[129] = { 0 };

		if (der_find(op->val, op->len, 0x80, &x) < 0 || x.len == 0 || x.len > 128) {
			v = op->tag == 0xA8 ? 7 : 1;   /* commandError / eimNotFound */
		} else {
			memcpy(id, x.val, x.len);
			t = emu_eim_find(e, id);
			db_init(&cfg);

			if (op->tag == 0xA8) {
				int64_t tok = 0;
				bool want_tok = der_find(op->val, op->len, 0x84, &x) == 0 && der_get_int(&x, &tok) == 0;

				if (t)
					v = 2;    /* associatedEimAlreadyExists */
				else if (e->neims == EMU_MAX_EIMS)
					v = 1;    /* insufficientMemory */
				else if (want_tok && tok != -1)
					v = 5;    /* invalidAssociationToken */
				else {
					dbuf stored;

					/* a generated token replaces the -1 request in what is stored */
					db_init(&stored);
					m = der_begin(&stored, 0x30);
					{
						const uint8_t *p = op->val, *end = op->val + op->len;
						der_tlv f;

						while (p < end && der_next(&p, end, &f) == 0)
							if (f.tag != 0x84)
								db_put(&stored, f.raw, f.raw_len);
					}
					der_end(&stored, m);

					if (emu_eim_from_cfg(&e->eims[e->neims], stored.d, stored.len) < 0) {
						v = 7;
					} else {
						emu_eim *n = &e->eims[e->neims++];

						if (want_tok) {
							n->has_token = true;
							n->token = ++e->token_ctr;
							m = der_begin(res, 0xA8);
							der_put_int(res, 0x84, n->token);
							der_end(res, m);
							db_free(&stored);
							db_free(&cfg);
							return 0;
						}
					}
					db_free(&stored);
				}
				m = der_begin(res, 0xA8);
				der_put_int(res, 0x02, v);
				der_end(res, m);
				db_free(&cfg);
				return v;
			}

			/* updateEim */
			if (!t)
				v = 1;
			else if (der_find(op->val, op->len, 0x84, &x) == 0)
				v = 7;    /* the token cannot be updated */
			else if (der_find(op->val, op->len, 0x83, &x) < 0 && der_find(op->val, op->len, 0xA5, &x) < 0 &&
			         der_find(op->val, op->len, 0x82, &x) < 0 && der_find(op->val, op->len, 0x81, &x) < 0 &&
			         der_find(op->val, op->len, 0x87, &x) < 0 && der_find(op->val, op->len, 0xA6, &x) < 0 &&
			         der_find(op->val, op->len, 0x88, &x) < 0)
				v = 7;    /* nothing to update */
			else {
				int64_t nc = t->counter;
				bool key = der_find(op->val, op->len, 0xA5, &x) == 0;

				if (der_find(op->val, op->len, 0x83, &x) == 0)
					der_get_int(&x, &nc);
				if (nc < t->counter && !key) {
					v = 7;   /* a lower counter only together with a new key */
				} else if (merge_cfg(&t->cfg, op->val, op->len, &cfg) < 0) {
					v = 127;
				} else {
					emu_eim n;

					if (emu_eim_from_cfg(&n, cfg.d, cfg.len) < 0) {
						v = 127;
					} else {
						n.counter = nc;
						n.has_token = t->has_token;
						n.token = t->token;
						emu_eim_free(t);
						*t = n;
					}
				}
			}
			db_free(&cfg);
			der_put_int(res, 0x8A, v);
			return v;
		}
		if (op->tag == 0xA8) {
			m = der_begin(res, 0xA8);
			der_put_int(res, 0x02, v);
			der_end(res, m);
		} else {
			der_put_int(res, 0x8A, v);
		}
		return v;
	}

	case 0xA9: { /* deleteEim */
		char id[129] = { 0 };

		if (der_find(op->val, op->len, 0x80, &x) < 0 || x.len == 0 || x.len > 128) {
			v = 7;
		} else {
			memcpy(id, x.val, x.len);
			if (!(t = emu_eim_find(e, id))) {
				v = 1;   /* eimNotFound */
			} else {
				/* deleted after the result is signed: the requester may be
				 * deleting itself, and it still signs this result (3.5.1) */
				k->del_eim = (int)(t - e->eims);
				v = e->neims == 1 ? 2 : 0;   /* lastEimDeleted */
			}
		}
		der_put_int(res, 0x89, v);
		return v == 2 ? 0 : v;
	}

	case 0xAB: { /* listEim: AB { A0 { 30 {80 id, 82 type}... } } */
		size_t l, s;

		(void)requester;
		m = der_begin(res, 0xAB);
		l = der_begin(res, 0xA0);
		for (i = 0; i < e->neims; i++) {
			der_tlv ty;
			der_tlv w;

			s = der_begin(res, 0x30);
			der_put_str(res, 0x80, e->eims[i].id);
			if (der_parse(e->eims[i].cfg.d, e->eims[i].cfg.len, &w) == 0 &&
			    der_find(w.val, w.len, 0x82, &ty) == 0)
				db_put(res, ty.raw, ty.raw_len);
			der_end(res, s);
		}
		der_end(res, l);
		der_end(res, m);
		return 0;
	}
	}

	der_put_int(res, 0x02, 2);   /* processingTerminated unknownOrDamagedCommand */
	return 2;
}

static int load_euicc_package(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	der_tlv top, signed_, sig, x, pkg, op;
	char eim_id[129] = { 0 };
	uint8_t txid[16];
	size_t txid_len = 0;
	int64_t counter = 0;
	emu_eim *m;
	dbuf input, results;
	prof ps[MAX_PROF];
	int np;
	pkgrun k;
	const uint8_t *p, *end;
	bool psmos;

	if (der_parse(req, len, &top) < 0 || top.tag != 0xBF51 ||
	    der_find(top.val, top.len, 0x30, &signed_) < 0 ||
	    der_find(top.val, top.len, 0x5F37, &sig) < 0 ||
	    der_find(signed_.val, signed_.len, 0x80, &x) < 0 || x.len == 0 || x.len > 128) {
		unsigned_error("", NULL, NULL, 0, 127, out);
		return 0;
	}
	memcpy(eim_id, x.val, x.len);

	if (der_find(signed_.val, signed_.len, 0x82, &x) == 0 && x.len <= sizeof(txid)) {
		memcpy(txid, x.val, x.len);
		txid_len = x.len;
	}

	/* unknown eIM: unsigned error with the eimId received */
	if (!(m = emu_eim_find(e, eim_id)) || !m->pub) {
		unsigned_error(eim_id, NULL, txid, txid_len, 127, out);
		return 0;
	}

	/* the signature over the euiccPackageSigned data object AS RECEIVED,
	 * followed by the associationToken data object */
	db_init(&input);
	db_put(&input, signed_.raw, signed_.raw_len);
	emu_assoc_do(m, &input);
	if (input.err || crypto_verify(m->pub, input.d, input.len, sig.val, sig.len) < 0) {
		db_free(&input);
		unsigned_error(eim_id, m, txid, txid_len, 127, out);
		return 0;
	}
	db_free(&input);

	if (der_find(signed_.val, signed_.len, 0x81, &x) < 0 || der_get_int(&x, &counter) < 0) {
		unsigned_error(eim_id, m, txid, txid_len, 127, out);
		return 0;
	}

	/* then the EID, then the replay counter; both as signed errors */
	if (der_find(signed_.val, signed_.len, 0x5A, &x) < 0 || x.len != 16 || memcmp(x.val, e->eid, 16))
		return sign_epe(e, m, counter, txid, txid_len, 3, out);   /* invalidEid */
	if (counter <= m->counter)
		return sign_epe(e, m, counter, txid, txid_len, 4, out);   /* replayError */

	/* Three phases, because an SGP.22 card is not atomic and ES10b.
	 * LoadEuiccPackage is (5.9.1).
	 *
	 * (a) Before the card is touched, the new counter is made durable,
	 *     together with the reset of the rollback authorisation that every
	 *     accepted package brings (5.9.1). Were the counter saved only after
	 *     the card had changed, a crash in between would leave it behind,
	 *     and the eIM's signed package, delivered again, would run a second
	 *     time: a delete or an enable repeated with no eIM asking for it.
	 * (b) The PSMOs run in order, and each enable, disable and delete is
	 *     carried out on the card right there; its result is the card's own
	 *     answer (psmo_code), and a refusal stops the list like any other
	 *     failure (3.3.1 step 5).
	 * (c) The result is built from those answers, signed, and saved with the
	 *     rest of the state; a rollback authorisation is recorded only for an
	 *     enable the card carried out.
	 *
	 * The crash window this leaves, after (a) and before (c): the package is
	 * counted, the card may have changed, and no result exists. The eIM gets
	 * no result for that counter, and the same package, if it comes again,
	 * is a replayError. That is chosen over the alternative, a signed "ok"
	 * made before the card acts: a missing result is what the eIM already
	 * meets whenever a result is lost in transit and it has to find the
	 * card's state by asking (listProfileInfo); a signed "ok" is a false
	 * statement it has no reason to question. An IoT eUICC has no such
	 * window, since it reverts the whole function on a power loss (5.9.1).
	 *
	 * An eCO list does not touch the card: its state changes, the counter
	 * and the result are saved together in (c), in one atomic write, and
	 * the counter is set after the eCOs, as 5.9.1 orders it, so that an
	 * updateEim is checked against the counter stored before this package. */
	psmos = der_find(signed_.val, signed_.len, 0xA0, &pkg) == 0;
	{
		int64_t old_counter = m->counter;
		bool old_rb = e->rb_granted;

		e->rb_granted = false;
		if (psmos) {
			m->counter = counter;
			if (emu_state_save(e) < 0) {
				/* nothing has run: leave the package unseen */
				m->counter = old_counter;
				e->rb_granted = old_rb;
				return -1;
			}
		}
	}

	memset(&k, 0, sizeof(k));
	k.del_eim = -1;
	db_init(&results);

	if (psmos) {   /* psmoList */
		np = profiles(e, ps, MAX_PROF);
		if (np < 0) {
			der_put_int(&results, 0x02, 127);
		} else {
			for (p = pkg.val, end = pkg.val + pkg.len; p < end; ) {
				if (der_next(&p, end, &op) < 0) {
					der_put_int(&results, 0x02, 2);
					break;
				}
				if (psmo(e, &k, ps, np, &op, &results) != 0)
					break;   /* stop at the first failure (3.3.1 step 5) */
			}
		}
	} else if (der_find(signed_.val, signed_.len, 0xA1, &pkg) == 0) {   /* ecoList */
		for (p = pkg.val, end = pkg.val + pkg.len; p < end; ) {
			if (der_next(&p, end, &op) < 0) {
				der_put_int(&results, 0x02, 2);
				break;
			}
			if (eco(e, &k, m, &op, &results) != 0)
				break;
		}
	} else {
		der_put_int(&results, 0x02, 2);
	}

	/* the counter moves with the package (5.9.1); an eIM deleted by this
	 * package is removed only after the result is signed */
	m->counter = counter;
	if (sign_epr(e, m, eim_id, counter, txid, txid_len, &results, out) < 0) {
		db_free(&results);
		return -1;
	}
	db_free(&results);

	if (k.grant_rb) {
		e->rb_granted = true;
		memcpy(e->rb_iccid, k.rb_iccid, 10);
		snprintf(e->rb_eim, sizeof(e->rb_eim), "%s", eim_id);
		e->rb_counter = counter;
		memcpy(e->rb_txid, txid, txid_len);
		e->rb_txid_len = txid_len;
		e->rb_epr_seq = e->seq;   /* the result just signed */
	}

	if (k.del_eim >= 0) {
		emu_eim_free(&e->eims[k.del_eim]);
		memmove(&e->eims[k.del_eim], &e->eims[k.del_eim + 1],
		        sizeof(e->eims[0]) * (size_t)(e->neims - k.del_eim - 1));
		e->neims--;
	}

	return emu_state_save(e);
}

/* --- the other SGP.32 functions -------------------------------------------- */

static void simple_result(dbuf *out, uint32_t tag, uint32_t rtag, int64_t v)
{
	size_t m = der_begin(out, tag);

	der_put_int(out, rtag, v);
	der_end(out, m);
}

/* One EimConfigurationData as GetEimConfigurationData returns it (5.9.18):
 * the stored configuration WITHOUT counterValue ("The eUICC SHALL NOT
 * provide counterValue"), and with the associationToken the eUICC generated,
 * not the -1 the eIM asked with. The stored copy keeps the eIM's request as
 * it came; this is only the rendering. */
static void put_eim_config(const emu_eim *m, dbuf *out)
{
	der_tlv whole, c;
	const uint8_t *p, *end;
	bool tok_done = !m->has_token;
	size_t s = der_begin(out, 0x30);

	if (der_parse(m->cfg.d, m->cfg.len, &whole) == 0)
		for (p = whole.val, end = whole.val + whole.len; p < end && der_next(&p, end, &c) == 0; ) {
			if (c.tag == 0x83 || c.tag == 0x84)
				continue;
			/* associationToken [4] sits between eimIdType [2] and
			 * eimPublicKeyData [5]; DER keeps declaration order */
			if (!tok_done && c.tag != 0x80 && c.tag != 0x81 && c.tag != 0x82) {
				der_put_int(out, 0x84, m->token);
				tok_done = true;
			}
			db_put(out, c.raw, c.raw_len);
		}
	if (!tok_done)
		der_put_int(out, 0x84, m->token);
	der_end(out, s);
}

/* ES10b.GetEimConfigurationData (5.9.18): BF55 { A0 { cfg... } } */
static int get_eim_config(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	der_tlv top, sc, id;
	size_t m, l;
	int i;
	char want[129] = { 0 };

	if (der_parse(req, len, &top) == 0 && der_find(top.val, top.len, 0xA0, &sc) == 0 &&
	    der_find(sc.val, sc.len, 0x80, &id) == 0 && id.len < sizeof(want))
		memcpy(want, id.val, id.len);

	m = der_begin(out, 0xBF55);
	l = der_begin(out, 0xA0);
	for (i = 0; i < e->neims; i++)
		if (!want[0] || !strcmp(want, e->eims[i].id))
			put_eim_config(&e->eims[i], out);
	der_end(out, l);
	der_end(out, m);
	return 0;
}

/* ES10b.AddInitialEim (5.9.4, 3.5.2) */
static int add_initial_eim(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	der_tlv top, list, c, x;
	const uint8_t *p, *end;
	dbuf oks;
	size_t m;
	int64_t code = -1;

	db_init(&oks);

	if (e->neims > 0)
		code = 2;   /* associatedEimAlreadyExists */
	else if (der_parse(req, len, &top) < 0 || der_find(top.val, top.len, 0xA0, &list) < 0)
		code = 7;
	else
		for (p = list.val, end = list.val + list.len; p < end && code < 0; ) {
			int64_t tok = 0;
			bool want_tok;

			if (der_next(&p, end, &c) < 0 || c.tag != 0x30) {
				code = 7;
				break;
			}
			want_tok = der_find(c.val, c.len, 0x84, &x) == 0 && der_get_int(&x, &tok) == 0;
			if (want_tok && tok != -1) {
				code = 5;   /* invalidAssociationToken */
				break;
			}
			if (e->neims == EMU_MAX_EIMS) {
				code = 1;
				break;
			}
			if (emu_eim_from_cfg(&e->eims[e->neims], c.raw, c.raw_len) < 0) {
				code = 7;
				break;
			}
			if (want_tok) {
				e->eims[e->neims].has_token = true;
				e->eims[e->neims].token = ++e->token_ctr;
				der_put_int(&oks, 0x84, e->eims[e->neims].token);
			} else {
				der_put_null(&oks, 0x05);   /* addOk */
			}
			e->neims++;
		}

	m = der_begin(out, 0xBF57);
	if (code >= 0) {
		/* nothing of a failed request is kept */
		while (e->neims > 0 && code != 2)
			emu_eim_free(&e->eims[--e->neims]);
		der_put_int(out, 0x81, code);
	} else {
		der_put(out, 0xA0, oks.d, oks.len);
	}
	der_end(out, m);
	db_free(&oks);

	return (code < 0 && emu_state_save(e) < 0) ? -1 : 0;
}

/* ES10b.ProfileRollback (5.9.16) */
static int profile_rollback(emu *e, dbuf *out)
{
	emu_eim *m;
	dbuf results, epr;
	size_t t;

	if (!e->rb_granted || !(m = emu_eim_find(e, e->rb_eim))) {
		simple_result(out, 0xBF58, 0x02, 1);   /* rollbackNotAllowed */
		return 0;
	}

	if (card_switch(e, 0xBF31, e->rb_iccid) != 0) {
		simple_result(out, 0xBF58, 0x02, 7);   /* commandError */
		return 0;
	}

	db_init(&results);
	db_init(&epr);
	der_put_int(&results, 0x8C, 0);   /* rollbackResult ok */
	if (sign_epr(e, m, e->rb_eim, e->rb_counter, e->rb_txid, e->rb_txid_len, &results, &epr) < 0) {
		db_free(&results);
		db_free(&epr);
		return -1;
	}
	e->rb_granted = false;

	/* the result of the package that granted the rollback is discarded
	 * (3.3.2 NOTE1): the IPA sends only the rollback's */
	{
		int i;

		for (i = 0; i < e->neprs; i++)
			if (e->epr_seq[i] == e->rb_epr_seq) {
				db_free(&e->eprs[i]);
				memmove(&e->eprs[i], &e->eprs[i + 1], sizeof(e->eprs[0]) * (size_t)(e->neprs - i - 1));
				memmove(&e->epr_seq[i], &e->epr_seq[i + 1], sizeof(e->epr_seq[0]) * (size_t)(e->neprs - i - 1));
				e->neprs--;
				break;
			}
	}

	t = der_begin(out, 0xBF58);
	der_put_int(out, 0x02, 0);
	db_put(out, epr.d, epr.len);   /* [81] replaces EuiccPackageResult's own [81] */
	der_end(out, t);

	db_free(&results);
	db_free(&epr);
	return emu_state_save(e);
}

/* ES10b.ExecuteFallbackMechanism (5.9.20) / ReturnFromFallback (5.9.21).
 *
 * Which profile is enabled is asked of the card every time (fallback_prof):
 * a return judged from a record of the last execute would switch the card
 * away from a profile the fallback never enabled. The checks run in the
 * order each section lists them, which decides the code when more than one
 * fails. */
static int fallback(emu *e, bool execute, dbuf *out)
{
	uint32_t tag = execute ? 0xBF5D : 0xBF5E;
	prof ps[MAX_PROF], *en, *fb, *prev;
	int np = profiles(e, ps, MAX_PROF);
	int64_t v;

	if (np < 0) {
		simple_result(out, tag, 0x80, 127);
		return 0;
	}

	en = enabled_prof(ps, np);
	/* an attribute whose profile is no longer on the card is set for no
	 * Profile on the eUICC (5.9.20), so it counts as not set */
	fb = fallback_prof(e, ps, np);

	if (execute) {
		if (!en) {
			simple_result(out, tag, 0x80, 7);   /* commandError */
			return 0;
		}
		if (!fb) {
			simple_result(out, tag, 0x80, 6);   /* fallbackNotAvailable */
			return 0;
		}
		/* the Emergency Profile check (ecallActive): an SGP.22 card has none */
		if (fb->enabled) {
			simple_result(out, tag, 0x80, 2);   /* profileNotInDisabledState */
			return 0;
		}
		v = card_switch(e, 0xBF31, fb->iccid);
		if (v == 0) {
			e->fb_prev_set = true;
			memcpy(e->fb_prev, en->iccid, 10);
			/* 5.9.20 resets it with the switch: a rollback granted before
			 * would otherwise switch the card from the Fallback Profile to
			 * the profile recorded before the eIM's enable, past
			 * ReturnFromFallback, and leave the fallback record behind */
			e->rb_granted = false;
		}
	} else {
		/* all three checks answer fallbackNotAvailable (5.9.21) */
		if (!fb || fb != en || !e->fb_prev_set || !(prev = find_prof(ps, np, e->fb_prev))) {
			simple_result(out, tag, 0x80, 6);
			return 0;
		}
		/* 5.9.21 lists the reset with its checks, before the switch */
		e->rb_granted = false;
		v = card_switch(e, 0xBF31, prev->iccid);
	}

	simple_result(out, tag, 0x80, v == 0 ? 0 : (v == 5 ? 5 : 127));
	return emu_state_save(e);
}

/* ES10b.ImmediateEnable (5.9.15) */
static int immediate_enable(emu *e, dbuf *out)
{
	int64_t v;

	if (!e->ie_flag) {
		simple_result(out, 0xBF5A, 0x80, 1);   /* immediateEnableNotAvailable */
		return 0;
	}
	if (!e->ie_ctx) {
		simple_result(out, 0xBF5A, 0x80, 4);   /* noSessionContext */
		return 0;
	}
	v = card_switch(e, 0xBF31, e->ie_iccid);
	e->ie_ctx = false;
	simple_result(out, 0xBF5A, 0x80, v == 0 ? 0 : (v == 5 ? 5 : 127));
	return 0;
}

/* ES10b.ConfigureImmediateProfileEnabling (5.9.17, 3.4.5) */
static int configure_immediate(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	der_tlv top, x;

	if (e->neims > 0) {
		simple_result(out, 0xBF59, 0x80, 2);   /* eIM configuration present */
		return 0;
	}
	if (der_parse(req, len, &top) < 0) {
		simple_result(out, 0xBF59, 0x80, 127);
		return 0;
	}
	e->ie_flag = der_find(top.val, top.len, 0x80, &x) == 0;
	if (der_find(top.val, top.len, 0x81, &x) == 0) {
		e->ie_oid.len = 0;
		db_put(&e->ie_oid, x.val, x.len);
	}
	if (der_find(top.val, top.len, 0x82, &x) == 0) {
		e->ie_addr.len = 0;
		db_put(&e->ie_addr, x.val, x.len);
	}
	simple_result(out, 0xBF59, 0x80, 0);
	return emu_state_save(e);
}

/* ES10b.RetrieveNotificationsList (5.9.11): the stored EPRs are answered
 * here, notifications by the card */
static int retrieve_notifications(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	der_tlv top, sc, x;
	size_t m, l;
	int i;
	int64_t seq = -1;

	if (der_parse(req, len, &top) < 0)
		return -1;

	if (der_find(top.val, top.len, 0xA0, &sc) == 0) {
		bool eprs = der_find(sc.val, sc.len, 0x82, &x) == 0;

		if (der_find(sc.val, sc.len, 0x80, &x) == 0)
			der_get_int(&x, &seq);

		if (eprs || seq >= EMU_SEQ_BASE) {
			m = der_begin(out, 0xBF2B);
			l = der_begin(out, 0xA2);
			for (i = 0; i < e->neprs; i++)
				if (eprs || e->epr_seq[i] == seq)
					db_put(out, e->eprs[i].d, e->eprs[i].len);
			der_end(out, l);
			der_end(out, m);
			return 0;
		}
	}
	return card_es10(e->card, req, len, out);
}

/* ES10b.RemoveNotificationFromList (SGP.22 5.7.11) */
static int remove_notification(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	der_tlv top, x;
	int64_t seq;
	int i;

	if (der_parse(req, len, &top) < 0 || der_find(top.val, top.len, 0x80, &x) < 0 ||
	    der_get_int(&x, &seq) < 0)
		return -1;

	if (seq < EMU_SEQ_BASE)
		return card_es10(e->card, req, len, out);

	for (i = 0; i < e->neprs; i++)
		if (e->epr_seq[i] == seq) {
			db_free(&e->eprs[i]);
			memmove(&e->eprs[i], &e->eprs[i + 1], sizeof(e->eprs[0]) * (size_t)(e->neprs - i - 1));
			memmove(&e->epr_seq[i], &e->epr_seq[i + 1], sizeof(e->epr_seq[0]) * (size_t)(e->neprs - i - 1));
			e->neprs--;
			simple_result(out, 0xBF30, 0x80, 0);
			return emu_state_save(e);
		}
	simple_result(out, 0xBF30, 0x80, 1);   /* nothingToDelete */
	return 0;
}

/* ES10b.eUICCMemoryReset (5.9.5): the SGP.22 options go to the card, the
 * two SGP.32 ones are this state */
static int memory_reset(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	der_tlv top, bits;
	uint8_t b0 = 0;
	int64_t card_rc = 1, eim_rc = -1, ie_rc = -1;
	size_t m;

	if (der_parse(req, len, &top) < 0 || der_find(top.val, top.len, 0x82, &bits) < 0 || bits.len < 1)
		return -1;
	if (bits.len >= 2)
		b0 = bits.val[1];

	if (b0 & 0xE0) {   /* bits 0-2: SGP.22 resetOptions */
		uint8_t sub[3] = { 0, 0, 0 };
		dbuf rq, rs;

		sub[0] = (uint8_t)((b0 & 0x80) != 0);
		sub[1] = (uint8_t)((b0 & 0x40) != 0);
		sub[2] = (uint8_t)((b0 & 0x20) != 0);
		db_init(&rq);
		db_init(&rs);
		m = der_begin(&rq, 0xBF34);
		der_put_bits(&rq, 0x82, sub, 3);
		der_end(&rq, m);
		if (card_call(e, &rq, &rs) < 0 || result_of(&rs, 0xBF34, &card_rc) < 0)
			card_rc = 127;
		db_free(&rq);
		db_free(&rs);
	}
	if (b0 & 0x04) {   /* bit 5: resetEimConfigData */
		eim_rc = e->neims ? 0 : 1;
		while (e->neims)
			emu_eim_free(&e->eims[--e->neims]);
	}
	if (b0 & 0x02) {   /* bit 6: resetImmediateEnableConfig */
		e->ie_flag = false;
		e->ie_oid.len = e->ie_addr.len = 0;
		ie_rc = 0;
	}

	m = der_begin(out, 0xBF64);
	der_put_int(out, 0x80, (b0 & 0xE0) ? card_rc : (eim_rc == 0 || ie_rc == 0 ? 0 : 1));
	if (eim_rc >= 0)
		der_put_int(out, 0x81, eim_rc);
	if (ie_rc >= 0)
		der_put_int(out, 0x82, ie_rc);
	der_end(out, m);
	return emu_state_save(e);
}

/* ES10b.GetProfilesInfo: the card's list, with fallbackAttribute added to
 * the Fallback Profile (put_profile_list) */
static int profiles_info(emu *e, const uint8_t *req, size_t len, dbuf *out)
{
	dbuf resp;

	db_init(&resp);
	if (card_es10(e->card, req, len, &resp) < 0) {
		db_free(&resp);
		return -1;
	}
	if (!e->fb_set || put_profile_list(e, &resp, true, true, out) < 0)
		db_put(out, resp.d, resp.len);
	db_free(&resp);
	return 0;
}

/* a completed download opens the Immediate Enable session context: the
 * ICCID from the installation result's notification metadata (SGP.22
 * ProfileInstallationResultData.notificationMetadata BF2F { 5A iccid }) */
static void observe_install(emu *e, const dbuf *resp)
{
	der_tlv pir, data, meta, x, fin;

	if (der_parse(resp->d, resp->len, &pir) < 0 || pir.tag != 0xBF37 ||
	    der_find(pir.val, pir.len, 0xBF27, &data) < 0 ||
	    der_find(data.val, data.len, 0xA2, &fin) < 0 ||
	    der_find(fin.val, fin.len, 0xA0, &x) < 0 ||   /* successResult */
	    der_find(data.val, data.len, 0xBF2F, &meta) < 0 ||
	    der_find(meta.val, meta.len, 0x5A, &x) < 0 || x.len != 10)
		return;
	memcpy(e->ie_iccid, x.val, 10);
	e->ie_ctx = true;
}

int emu_es10(emu *e, const uint8_t *req, size_t len, dbuf *resp)
{
	der_tlv t;
	int rc;

	/* LoadBoundProfilePackage arrives in segments (SGP.22 2.5.5), and the
	 * header segments ('BF36' with the first TLV, 'A1'/'A3' tag and length
	 * alone) are not complete TLVs. They are SGP.22's, so they go to the
	 * card as they are, and so does whatever else this layer cannot parse. */
	if (der_parse(req, len, &t) < 0) {
		rc = card_es10(e->card, req, len, resp);
		if (rc == 0 && resp->len)
			observe_install(e, resp);
		return rc;
	}

	switch (t.tag) {
	case 0xBF51: return load_euicc_package(e, req, len, resp);
	case 0xBF55: return get_eim_config(e, req, len, resp);
	case 0xBF57: return add_initial_eim(e, req, len, resp);
	case 0xBF56:   /* GetCerts: an SGP.22 card has no such function */
		simple_result(resp, 0xBF56, 0x81, 127);
		return 0;
	case 0xBF58: return profile_rollback(e, resp);
	case 0xBF59: return configure_immediate(e, req, len, resp);
	case 0xBF5A: return immediate_enable(e, resp);
	case 0xBF5B:   /* Enable/DisableEmergencyProfile: no emergency profile */
	case 0xBF5C:
		simple_result(resp, t.tag, 0x80, 8);   /* ecallNotAvailable */
		return 0;
	case 0xBF5D: return fallback(e, true, resp);
	case 0xBF5E: return fallback(e, false, resp);
	case 0xBF5F:   /* GetConnectivityParameters: none on an SGP.22 card */
		simple_result(resp, 0xBF5F, 0x81, 1);   /* parametersNotAvailable */
		return 0;
	case 0xBF2B: return retrieve_notifications(e, req, len, resp);
	case 0xBF30: return remove_notification(e, req, len, resp);
	case 0xBF64: return memory_reset(e, req, len, resp);
	case 0xBF2D: return profiles_info(e, req, len, resp);
	}

	/* everything else is SGP.22 and goes to the card as it is */
	rc = card_es10(e->card, req, len, resp);
	if (rc == 0 && resp->len)   /* a segment answering with the installation result */
		observe_install(e, resp);
	return rc;
}

int emu_eim_state(const emu *e, const char *eim_id, int64_t *counter, bool *has_token, int64_t *token)
{
	int i;

	for (i = 0; i < e->neims; i++)
		if (!eim_id || !strcmp(eim_id, e->eims[i].id)) {
			*counter = e->eims[i].counter;
			*has_token = e->eims[i].has_token;
			*token = e->eims[i].token;
			return 0;
		}
	return -1;
}

emu *emu_open(card *c, const emu_config *cfg)
{
	uint8_t req[] = { 0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A };   /* GetEUICCData, tagList 5A */
	dbuf resp;
	der_tlv t, x;
	emu *e = calloc(1, sizeof(*e));

	if (!e)
		return NULL;
	e->card = c;
	e->cfg = *cfg;
	e->state_path = strdup(cfg->state_path ? cfg->state_path : "");
	e->cfg.state_path = e->state_path;
	if (!e->state_path) {
		free(e);
		return NULL;
	}
	e->seq = EMU_SEQ_BASE - 1;
	db_init(&e->ie_oid);
	db_init(&e->ie_addr);

	db_init(&resp);
	if (card_es10(c, req, sizeof(req), &resp) < 0 || der_parse(resp.d, resp.len, &t) < 0 ||
	    der_find(t.val, t.len, 0x5A, &x) < 0 || x.len != 16) {
		db_free(&resp);
		free(e->state_path);
		free(e);
		return NULL;
	}
	memcpy(e->eid, x.val, 16);
	db_free(&resp);

	if (emu_state_load(e) < 0) {
		emu_close(e);
		return NULL;
	}
	return e;
}

void emu_close(emu *e)
{
	int i;

	if (!e)
		return;
	for (i = 0; i < e->neims; i++)
		emu_eim_free(&e->eims[i]);
	for (i = 0; i < e->neprs; i++)
		db_free(&e->eprs[i]);
	db_free(&e->ie_oid);
	db_free(&e->ie_addr);
	free(e->state_path);
	free(e);
}
