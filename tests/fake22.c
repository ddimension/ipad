/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fake22.h"
#include "hex.h"
#include "vectors.h"

void fake22_init(fake22 *f)
{
	memset(f, 0, sizeof(*f));
	hex_decode("89049032123451234512345678901235", f->eid, 16);
}

int fake22_add(fake22 *f, const char *iccid_hex, int enabled)
{
	int i = f->np++;

	hex_decode(iccid_hex, f->p[i].iccid, 10);
	f->p[i].enabled = enabled;
	f->p[i].present = 1;
	return i;
}

int fake22_vector(const char *type, const char *label, dbuf *out)
{
	size_t i, n;
	uint8_t *b;

	for (i = 0; i < sizeof(VECTORS) / sizeof(VECTORS[0]); i++) {
		if (strcmp(VECTORS[i].type, type) || strcmp(VECTORS[i].label, label))
			continue;
		n = strlen(VECTORS[i].hex) / 2;
		b = malloc(n);
		if (!b || hex_decode(VECTORS[i].hex, b, n) != (int)n) {
			free(b);
			return -1;
		}
		db_put(out, b, n);
		free(b);
		return 0;
	}
	return -1;
}

void fake22_free(fake22 *f)
{
	int i;

	for (i = 0; i < f->nnotes; i++)
		db_free(&f->notes[i]);
	f->nnotes = 0;
}

static int64_t add_note(fake22 *f, const dbuf *n)
{
	int i = f->nnotes++;

	db_init(&f->notes[i]);
	db_put(&f->notes[i], n->d, n->len);
	return f->note_seq[i];
}

/* NotificationMetadata BF2F { 80 seq, 81 event, 0C address, 5A iccid } */
static void metadata(fake22 *f, dbuf *b, int event_bit, const uint8_t *iccid)
{
	uint8_t ev[8] = { 0 };
	size_t m = der_begin(b, 0xBF2F);

	ev[event_bit] = 1;
	f->note_seq[f->nnotes] = ++f->next_seq;
	der_put_int(b, 0x80, f->next_seq);
	der_put_bits(b, 0x81, ev, (size_t)event_bit + 1);
	der_put_str(b, 0x0C, "smdp.test.example");
	der_put(b, 0x5A, iccid, 10);
	der_end(b, m);
}

int64_t fake22_add_pir(fake22 *f, const char *iccid_hex)
{
	uint8_t ic[10], txid[16], sig[64];
	dbuf n;
	size_t m, d, r;

	hex_decode(iccid_hex, ic, 10);
	memset(txid, 0x77, sizeof(txid));
	memset(sig, 0x5E, sizeof(sig));
	db_init(&n);
	m = der_begin(&n, 0xBF37);
	d = der_begin(&n, 0xBF27);
	der_put(&n, 0x80, txid, 16);
	metadata(f, &n, 0, ic);   /* notificationInstall(0) */
	der_put(&n, 0x06, "\x2b\x06\x01\x04\x01", 5);
	r = der_begin(&n, 0xA2);
	{
		size_t ok = der_begin(&n, 0xA0);   /* successResult */

		der_put(&n, 0x4F, ISDR_AID, 16);
		/* simaResponse: EUICCResponse { peStatus { status ok } } */
		der_put(&n, 0x04, "\x30\x07\xa0\x05\x30\x03\x80\x01\x00", 9);
		der_end(&n, ok);
	}
	der_end(&n, r);
	der_end(&n, d);
	der_put(&n, 0x5F37, sig, sizeof(sig));
	der_end(&n, m);
	{
		int64_t s = add_note(f, &n);

		db_free(&n);
		return s;
	}
}

int64_t fake22_add_other(fake22 *f)
{
	uint8_t sig[64];
	dbuf n;
	size_t m;
	int64_t s;

	memset(sig, 0x6E, sizeof(sig));
	db_init(&n);
	m = der_begin(&n, 0x30);
	metadata(f, &n, 2, f->p[0].iccid);   /* notificationEnable(2) */
	der_put(&n, 0x5F37, sig, sizeof(sig));
	db_put(&n, f->cert, f->cert_len);   /* euiccCertificate */
	db_put(&n, f->cert, f->cert_len);   /* eumCertificate */
	der_end(&n, m);
	s = add_note(f, &n);
	db_free(&n);
	return s;
}

static void seg(fake22 *f, const char *name)
{
	size_t l = strlen(f->segs);

	snprintf(f->segs + l, sizeof(f->segs) - l, "%s%s", l ? " " : "", name);
}

/* the BPP segments of LoadBoundProfilePackage; headers do not parse as
 * whole TLVs, so this looks at the tag alone */
static int bpp_segment(fake22 *f, const uint8_t *req, size_t len, dbuf *r)
{
	der_tlv t;

	if (len >= 2 && req[0] == 0xBF && req[1] == 0x36) {
		f->segs[0] = 0;
		seg(f, "BF36");
		return 1;
	}
	if (len >= 1 && (req[0] == 0xA1 || req[0] == 0xA3) && der_parse(req, len, &t) < 0) {
		seg(f, req[0] == 0xA1 ? "A1" : "A3");
		return 1;
	}
	if (der_parse(req, len, &t) < 0)
		return 0;
	switch (t.tag) {
	case 0xA0: seg(f, "A0"); return 1;
	case 0xA2: seg(f, "A2"); return 1;
	case 0x88: seg(f, "88"); return 1;
	case 0x86:
		seg(f, "86");
		if (t.len == 4 && !memcmp(t.val, "LAST", 4)) {
			int k = fake22_add(f, f->install_iccid, 0);
			int64_t s = fake22_add_pir(f, f->install_iccid);
			const dbuf *n = &f->notes[f->nnotes - 1];

			(void)k;
			(void)s;
			db_put(r, n->d, n->len);   /* the PIR ends the load */
		}
		return 1;
	}
	return 0;
}

int fake22_enabled(const fake22 *f)
{
	int i;

	for (i = 0; i < f->np; i++)
		if (f->p[i].present && f->p[i].enabled)
			return i;
	return -1;
}

static int find(fake22 *f, const uint8_t *iccid)
{
	int i;

	for (i = 0; i < f->np; i++)
		if (f->p[i].present && !memcmp(f->p[i].iccid, iccid, 10))
			return i;
	return -1;
}

static void result(dbuf *r, uint32_t tag, int v)
{
	size_t m = der_begin(r, tag);

	der_put_int(r, 0x80, v);
	der_end(r, m);
}

uint16_t fake22_handler(simcard *s, const uint8_t *req, size_t len, dbuf *r)
{
	fake22 *f = s->user;
	der_tlv t, x, y;
	size_t m, l, e;
	int i, k;

	if (bpp_segment(f, req, len, r))
		return 0x9000;
	if (der_parse(req, len, &t) < 0)
		return 0x6A80;

	switch (t.tag) {
	case 0xBF3E:
		m = der_begin(r, 0xBF3E);
		der_put(r, 0x5A, f->eid, 16);
		der_end(r, m);
		return 0x9000;

	case 0xBF2D: {
		/* the tags asked for: a tag list (5C) or the default (*) tags
		 * (SGP.22 5.7.15), written in ProfileInfo's declaration order */
		bool want5a = true, want9f70 = true, want91 = true, want9f67 = false;

		f->last_had_taglist = der_find(t.val, t.len, 0x5C, &x) == 0;
		f->last_taglist_len = 0;
		if (f->last_had_taglist) {
			const uint8_t *q = x.val, *qe = x.val + x.len;
			bool sgp32 = false;

			if (x.len <= sizeof(f->last_taglist)) {
				memcpy(f->last_taglist, x.val, x.len);
				f->last_taglist_len = x.len;
			}
			want5a = want9f70 = want91 = false;
			while (q < qe) {
				uint32_t tg = *q++;

				if ((tg & 0x1F) == 0x1F && q < qe)
					tg = tg << 8 | *q++;
				want5a |= tg == 0x5A;
				want9f70 |= tg == 0x9F70;
				want91 |= tg == 0x91;
				want9f67 |= tg == 0x9F67;
				sgp32 |= tg == 0x9F26 || tg == 0x9F67 || tg == 0x9F7B;
			}
			if ((sgp32 && f->refuse_taglist) || f->refuse_taglist == 3) {
				if (f->refuse_taglist == 1)
					return 0x6A80;
				/* profileInfoListError incorrectInputValues(1) */
				db_put(r, "\xBF\x2D\x03\x81\x01\x01", 6);
				return 0x9000;
			}
		}
		m = der_begin(r, 0xBF2D);
		l = der_begin(r, 0xA0);
		for (i = 0; i < f->np; i++) {
			if (!f->p[i].present)
				continue;
			e = der_begin(r, 0xE3);
			if (want5a)
				der_put(r, 0x5A, f->p[i].iccid, 10);
			if (want9f70) {
				uint8_t st = (uint8_t)f->p[i].enabled;

				der_put(r, 0x9F70, &st, 1);
			}
			if (want91)
				der_put_str(r, 0x91, "Test Operator");
			if (want9f67 && f->p[i].fallback_allowed)
				der_put_bool(r, 0x9F67, f->p[i].fallback_allowed == 1);
			der_end(r, e);
		}
		der_end(r, l);
		der_end(r, m);
		return 0x9000;
	}

	case 0xBF31:
	case 0xBF32:
		if (der_find(t.val, t.len, 0xA0, &x) < 0 || der_find(x.val, x.len, 0x5A, &y) < 0 || y.len != 10)
			return 0x6A80;
		f->last_refresh = der_find(t.val, t.len, 0x81, &x) == 0 && x.len == 1 && x.val[0];
		k = find(f, y.val);
		if (f->before_change)
			f->before_change(f->before_arg);
		if (t.tag == 0xBF31) {
			f->enables++;
			if (f->refuse_enable) { result(r, 0xBF31, f->refuse_enable); return 0x9000; }
			if (k < 0) { result(r, 0xBF31, 1); return 0x9000; }
			if (f->p[k].enabled) { result(r, 0xBF31, 2); return 0x9000; }
			for (i = 0; i < f->np; i++)
				f->p[i].enabled = 0;
			f->p[k].enabled = 1;
			result(r, 0xBF31, 0);
		} else {
			f->disables++;
			if (f->refuse_disable) { result(r, 0xBF32, f->refuse_disable); return 0x9000; }
			if (k < 0) { result(r, 0xBF32, 1); return 0x9000; }
			if (!f->p[k].enabled) { result(r, 0xBF32, 2); return 0x9000; }
			f->p[k].enabled = 0;
			result(r, 0xBF32, 0);
		}
		return 0x9000;

	case 0xBF33:
		f->deletes++;
		if (der_find(t.val, t.len, 0x5A, &y) < 0 || y.len != 10)
			return 0x6A80;
		k = find(f, y.val);
		if (f->before_change)
			f->before_change(f->before_arg);
		if (f->refuse_delete) { result(r, 0xBF33, f->refuse_delete); return 0x9000; }
		if (k < 0) { result(r, 0xBF33, 1); return 0x9000; }
		if (f->p[k].enabled) { result(r, 0xBF33, 2); return 0x9000; }
		f->p[k].present = 0;
		result(r, 0xBF33, 0);
		return 0x9000;

	case 0xBF43: {   /* one rule: PPR1 for any operator */
		size_t a, rule, ops;
		uint8_t ppr1[2] = { 0, 1 }, none[1] = { 0 };

		/* ProfilePolicyAuthorisationRule under SGP.22's AUTOMATIC TAGS:
		 * pprIds [0], allowedOperators [1], pprFlags [2] */
		m = der_begin(r, 0xBF43);
		a = der_begin(r, 0xA0);
		rule = der_begin(r, 0x30);
		der_put_bits(r, 0x80, ppr1, 2);
		ops = der_begin(r, 0xA1);
		der_end(r, ops);
		der_put_bits(r, 0x82, none, 1);
		der_end(r, rule);
		der_end(r, a);
		der_end(r, m);
		return 0x9000;
	}

	case 0xBF3F:
		if (der_find(t.val, t.len, 0x80, &x) == 0 && x.len < sizeof(f->dp)) {
			memcpy(f->dp, x.val, x.len);
			f->dp[x.len] = 0;
		}
		result(r, 0xBF3F, 0);
		return 0x9000;

	case 0xBF2B: {
		int64_t want = -1;

		if (der_find(t.val, t.len, 0xA0, &x) == 0 && der_find(x.val, x.len, 0x80, &y) == 0)
			der_get_int(&y, &want);
		m = der_begin(r, 0xBF2B);
		l = der_begin(r, 0xA0);
		for (i = 0; i < f->nnotes; i++)
			if (want < 0 || f->note_seq[i] == want)
				db_put(r, f->notes[i].d, f->notes[i].len);
		der_end(r, l);
		der_end(r, m);
		return 0x9000;
	}

	case 0xBF30: {
		int64_t seq = -1;

		if (der_find(t.val, t.len, 0x80, &x) == 0)
			der_get_int(&x, &seq);
		for (i = 0; i < f->nnotes; i++)
			if (f->note_seq[i] == seq) {
				db_free(&f->notes[i]);
				memmove(&f->notes[i], &f->notes[i + 1], sizeof(f->notes[0]) * (size_t)(f->nnotes - i - 1));
				memmove(&f->note_seq[i], &f->note_seq[i + 1], sizeof(f->note_seq[0]) * (size_t)(f->nnotes - i - 1));
				f->nnotes--;
				result(r, 0xBF30, 0);
				return 0x9000;
			}
		result(r, 0xBF30, 1);   /* nothingToDelete */
		return 0x9000;
	}

	case 0xBF20:   /* EUICCInfo1: svn 2.3.0, one CI key id both ways */
		m = der_begin(r, 0xBF20);
		der_put(r, 0x82, "\x02\x03\x00", 3);
		l = der_begin(r, 0xA9);
		der_put(r, 0x04, "\xF5\xF5\xF5\xF5", 4);
		der_end(r, l);
		l = der_begin(r, 0xAA);
		der_put(r, 0x04, "\xF5\xF5\xF5\xF5", 4);
		der_end(r, l);
		der_end(r, m);
		return 0x9000;

	case 0xBF2E: {
		uint8_t ch[16];

		memset(ch, 0xC4, sizeof(ch));
		m = der_begin(r, 0xBF2E);
		der_put(r, 0x80, ch, 16);
		der_end(r, m);
		return 0x9000;
	}

	case 0xBF38:   /* AuthenticateServer / PrepareDownload: the eIM's vectors */
		f->auth_mid[0] = 0;
		if (der_find(t.val, t.len, 0xA0, &x) == 0 && der_find(x.val, x.len, 0x80, &x) == 0 &&
		    x.len < sizeof(f->auth_mid)) {
			memcpy(f->auth_mid, x.val, x.len);
			f->auth_mid[x.len] = 0;
		}
		return fake22_vector("AuthenticateServerResponse", "", r) == 0 ? 0x9000 : 0x6F00;
	case 0xBF21:
		return fake22_vector("PrepareDownloadResponse", "", r) == 0 ? 0x9000 : 0x6F00;

	case 0xBF41:
		f->cancels++;
		if (der_find(t.val, t.len, 0x81, &x) == 0) {
			int64_t v = 0;

			der_get_int(&x, &v);
			f->cancel_reason = (int)v;
		}
		m = der_begin(r, 0xBF41);
		l = der_begin(r, 0xA0);
		e = der_begin(r, 0x30);
		/* EuiccCancelSessionSigned: automatic tags (SGP.22 5.7.14) */
		if (der_find(t.val, t.len, 0x80, &x) == 0)
			der_put(r, 0x80, x.val, x.len);
		der_put(r, 0x81, "\x2b\x06\x01\x04\x01", 5);
		der_put_int(r, 0x82, f->cancel_reason);
		der_end(r, e);
		der_put(r, 0x5F37, "\x01\x02", 2);
		der_end(r, l);
		der_end(r, m);
		return 0x9000;
	}

	return 0x6D00;   /* instruction not supported: an SGP.32 function, say */
}
