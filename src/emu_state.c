/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The emulation's persistent state, as DER in one file per EID, written to a
 * temporary file and renamed: a crash leaves the old state or the new one.
 * That is the emulation's version of the atomicity section 5.9.1 demands of
 * ES10b.LoadEuiccPackage, and it matters most for the replay counter: a
 * counter lost to a torn write would accept an old package again.
 *
 *   State ::= SEQUENCE {
 *     eid        [0]  OCTET STRING (16),
 *     eims       [1]  SEQUENCE OF SEQUENCE { cfg EimConfigurationData,
 *                                            counter [1] INTEGER,
 *                                            token   [2] INTEGER OPTIONAL },
 *     seq        [3]  INTEGER,
 *     eprs       [4]  SEQUENCE OF SEQUENCE { seq [0] INTEGER, epr EuiccPackageResult },
 *     rollback   [5]  SEQUENCE { iccid 5A, eimId [0] UTF8String, counter [1] INTEGER,
 *                                txid [2] OCTET STRING OPTIONAL, eprSeq [3] INTEGER } OPTIONAL,
 *     fallback   [6]  SEQUENCE { iccid 5A, active [1] BOOLEAN, prev [2] OCTET STRING OPTIONAL } OPTIONAL,
 *     immediate  [7]  SEQUENCE { flag [0] BOOLEAN, oid [1] OCTET STRING OPTIONAL,
 *                                addr [2] OCTET STRING OPTIONAL } OPTIONAL,
 *     tokenCtr   [8]  INTEGER
 *   }
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "emu_int.h"

void emu_eim_free(emu_eim *m)
{
	db_free(&m->cfg);
	crypto_key_free(m->pub);
	memset(m, 0, sizeof(*m));
}

emu_eim *emu_eim_find(emu *e, const char *id)
{
	int i;

	for (i = 0; i < e->neims; i++)
		if (!strcmp(e->eims[i].id, id))
			return &e->eims[i];
	return NULL;
}

void emu_assoc_do(const emu_eim *m, dbuf *b)
{
	/* section 2.11: without a configured token the data object is '84 01 00' */
	der_put_int(b, 0x84, m && m->has_token ? m->token : 0);
}

/* the key from eimPublicKeyData [5]: eimPublicKey [0] (SubjectPublicKeyInfo,
 * implicitly tagged, so its content is the SPKI's content) or eimCertificate
 * [1] (likewise a Certificate) */
static crypto_key *key_of(const uint8_t *cfg, size_t len)
{
	der_tlv t, k;
	dbuf b;
	crypto_key *key = NULL;

	if (der_find(cfg, len, 0xA5, &t) < 0 || der_parse(t.val, t.len, &k) < 0)
		return NULL;

	db_init(&b);
	der_put(&b, 0x30, k.val, k.len);   /* back to the universal SEQUENCE */
	if (!b.err)
		key = (k.tag == 0xA0) ? crypto_pub_from_spki(b.d, b.len)
		    : (k.tag == 0xA1) ? crypto_pub_from_cert(b.d, b.len) : NULL;
	db_free(&b);
	return key;
}

int emu_eim_from_cfg(emu_eim *m, const uint8_t *cfg, size_t len)
{
	der_tlv whole, t;
	int64_t v;

	memset(m, 0, sizeof(*m));

	if (der_parse(cfg, len, &whole) < 0 || whole.tag != 0x30)
		return -1;

	if (der_find(whole.val, whole.len, 0x80, &t) < 0 || t.len == 0 || t.len > 128)
		return -1;   /* eimId is mandatory, 1..128 */
	memcpy(m->id, t.val, t.len);
	m->id[t.len] = '\0';

	if (der_find(whole.val, whole.len, 0x83, &t) == 0 && der_get_int(&t, &v) == 0)
		m->counter = v;

	if (der_find(whole.val, whole.len, 0x84, &t) == 0 && der_get_int(&t, &v) == 0) {
		m->has_token = true;
		m->token = v;
	}

	m->pub = key_of(whole.val, whole.len);

	db_init(&m->cfg);
	db_put(&m->cfg, cfg, len);
	return m->cfg.err ? -1 : 0;
}

/* --- file ------------------------------------------------------------------ */

int emu_state_save(const emu *e)
{
	dbuf b;
	size_t top, m, it;
	char tmp[4096];
	int i, fd, rc = -1;

	db_init(&b);
	top = der_begin(&b, 0x30);
	der_put(&b, 0x80, e->eid, sizeof(e->eid));

	m = der_begin(&b, 0xA1);
	for (i = 0; i < e->neims; i++) {
		it = der_begin(&b, 0x30);
		db_put(&b, e->eims[i].cfg.d, e->eims[i].cfg.len);
		der_put_int(&b, 0x81, e->eims[i].counter);
		if (e->eims[i].has_token)
			der_put_int(&b, 0x82, e->eims[i].token);
		der_end(&b, it);
	}
	der_end(&b, m);

	der_put_int(&b, 0x83, e->seq);

	m = der_begin(&b, 0xA4);
	for (i = 0; i < e->neprs; i++) {
		it = der_begin(&b, 0x30);
		der_put_int(&b, 0x80, e->epr_seq[i]);
		db_put(&b, e->eprs[i].d, e->eprs[i].len);
		der_end(&b, it);
	}
	der_end(&b, m);

	if (e->rb_granted) {
		m = der_begin(&b, 0xA5);
		der_put(&b, 0x5A, e->rb_iccid, 10);
		der_put_str(&b, 0x80, e->rb_eim);
		der_put_int(&b, 0x81, e->rb_counter);
		if (e->rb_txid_len)
			der_put(&b, 0x82, e->rb_txid, e->rb_txid_len);
		der_put_int(&b, 0x83, e->rb_epr_seq);
		der_end(&b, m);
	}

	if (e->fb_set) {
		m = der_begin(&b, 0xA6);
		der_put(&b, 0x5A, e->fb_iccid, 10);
		if (e->fb_prev_set)
			der_put(&b, 0x82, e->fb_prev, 10);
		der_end(&b, m);
	}

	if (e->ie_flag || e->ie_oid.len || e->ie_addr.len) {
		m = der_begin(&b, 0xA7);
		der_put_bool(&b, 0x80, e->ie_flag);
		if (e->ie_oid.len)
			der_put(&b, 0x81, e->ie_oid.d, e->ie_oid.len);
		if (e->ie_addr.len)
			der_put(&b, 0x82, e->ie_addr.d, e->ie_addr.len);
		der_end(&b, m);
	}

	der_put_int(&b, 0x88, e->token_ctr);
	der_end(&b, top);

	if (b.err || snprintf(tmp, sizeof(tmp), "%s.tmp", e->cfg.state_path) >= (int)sizeof(tmp))
		goto out;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		goto out;
	if (write(fd, b.d, b.len) == (ssize_t)b.len && fsync(fd) == 0)
		rc = 0;
	close(fd);
	if (rc == 0 && rename(tmp, e->cfg.state_path) != 0)
		rc = -1;
	if (rc != 0)
		unlink(tmp);
out:
	db_free(&b);
	return rc;
}

static int read_file(const char *path, dbuf *b)
{
	FILE *f = fopen(path, "rb");
	uint8_t buf[4096];
	size_t n;

	if (!f)
		return -1;
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		db_put(b, buf, n);
	fclose(f);
	return b->err ? -1 : 0;
}

/* 0: loaded; 1: no state yet (a fresh card); -1: unreadable, or for another EID */
int emu_state_load(emu *e)
{
	dbuf b;
	der_tlv top, t, it, x;
	const uint8_t *p, *end;
	int64_t v;
	int rc = -1;

	db_init(&b);
	if (read_file(e->cfg.state_path, &b) < 0) {
		db_free(&b);
		return 1;
	}

	if (der_parse(b.d, b.len, &top) < 0 || top.tag != 0x30)
		goto out;

	if (der_find(top.val, top.len, 0x80, &t) < 0 || t.len != 16 || memcmp(t.val, e->eid, 16))
		goto out;   /* another card's state: refuse, never reuse */

	if (der_find(top.val, top.len, 0xA1, &t) == 0)
		for (p = t.val, end = t.val + t.len; p < end && e->neims < EMU_MAX_EIMS; ) {
			const uint8_t *q;
			der_tlv cfg;

			if (der_next(&p, end, &it) < 0)
				goto out;
			/* the configuration is the entry's first element */
			q = it.val;
			if (der_next(&q, it.val + it.len, &cfg) < 0 ||
			    emu_eim_from_cfg(&e->eims[e->neims], cfg.raw, cfg.raw_len) < 0)
				goto out;
			if (der_find(it.val, it.len, 0x81, &x) == 0 && der_get_int(&x, &v) == 0)
				e->eims[e->neims].counter = v;
			if (der_find(it.val, it.len, 0x82, &x) == 0 && der_get_int(&x, &v) == 0) {
				e->eims[e->neims].has_token = true;
				e->eims[e->neims].token = v;
			}
			e->neims++;
		}

	if (der_find(top.val, top.len, 0x83, &t) == 0 && der_get_int(&t, &v) == 0)
		e->seq = v;

	if (der_find(top.val, top.len, 0xA4, &t) == 0)
		for (p = t.val, end = t.val + t.len; p < end && e->neprs < EMU_MAX_EPRS; ) {
			der_tlv epr;

			if (der_next(&p, end, &it) < 0 ||
			    der_find(it.val, it.len, 0x80, &x) < 0 || der_get_int(&x, &v) < 0 ||
			    der_find(it.val, it.len, 0xBF51, &epr) < 0)
				goto out;
			e->epr_seq[e->neprs] = v;
			db_init(&e->eprs[e->neprs]);
			db_put(&e->eprs[e->neprs], epr.raw, epr.raw_len);
			e->neprs++;
		}

	if (der_find(top.val, top.len, 0xA5, &t) == 0 &&
	    der_find(t.val, t.len, 0x5A, &x) == 0 && x.len == 10) {
		e->rb_granted = true;
		memcpy(e->rb_iccid, x.val, 10);
		if (der_find(t.val, t.len, 0x80, &x) == 0 && x.len < sizeof(e->rb_eim)) {
			memcpy(e->rb_eim, x.val, x.len);
			e->rb_eim[x.len] = '\0';
		}
		if (der_find(t.val, t.len, 0x81, &x) == 0)
			der_get_int(&x, &e->rb_counter);
		if (der_find(t.val, t.len, 0x82, &x) == 0 && x.len <= sizeof(e->rb_txid)) {
			memcpy(e->rb_txid, x.val, x.len);
			e->rb_txid_len = x.len;
		}
		if (der_find(t.val, t.len, 0x83, &x) == 0)
			der_get_int(&x, &e->rb_epr_seq);
	}

	if (der_find(top.val, top.len, 0xA6, &t) == 0 &&
	    der_find(t.val, t.len, 0x5A, &x) == 0 && x.len == 10) {
		e->fb_set = true;
		memcpy(e->fb_iccid, x.val, 10);
		/* a [1] BOOLEAN ("fallback active") in the record is ignored:
		 * whether the Fallback Profile is enabled is the card's to say
		 * (emu.c fallback_prof), and a stored copy goes stale whenever the
		 * card changes without ipad */
		if (der_find(t.val, t.len, 0x82, &x) == 0 && x.len == 10) {
			e->fb_prev_set = true;
			memcpy(e->fb_prev, x.val, 10);
		}
	}

	if (der_find(top.val, top.len, 0xA7, &t) == 0) {
		e->ie_flag = der_find(t.val, t.len, 0x80, &x) == 0 && x.len == 1 && x.val[0];
		if (der_find(t.val, t.len, 0x81, &x) == 0)
			db_put(&e->ie_oid, x.val, x.len);
		if (der_find(t.val, t.len, 0x82, &x) == 0)
			db_put(&e->ie_addr, x.val, x.len);
	}

	if (der_find(top.val, top.len, 0x88, &t) == 0)
		der_get_int(&t, &e->token_ctr);

	rc = 0;
out:
	db_free(&b);
	return rc;
}
