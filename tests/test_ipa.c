/* SPDX-License-Identifier: GPL-2.0-only
 * ipa.c against a scripted eIM (in process, through the transport seam) and
 * the emulation over a simulated SGP.22 card. Section numbers are SGP.32
 * v1.3. With IPAD_ESIPA_DUMP=<file> every message both ways is written out
 * for tools/esipa-check, which decodes them with the eIM's ASN.1 types. */
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include "check.h"
#include "fake22.h"
#include "eimpkg.h"
#include "emu.h"
#include "euicc.h"
#include "ipa.h"
#include "hex.h"

static const char *EIM = "eim.test.example";
static crypto_key *eim_key, *dev_key, *tls_key;
static FILE *dump;
static dbuf CERT;   /* a real certificate for every Certificate field */

static void load_fixture(const char *name, dbuf *out)
{
	char p[512];
	uint8_t buf[4096];
	size_t n;
	FILE *f;

	snprintf(p, sizeof(p), "%s/%s", FIXTURES, name);
	if (!(f = fopen(p, "rb")))
		return;
	n = fread(buf, 1, sizeof(buf), f);
	fclose(f);
	db_put(out, buf, n);
}

/* ---- the scripted eIM ---- */

typedef struct {
	dbuf queue[16];             /* GetEimPackageResponses to hand out */
	int nq, qi;
	dbuf got[160];              /* every request, in order */
	int ngot;
	bool offline;
	int64_t auth_client_error;  /* > 0: AuthenticateClient answers this error */
	bool invalid;               /* a deliberately malformed exchange: not dumped */
} fake_eim;

static void dump_hex(const char *dir, const uint8_t *p, size_t n)
{
	size_t i;

	if (!dump)
		return;
	fprintf(dump, "%s ", dir);
	for (i = 0; i < n; i++)
		fprintf(dump, "%02x", p[i]);
	fprintf(dump, "\n");
}

static void queue(fake_eim *f, const dbuf *inner)
{
	dbuf *q;
	size_t m;

	if (f->nq == (int)(sizeof(f->queue) / sizeof(f->queue[0]))) {
		fprintf(stderr, "test bug: fake eIM queue full\n");
		exit(2);
	}
	q = &f->queue[f->nq++];

	db_init(q);
	m = der_begin(q, 0xBF4F);
	db_put(q, inner->d, inner->len);
	der_end(q, m);
}

static int64_t epr_seq(const der_tlv *bf51)
{
	der_tlv k, d, s;
	int64_t v = -1;

	if (der_parse(bf51->val, bf51->len, &k) == 0 && der_find(k.val, k.len, 0x30, &d) == 0 &&
	    der_find(d.val, d.len, 0x83, &s) == 0)
		der_get_int(&s, &v);
	return v;
}

static int eim_transport(void *ud, const uint8_t *req, size_t len, int *status, dbuf *resp)
{
	fake_eim *f = ud;
	der_tlv t, x;
	size_t m, k, l;
	uint8_t txid[16];

	if (f->offline || f->ngot == (int)(sizeof(f->got) / sizeof(f->got[0])))
		return -1;
	db_init(&f->got[f->ngot]);
	db_put(&f->got[f->ngot++], req, len);
	if (!f->invalid)
		dump_hex("to-eim", req, len);
	*status = 200;
	memset(txid, 0x33, sizeof(txid));
	if (der_parse(req, len, &t) < 0)
		return -1;

	switch (t.tag) {
	case 0xBF4F:
		if (f->qi < f->nq)
			db_put(resp, f->queue[f->qi].d, f->queue[f->qi].len), f->qi++;
		else
			db_put(resp, "\xBF\x4F\x03\x02\x01\x01", 6);   /* noEimPackageAvailable */
		break;
	case 0xBF50:
		/* acknowledge a signed EPR by its seqNumber (3.3.1 step 13) */
		m = der_begin(resp, 0xBF50);
		if (der_find(t.val, t.len, 0xBF51, &x) == 0 && epr_seq(&x) >= 0) {
			k = der_begin(resp, 0xBF53);
			der_put_int(resp, 0x80, epr_seq(&x));
			der_end(resp, k);
		} else {
			der_put(resp, 0x30, NULL, 0);   /* emptyResponse */
		}
		der_end(resp, m);
		break;
	case 0xBF3D:
		*status = 204;
		return 0;
	case 0xBF39:   /* InitiateAuthenticationOkEsipa */
		m = der_begin(resp, 0xBF39);
		k = der_begin(resp, 0xA0);
		l = der_begin(resp, 0x30);   /* serverSigned1 */
		der_put(resp, 0x80, txid, 16);
		if (der_find(t.val, t.len, 0x81, &x) == 0)
			der_put(resp, 0x81, x.val, x.len);
		der_put_str(resp, 0x83, "smdp.test.example");
		der_put(resp, 0x84, txid, 16);
		der_end(resp, l);
		der_put(resp, 0x5F37, txid, 16);
		der_put(resp, 0x04, "\xF5\xF5\xF5\xF5", 4);
		db_put(resp, CERT.d, CERT.len);   /* serverCertificate */
		der_put_str(resp, 0x0C, "MATCH");
		der_end(resp, k);
		der_end(resp, m);
		break;
	case 0xBF3B:
		m = der_begin(resp, 0xBF3B);
		if (f->auth_client_error > 0) {
			der_put_int(resp, 0x82, f->auth_client_error);
		} else {
			k = der_begin(resp, 0xA0);   /* AuthenticateClientOkDPEsipa */
			der_put(resp, 0x80, txid, 16);
			l = der_begin(resp, 0x30);   /* smdpSigned2 */
			der_put(resp, 0x80, txid, 16);
			der_put_bool(resp, 0x01, false);
			der_end(resp, l);
			der_put(resp, 0x5F37, txid, 16);
			db_put(resp, CERT.d, CERT.len);   /* smdpCertificate */
			der_end(resp, k);
		}
		der_end(resp, m);
		break;
	case 0xBF3A: {   /* a BPP with two 88 and two 86 segments */
		size_t b, s;

		m = der_begin(resp, 0xBF3A);
		k = der_begin(resp, 0xA0);
		der_put(resp, 0x80, txid, 16);
		b = der_begin(resp, 0xBF36);
		{
			/* InitialiseSecureChannelRequest from the eIM's BPP vector */
			dbuf v;
			der_tlv bpp, isc;

			db_init(&v);
			if (fake22_vector("BoundProfilePackage", "", &v) == 0 && der_parse(v.d, v.len, &bpp) == 0 &&
			    der_find(bpp.val, bpp.len, 0xBF23, &isc) == 0)
				db_put(resp, isc.raw, isc.raw_len);
			db_free(&v);
		}
		s = der_begin(resp, 0xA0);
		der_put(resp, 0x87, "cfg", 3);
		der_end(resp, s);
		s = der_begin(resp, 0xA1);
		der_put(resp, 0x88, "md1", 3);
		der_put(resp, 0x88, "md2", 3);
		der_end(resp, s);
		s = der_begin(resp, 0xA3);
		der_put(resp, 0x86, "pe01", 4);
		der_put(resp, 0x86, "LAST", 4);
		der_end(resp, s);
		der_end(resp, b);
		der_end(resp, k);
		der_end(resp, m);
		break;
	}
	case 0xBF41:
		db_put(resp, "\xBF\x41\x02\xA0\x00", 5);   /* cancelSessionOk */
		break;
	default:
		*status = 400;
		return 0;
	}
	if (!f->invalid)
		dump_hex("to-ipa", resp->d, resp->len);
	return 0;
}

static int count_got(const fake_eim *f, int from, uint32_t tag)
{
	der_tlv t;
	int i, n = 0;

	for (i = from; i < f->ngot; i++)
		if (der_parse(f->got[i].d, f->got[i].len, &t) == 0 && t.tag == tag)
			n++;
	return n;
}

/* the last request with `tag`, or NULL */
static const dbuf *last_got(const fake_eim *f, uint32_t tag)
{
	der_tlv t;
	int i;

	for (i = f->ngot - 1; i >= 0; i--)
		if (der_parse(f->got[i].d, f->got[i].len, &t) == 0 && t.tag == tag)
			return &f->got[i];
	return NULL;
}

/* the last HandleNotification carrying a ProvideEimPackageResult; *res is
 * its BF50 */
static const dbuf *last_result_notification(const fake_eim *f, int from, der_tlv *res)
{
	der_tlv t;
	int i;

	for (i = f->ngot - 1; i >= from; i--)
		if (der_parse(f->got[i].d, f->got[i].len, &t) == 0 && t.tag == 0xBF3D &&
		    der_find(t.val, t.len, 0xBF50, res) == 0)
			return &f->got[i];
	return NULL;
}

/* ---- the host ---- */

typedef struct {
	char changed[4][21];
	int nchanged;
	bool online;
	fake22 *card;
	int download_rc, downloads;
	char ac[128];
	int nconn;
	char conn_iccid[21];
	bool conn_params, conn_emulated;
	char last_log[256];
} host;

static bool on_changed(void *ud, const char *iccid)
{
	host *h = ud;

	if (h->nchanged < 4)
		snprintf(h->changed[h->nchanged++], 21, "%s", iccid);
	return h->online;
}

static int on_download(void *ud, const char *ac, const char *cc)
{
	host *h = ud;

	(void)cc;
	h->downloads++;
	snprintf(h->ac, sizeof(h->ac), "%s", ac);
	if (h->download_rc == 0) {
		fake22_add(h->card, "98001032547698103254", 0);
		fake22_add_pir(h->card, "98001032547698103254");
	}
	return h->download_rc;
}

static void on_conn(void *ud, const char *iccid, const conn_params *p, bool emulated)
{
	host *h = ud;

	h->nconn++;
	snprintf(h->conn_iccid, sizeof(h->conn_iccid), "%s", iccid);
	h->conn_params = p != NULL;
	h->conn_emulated = emulated;
}

static void on_log(void *ud, int lvl, const char *msg)
{
	host *h = ud;

	(void)lvl;
	snprintf(h->last_log, sizeof(h->last_log), "%s", msg);
	if (getenv("IPAD_TEST_VERBOSE"))
		fprintf(stderr, "  log: %s\n", msg);
}

/* ---- helpers ---- */

static void pkg_enable(fake_eim *f, const uint8_t *eid, int64_t counter, const char *iccid, bool rollback)
{
	dbuf ops, p;

	db_init(&ops);
	db_init(&p);
	eimpkg_op(&ops, 0xA3, iccid, rollback);
	eimpkg_package(&p, EIM, eid, counter, 0xA0, &ops, eim_key, 0, false);
	queue(f, &p);
	db_free(&ops);
	db_free(&p);
}

/* the content of `tag` inside the first TLV of a request */
static int inner(const dbuf *msg, uint32_t tag, der_tlv *out)
{
	der_tlv t;

	return der_parse(msg->d, msg->len, &t) < 0 ? -1 : der_find(t.val, t.len, tag, out);
}

static int epr_has(const der_tlv *bf51, uint32_t result_tag)
{
	der_tlv k, d, r, x;

	return der_parse(bf51->val, bf51->len, &k) == 0 && der_find(k.val, k.len, 0x30, &d) == 0 &&
	       der_find(d.val, d.len, 0x30, &r) == 0 && der_find(r.val, r.len, result_tag, &x) == 0;
}

static int stored_eprs(euicc *eu)
{
	static const uint8_t q[] = { 0xBF, 0x2B, 0x04, 0xA0, 0x02, 0x82, 0x00 };
	dbuf r;
	der_tlv t, l, x;
	const uint8_t *p, *end;
	int n = -1;

	db_init(&r);
	if (euicc_es10(eu, q, sizeof(q), &r) == 0 && der_parse(r.d, r.len, &t) == 0 &&
	    der_find(t.val, t.len, 0xA2, &l) == 0)
		for (n = 0, p = l.val, end = l.val + l.len; p < end && der_next(&p, end, &x) == 0; )
			n++;
	db_free(&r);
	return n;
}

int main(void)
{
	char state[] = "/tmp/ipad-test-ipa-XXXXXX";
	int fd = mkstemp(state);
	simcard s;
	fake22 fc;
	card c;
	emu_config ecfg;
	euicc eu;
	fake_eim eim;
	host h;
	ipa_config cfg;
	ipa_summary sum;
	ipa *a;
	dbuf b;
	der_tlv x, y;
	char err[160];
	int mark;
	const dbuf *m;

	close(fd);
	unlink(state);
	if (getenv("IPAD_ESIPA_DUMP"))
		dump = fopen(getenv("IPAD_ESIPA_DUMP"), "w");

	eim_key = crypto_key_generate();
	dev_key = crypto_key_generate();
	tls_key = crypto_key_generate();

	db_init(&CERT);
	load_fixture("prime256v1.cert.der", &CERT);
	fake22_init(&fc);
	fc.cert = CERT.d;
	fc.cert_len = CERT.len;
	fake22_add(&fc, "98001032547698103214", 1);   /* A, enabled: 89000123456789012341 */
	fake22_add(&fc, "98001032547698103224", 0);   /* B */
	fake22_add(&fc, "98001032547698103234", 0);   /* C */
	simcard_init(&s, 1, fake22_handler, &fc);
	card_init(&c, &SIMCARD_OPS, &s);
	memset(&ecfg, 0, sizeof(ecfg));
	ecfg.state_path = state;
	ecfg.key = dev_key;
	eu.kind = EUICC_EMU;
	eu.card = &c;
	eu.emu = emu_open(&c, &ecfg);
	OK(eu.emu != NULL, "setup: emulation open");

	memset(&eim, 0, sizeof(eim));
	memset(&h, 0, sizeof(h));
	h.online = true;
	h.card = &fc;
	memset(&cfg, 0, sizeof(cfg));
	cfg.eu = &eu;
	cfg.state_change_cause = -1;
	memcpy(cfg.tac, "\x35\x29\x06\x11", 4);
	cfg.host.profile_changed = on_changed;
	cfg.host.download = on_download;
	cfg.host.connectivity = on_conn;
	cfg.host.log = on_log;
	cfg.host.ud = &h;
	cfg.transport = eim_transport;
	cfg.transport_ud = &eim;

	/* --- IpaCapabilities bytes (4.1), both ways; a BIT STRING drops
	 * trailing zero bits, so direct off leaves one named bit less --- */
	{
		static const uint8_t both[] = { 0x30, 0x08, 0x80, 0x02, 0x06, 0xC0, 0x81, 0x02, 0x07, 0x80 };
		static const uint8_t ind[] = { 0x30, 0x08, 0x80, 0x02, 0x06, 0x40, 0x81, 0x02, 0x07, 0x80 };

		db_init(&b);
		ipa_put_capabilities(&b, 0x30, true);
		EQ_HEX(b.d, b.len, both, sizeof(both), "caps: direct + indirect, ipaRetrieveHttps");
		b.len = 0;
		ipa_put_capabilities(&b, 0x30, false);
		EQ_HEX(b.d, b.len, ind, sizeof(ind), "caps: indirect only");
		db_free(&b);
	}

	/* --- no eIM yet: nothing to poll --- */
	OK(ipa_open(&cfg) == NULL, "open: refused without an eIM configured");

	/* --- provisioning (AddInitialEim 5.9.17) --- */
	db_init(&b);
	eimpkg_cfg_ex(&b, EIM, "eim.test.example:8443", 4, eim_key, false, tls_key);
	OK(ipa_add_initial_eim(&eu, b.d, b.len, err, sizeof(err)) == 0, "provision: accepted");
	OK(ipa_add_initial_eim(&eu, b.d, b.len, err, sizeof(err)) < 0 && strstr(err, "already"),
	   "provision: a second one is refused, and says why");
	OK(ipa_add_initial_eim(&eu, b.d, b.len - 1, err, sizeof(err)) < 0, "provision: a truncated file is refused");
	db_free(&b);

	a = ipa_open(&cfg);
	OK(a != NULL, "open: EID and eIM read");
	if (!a)
		DONE("test_ipa");
	OK(!memcmp(ipa_eid(a), fc.eid, 16), "open: the card's EID");
	OK(!strcmp(ipa_url(a), "https://eim.test.example:8443/gsma/rsp2/asn1"),
	   "open: URL from eimFqdn (6.1.1 path)");
	{
		uint8_t spki[128];
		int n = crypto_key_spki(tls_key, spki, sizeof(spki));
		const http_tls *t = ipa_tls(a);

		OK(t->pin_spki && (int)t->pin_spki_len == n && !memcmp(t->pin_spki, spki, (size_t)n),
		   "open: trustedEimPkTls becomes the TLS pin (full SPKI)");
	}

	/* --- an empty poll --- */
	OK(ipa_poll(a, &sum) == 0 && sum.packages == 0, "poll: nothing to do");
	{
		const uint8_t *e = fc.eid;
		uint8_t want[21] = { 0xBF, 0x4F, 0x12, 0x5A, 0x10 };

		memcpy(want + 5, e, 16);
		EQ_HEX(eim.got[0].d, eim.got[0].len, want, sizeof(want), "poll: GetEimPackageRequest is BF4F{5A eid}");
	}
	ipa_close(a);

	/* a state change and the rPLMN go out with the next poll, once */
	cfg.state_change_cause = 4;   /* reset */
	cfg.has_rplmn = true;
	memcpy(cfg.rplmn, "\x62\xF2\x20", 3);
	a = ipa_open(&cfg);
	mark = eim.ngot;
	ipa_poll(a, &sum);
	ipa_poll(a, &sum);
	OK(inner(&eim.got[mark], 0x80, &x) == 0 && inner(&eim.got[mark], 0x81, &y) == 0 && y.len == 1 &&
	   y.val[0] == 4, "poll: notifyStateChange + stateChangeCause (3.1.1.1)");
	OK(inner(&eim.got[mark + 1], 0x80, &x) < 0, "poll: the state change is sent once");
	OK(inner(&eim.got[mark + 1], 0x82, &x) == 0 && x.len == 3, "poll: rPLMN every time");

	/* --- eUICC Package: enable B, acknowledged, EPR removed (3.3.1) --- */
	pkg_enable(&eim, fc.eid, 5, "98001032547698103224", false);
	mark = eim.ngot;
	OK(ipa_poll(a, &sum) == 0 && sum.packages == 1, "package: executed");
	OK(fake22_enabled(&fc) == 1, "package: B enabled on the card");
	OK(h.nchanged == 1 && !strcmp(h.changed[0], "89000123456789012342"),
	   "package: host told the new ICCID (digits, not BCD)");
	OK(sum.profile_changed && !sum.rolled_back, "package: summary says changed");
	m = last_got(&eim, 0xBF50);
	OK(m && inner(m, 0x5A, &x) == 0 && inner(m, 0xBF51, &y) == 0 && epr_has(&y, 0x83),
	   "package: ProvideEimPackageResult{5A, BF51 with enableResult}");
	OK(sum.acknowledged == 1 && stored_eprs(&eu) == 0, "package: the acknowledged EPR is removed (step 15)");

	/* --- enable C with rollback, device offline -> ProfileRollback (3.3.2) --- */
	h.nchanged = 0;
	h.online = false;
	pkg_enable(&eim, fc.eid, 6, "98001032547698103234", true);
	mark = eim.ngot;
	ipa_poll(a, &sum);
	OK(h.nchanged == 2 && !strcmp(h.changed[0], "89000123456789012343") &&
	   !strcmp(h.changed[1], "89000123456789012342"), "rollback: host sees C, then B again");
	OK(fake22_enabled(&fc) == 1, "rollback: B is enabled again");
	OK(sum.rolled_back, "rollback: reported");
	OK(count_got(&eim, mark, 0xBF50) == 1, "rollback: exactly one result goes out");
	m = last_got(&eim, 0xBF50);
	OK(m && inner(m, 0xBF51, &y) == 0 && epr_has(&y, 0x8C), "rollback: it is the rollback's (NOTE1)");
	OK(stored_eprs(&eu) == 0, "rollback: nothing left behind");

	/* without the rollback grant the result stays on the eUICC */
	h.nchanged = 0;
	pkg_enable(&eim, fc.eid, 7, "98001032547698103234", false);
	mark = eim.ngot;
	ipa_poll(a, &sum);
	OK(fake22_enabled(&fc) == 2 && !sum.rolled_back, "no grant: C stays enabled");
	OK(count_got(&eim, mark, 0xBF50) == 0 && stored_eprs(&eu) == 1,
	   "no grant: result kept on the eUICC for IpaEuiccData A2");
	h.online = true;

	/* --- IpaEuiccDataRequest (2.11.1.2) --- */
	{
		dbuf q;
		size_t k;
		uint8_t tx[16];

		memset(tx, 0x44, sizeof(tx));
		db_init(&q);
		k = der_begin(&q, 0xBF52);
		der_put(&q, 0x5C, "\xA0\xA2\xBF\x20\x84\xA8\xA9\xDF\x7F", 9);   /* DF7F: unknown, ignored */
		der_put(&q, 0x83, tx, 16);
		der_end(&q, k);
		queue(&eim, &q);
		mark = eim.ngot;
		ipa_poll(a, &sum);
		m = last_got(&eim, 0xBF50);
		OK(m && inner(m, 0xBF52, &y) == 0 && der_find(y.val, y.len, 0xA0, &x) == 0, "data: BF52{A0 ipaEuiccData}");
		{
			der_tlv z, l;
			static const uint8_t caps[] = { 0xA8, 0x08, 0x80, 0x02, 0x06, 0xC0, 0x81, 0x02, 0x07, 0x80 };

			OK(der_find(x.val, x.len, 0xA2, &l) == 0 && der_find(l.val, l.len, 0xBF51, &z) == 0,
			   "data: the stored EPR under A2");
			OK(der_find(x.val, x.len, 0xBF20, &z) == 0, "data: euiccInfo1");
			OK(der_find(x.val, x.len, 0x87, &z) == 0 && z.len == 16 && !memcmp(z.val, tx, 16),
			   "data: eimTransactionId echoed as 87");
			OK(der_find(x.val, x.len, 0xA8, &z) == 0, "data: ipaCapabilities");
			if (der_find(x.val, x.len, 0xA8, &z) == 0)
				EQ_HEX(z.raw, z.raw_len, caps, sizeof(caps), "data: direct+indirect, ipaRetrieveHttps");
			OK(der_find(x.val, x.len, 0xA9, &z) == 0 && der_find(z.val, z.len, 0x80, &l) == 0 &&
			   l.len == 4, "data: deviceInfo with TAC");
			OK(der_find(x.val, x.len, 0x84, &z) < 0, "data: no associationToken when none was issued");
		}
		OK(sum.acknowledged == 0 && stored_eprs(&eu) == 1, "data: an unacknowledged EPR stays");

		/* the components come in declaration order: DER requires it */
		{
			const uint8_t *p = x.val, *end = x.val + x.len;
			static const uint32_t order[] = { 0xA0, 0x81, 0xA2, 0xBF20, 0xBF22, 0x83, 0x84, 0xA5, 0xA6, 0x87, 0xA8, 0xA9 };
			size_t oi = 0;
			bool sorted = true;
			der_tlv z;

			while (p < end && der_next(&p, end, &z) == 0) {
				while (oi < sizeof(order) / sizeof(order[0]) && order[oi] != z.tag)
					oi++;
				if (oi == sizeof(order) / sizeof(order[0]))
					sorted = false;
			}
			OK(sorted, "data: components in IpaEuiccData order");
		}

		/* no tagList: incorrectTagList */
		eim.invalid = true;
		q.len = 0;
		k = der_begin(&q, 0xBF52);
		der_put(&q, 0x83, tx, 16);
		der_end(&q, k);
		queue(&eim, &q);
		ipa_poll(a, &sum);
		m = last_got(&eim, 0xBF50);
		OK(m && inner(m, 0xBF52, &y) == 0 && der_find(y.val, y.len, 0xA1, &x) == 0 &&
		   der_find(x.val, x.len, 0x02, &y) == 0 && y.len == 1 && y.val[0] == 1,
		   "data: without tagList, A1{02 incorrectTagList}");
		eim.invalid = false;
		db_free(&q);
	}

	/* --- Notifications (3.7) --- */
	fake22_add_other(&fc);
	mark = eim.ngot;
	ipa_poll(a, &sum);
	OK(sum.notifications == 1 && fc.nnotes == 0, "notify: delivered and removed");
	m = last_got(&eim, 0xBF3D);
	OK(m && inner(m, 0xA0, &x) == 0 && der_parse(x.val, x.len, &y) == 0 && y.tag == 0x30,
	   "notify: BF3D{A0{OtherSignedNotification}}");
	fake22_add_other(&fc);
	eim.offline = true;
	OK(ipa_deliver_notifications(a) == 0 && fc.nnotes == 1, "notify: eIM unreachable, kept");
	eim.offline = false;
	OK(ipa_deliver_notifications(a) == 1 && fc.nnotes == 0, "notify: sent on the next chance");

	/* --- direct download through the host (3.2.3.1) --- */
	{
		dbuf q;
		size_t k, l;
		uint8_t tx[16];

		memset(tx, 0x55, sizeof(tx));
		db_init(&q);
		k = der_begin(&q, 0xBF54);
		l = der_begin(&q, 0xA0);
		der_put_str(&q, 0x80, "1$smdp.test.example$MATCH");
		der_end(&q, l);
		der_put(&q, 0x82, tx, 16);
		der_end(&q, k);
		queue(&eim, &q);
		mark = eim.ngot;
		ipa_poll(a, &sum);
		OK(h.downloads == 1 && !strcmp(h.ac, "1$smdp.test.example$MATCH"), "direct: host downloads the AC");
		OK(count_got(&eim, mark, 0xBF3D) == 2, "direct: trigger result + PIR notification");
		m = last_result_notification(&eim, mark, &x);
		OK(m && der_find(x.val, x.len, 0xBF54, &y) == 0 && der_find(y.val, y.len, 0x82, &x) == 0 &&
		   der_find(y.val, y.len, 0xBF37, &x) == 0,
		   "direct: HandleNotification{BF50{BF54{82 txid, BF37 PIR}}} (step 13)");
		OK(fc.nnotes == 0, "direct: PIR delivered and removed");

		/* the host fails and no new PIR appears: profileDownloadError,
		 * even with an older PIR still waiting on the card */
		h.download_rc = -1;
		fake22_add_pir(&fc, "98001032547698103294");
		queue(&eim, &q);
		mark = eim.ngot;
		ipa_poll(a, &sum);
		m = last_result_notification(&eim, mark, &x);
		OK(m && der_find(x.val, x.len, 0xBF54, &y) == 0 &&
		   der_find(y.val, y.len, 0x30, &x) == 0 && der_find(x.val, x.len, 0x80, &y) == 0 && y.val[0] == 127,
		   "direct: failure reported as profileDownloadError undefinedError");
		h.download_rc = 0;

		/* --- indirect download through the eIM (3.2.3.2) --- */
		q.len = 0;
		k = der_begin(&q, 0xBF54);
		der_put(&q, 0x82, tx, 16);
		der_end(&q, k);
		queue(&eim, &q);
		snprintf(fc.install_iccid, sizeof(fc.install_iccid), "98001032547698103264");
		mark = eim.ngot;
		ipa_poll(a, &sum);
		OK(count_got(&eim, mark, 0xBF39) == 1 && count_got(&eim, mark, 0xBF3B) == 1 &&
		   count_got(&eim, mark, 0xBF3A) == 1, "indirect: InitiateAuthentication, AuthenticateClient, GetBPP");
		OK(!strcmp(fc.segs, "BF36 A0 A1 88 88 A3 86 86"), "indirect: BPP loaded in SGP.22 segments");
		if (strcmp(fc.segs, "BF36 A0 A1 88 88 A3 86 86"))
			fprintf(stderr, "  segments: %s\n", fc.segs);
		m = last_got(&eim, 0xBF39);
		OK(m && inner(m, 0x81, &x) == 0 && x.len == 16 && x.val[0] == 0xC4, "indirect: the card's challenge");
		OK(m && inner(m, 0xBF20, &x) == 0, "indirect: euiccInfo1 sent (no minimizeEsipaBytes)");
		OK(m && inner(m, 0x82, &x) == 0 && !memcmp(x.val, tx, 16), "indirect: eimTransactionId passed on");
		m = last_got(&eim, 0xBF3B);
		OK(m && inner(m, 0x80, &x) == 0 && inner(m, 0xBF38, &y) == 0, "indirect: BF3B{80 txid, BF38 response}");
		m = last_got(&eim, 0xBF3D);
		OK(m && inner(m, 0xA0, &x) == 0 && der_parse(x.val, x.len, &y) == 0 && y.tag == 0xBF37,
		   "indirect: PIR delivered as pendingNotification (step 23)");
		OK(fc.nnotes == 0 && fc.cancels == 0, "indirect: PIR removed, nothing cancelled");

		/* AuthenticateClient refused: cancel with pprNotAllowed (3.2.3.3) */
		eim.auth_client_error = 50;
		queue(&eim, &q);
		mark = eim.ngot;
		ipa_poll(a, &sum);
		OK(fc.cancels == 1 && fc.cancel_reason == 3, "cancel: ES10b.CancelSession, reason pprNotAllowed");
		m = last_got(&eim, 0xBF41);
		OK(m && inner(m, 0x80, &x) == 0 && inner(m, 0xA1, &y) == 0 && der_parse(y.val, y.len, &x) == 0 &&
		   x.tag == 0xA0, "cancel: BF41{80 txid, A1{card's response}}");
		OK(count_got(&eim, mark, 0xBF3A) == 0, "cancel: no GetBPP after a refusal");
		eim.auth_client_error = 0;
		db_free(&q);
	}

	/* --- an alternative this IPA does not know --- */
	{
		dbuf q;

		db_init(&q);
		der_put(&q, 0xBF60, NULL, 0);
		queue(&eim, &q);
		eim.invalid = true;
		ipa_poll(a, &sum);
		eim.invalid = false;
		m = last_got(&eim, 0xBF50);
		OK(m && inner(m, 0xA0, &x) == 0 && der_find(x.val, x.len, 0x02, &y) == 0 && y.val[0] == 2,
		   "unknown: eimPackageResultResponseError unknownPackage");
		db_free(&q);
	}

	/* --- connectivity (5.9.24): an SGP.22 card has none --- */
	OK(ipa_connectivity(a) == 0 && h.nconn == 1, "connectivity: host called");
	OK(!strcmp(h.conn_iccid, "89000123456789012343") && !h.conn_params && h.conn_emulated,
	   "connectivity: enabled ICCID, no parameters, emulated");

	/* --- the eIM unreachable: the poll says so --- */
	eim.offline = true;
	OK(ipa_poll(a, &sum) < 0, "offline: poll fails");
	eim.offline = false;

	ipa_close(a);
	emu_close(eu.emu);

	/* --- a trustedPublicKeyDataTls ipad cannot use: the CA bundle decides,
	 * and the log says so (a fresh emulation state on the same card) --- */
	{
		char st2[] = "/tmp/ipad-test-ipa2-XXXXXX";
		static const uint8_t junk[] = { 0x02, 0x01, 0x00 };
		dbuf c0, c1;
		der_tlv t;
		size_t m0, m1;

		close(mkstemp(st2));
		unlink(st2);
		ecfg.state_path = st2;
		eu.emu = emu_open(&c, &ecfg);
		db_init(&c0);
		db_init(&c1);
		eimpkg_cfg_ex(&c0, EIM, "eim.test.example:8443", 4, eim_key, false, NULL);
		der_parse(c0.d, c0.len, &t);
		m0 = der_begin(&c1, 0x30);
		db_put(&c1, t.val, t.len);
		m1 = der_begin(&c1, 0xA6);
		der_put(&c1, 0xA1, junk, sizeof(junk));   /* a "certificate" that does not parse */
		der_end(&c1, m1);
		der_end(&c1, m0);
		OK(eu.emu && ipa_add_initial_eim(&eu, c1.d, c1.len, err, sizeof(err)) == 0, "tls anchor: provisioned");
		h.last_log[0] = 0;
		a = ipa_open(&cfg);
		OK(a && strstr(h.last_log, "trustedPublicKeyDataTls unusable (certificate does not parse)") &&
		   strstr(h.last_log, "CA bundle"), "tls anchor: an unusable one is logged, the CA bundle named");
		OK(a && !ipa_tls(a)->pin_spki && !ipa_tls(a)->ca_der, "tls anchor: neither pin nor CA taken from it");
		ipa_close(a);
		emu_close(eu.emu);
		db_free(&c0);
		db_free(&c1);
		unlink(st2);
	}
	simcard_free(&s);
	fake22_free(&fc);
	for (mark = 0; mark < eim.ngot; mark++)
		db_free(&eim.got[mark]);
	for (mark = 0; mark < eim.nq; mark++)
		db_free(&eim.queue[mark]);
	db_free(&CERT);
	crypto_key_free(eim_key);
	crypto_key_free(dev_key);
	crypto_key_free(tls_key);
	unlink(state);
	if (dump)
		fclose(dump);
	DONE("test_ipa");
}
