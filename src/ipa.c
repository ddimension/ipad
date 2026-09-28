/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * Section numbers are SGP.32 v1.3 unless marked SGP.22 (v2.7). The message
 * layouts follow SGP32Definitions under AUTOMATIC TAGS: a component gets an
 * automatic tag only when none of its siblings carries one, which is why
 * IpaEuiccDataResponse is BF52{A0 ...} but ProvideEimPackageResult carries
 * its result untagged. Every message sent here is decoded by the eIM's own
 * ASN.1 types in tests/esipa_check (round trip, byte-identical).
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "ipa.h"
#include "nbo.h"
#include "crypto.h"
#include "hex.h"

#define ES9_MAX 16

struct ipa {
	ipa_config c;
	uint8_t eid[16];
	char eim_id[129];
	char url[320];
	uint8_t pin[512];
	dbuf ca;
	int cause;               /* state change cause for the next poll, -1 none */
	int64_t es9[ES9_MAX];    /* PIRs owed to their SM-DP+ over ES9+ (es9_path) */
	int nes9;
	/* the card's RetrieveNotificationsList without criteria, read once per
	 * poll (the package phase and the notification phase share it): on a
	 * consumer card with old notifications it is tens of kilobytes of GET
	 * RESPONSE. Dropped whenever the list may change. */
	dbuf nl;
	bool nl_ok;
	nbo nb;                  /* notification backoff (nbo.h, nbo_path) */
	bool nb_synced;          /* its eIM fingerprint checked in this delivery run */
};

#define DAP_URL_PATH "/gsma/rsp2/asn1"

/* ESipa error codes by name (SGP32Definitions.asn; 5.14.1 Table 13a adds
 * 50-52 to InitiateAuthentication). The code is what the eIM operator
 * searches for; neither carries an activation code or MatchingID. */
typedef struct { int v; const char *name; } code_name;

static const code_name IA_ERR[] = {
	{ 1, "invalidDpAddress" }, { 2, "euiccVersionNotSupportedByDp" }, { 3, "ciPKIdNotSupported" },
	{ 50, "smdpAddressMismatch" }, { 51, "smdpOidMismatch" }, { 52, "invalidEimTransactionId" },
	{ 127, "undefinedError" }, { 0, NULL }
};
static const code_name AC_ERR[] = {
	{ 1, "eumCertificateInvalid" }, { 2, "eumCertificateExpired" }, { 3, "euiccCertificateInvalid" },
	{ 4, "euiccCertificateExpired" }, { 5, "euiccSignatureInvalid" }, { 6, "matchingIdRefused" },
	{ 7, "eidMismatch" }, { 8, "noEligibleProfile" }, { 9, "ciPKUnknown" }, { 10, "invalidTransactionId" },
	{ 11, "insufficientMemory" }, { 18, "downloadOrderExpired" }, { 50, "pprNotAllowed" },
	{ 56, "eventIdUnknown" }, { 127, "undefinedError" }, { 0, NULL }
};
static const code_name GBPP_ERR[] = {
	{ 1, "euiccSignatureInvalid" }, { 2, "confirmationCodeMissing" }, { 3, "confirmationCodeRefused" },
	{ 4, "confirmationCodeRetriesExceeded" }, { 5, "bppRebindingRefused" }, { 6, "deprecated" },
	{ 50, "metadataMismatch" }, { 95, "invalidTransactionId" }, { 127, "undefinedError" }, { 0, NULL }
};
/* eimPackageError of GetEimPackage and provideEimPackageResultError */
static const code_name PKG_ERR[] = {
	{ 1, "noEimPackageAvailable" }, { 2, "eidNotFound" }, { 3, "invalidEid" }, { 4, "missingEid" },
	{ 127, "undefinedError" }, { 0, NULL }
};

/* v < 0: the answer carried no code */
static const char *code_of(const code_name *t, int64_t v)
{
	if (v < 0)
		return "no code";
	for (; t->name; t++)
		if (t->v == v)
			return t->name;
	return "unknown";
}

static void say(const ipa *a, int lvl, const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	if (!a->c.host.log)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	a->c.host.log(a->c.host.ud, lvl, buf);
}

/* The eIM configuration names a TLS trust anchor ipad cannot use. The
 * connection still goes ahead on the CA bundle, as it would without one
 * (SGP.32 leaves trustedPublicKeyDataTls optional), but the operator meant
 * something stricter and should hear that it is not in force. */
static void tls_unusable(const ipa *a, const char *why)
{
	say(a, LOG_WARNING, "eIM %s: trustedPublicKeyDataTls unusable (%s); the CA bundle %s decides instead",
	    a->eim_id, why, a->c.tls.ca_file ? a->c.tls.ca_file : "/etc/ssl/certs/ca-certificates.crt");
}

/* one ES10 function; the answer must be a single TLV with the request's tag */
static int es10(euicc *eu, const uint8_t *req, size_t len, dbuf *resp, der_tlv *t)
{
	der_tlv q;

	resp->len = 0;
	if (euicc_es10(eu, req, len, resp) < 0 || resp->err)
		return -1;
	if (!t)
		return 0;
	if (der_parse(resp->d, resp->len, t) < 0 || der_parse(req, len, &q) < 0 || t->tag != q.tag)
		return -1;
	return 0;
}

static int es10_empty(euicc *eu, uint32_t tag, dbuf *resp, der_tlv *t)
{
	dbuf q;
	int rc;

	db_init(&q);
	der_put(&q, tag, NULL, 0);
	rc = es10(eu, q.d, q.len, resp, t);
	db_free(&q);
	return rc;
}

/* ICCID (EF.ICCID, nibble-swapped BCD, F padding) as digits */
static void iccid_str(const uint8_t *b, size_t n, char out[21])
{
	static const char dig[] = "0123456789ABCDEF";
	size_t i, k = 0;

	for (i = 0; i < n && i < 10; i++) {
		uint8_t lo = b[i] & 0x0F, hi = b[i] >> 4;

		if (lo != 0xF)
			out[k++] = dig[lo];
		if (hi != 0xF)
			out[k++] = dig[hi];
	}
	out[k] = 0;
}

int ipa_enabled_iccid(euicc *eu, char out[21])
{
	/* ProfileInfoListRequest with tagList {ICCID, profileState} (SGP.22 5.7.15) */
	static const uint8_t req[] = { 0xBF, 0x2D, 0x05, 0x5C, 0x03, 0x5A, 0x9F, 0x70 };
	dbuf r;
	der_tlv t, list, e, x;
	const uint8_t *p, *end;
	int rc = -1;

	out[0] = 0;
	db_init(&r);
	if (es10(eu, req, sizeof(req), &r, &t) == 0 && der_find(t.val, t.len, 0xA0, &list) == 0) {
		rc = 0;
		for (p = list.val, end = list.val + list.len; p < end; ) {
			if (der_next(&p, end, &e) < 0)
				break;
			if (der_find(e.val, e.len, 0x9F70, &x) == 0 && x.len == 1 && x.val[0] == 1 &&
			    der_find(e.val, e.len, 0x5A, &x) == 0) {
				iccid_str(x.val, x.len, out);
				break;
			}
		}
	}
	db_free(&r);
	return rc;
}

/* ---- ESipa transport (6.1.1: HTTP POST, ASN.1 binding) ---- */

static int esipa(ipa *a, const dbuf *msg, int *status, dbuf *resp)
{
	static const char *const hdrs[] = {
		"Content-Type: application/x-gsma-rsp-asn1",
		"X-Admin-Protocol: gsma/rsp/v1.3.0",
		"User-Agent: gsma-rsp-ipad; ipad",
		NULL,
	};
	http_resp r;
	int rc;

	resp->len = 0;
	*status = 0;
	if (msg->err)
		return -1;
	if (a->c.transport)
		return a->c.transport(a->c.transport_ud, msg->d, msg->len, status, resp);

	memset(&r, 0, sizeof(r));
	db_init(&r.body);
	rc = http_post(a->url, hdrs, msg->d, msg->len, &a->c.tls, &r);
	*status = r.status;
	if (rc < 0)
		say(a, LOG_WARNING, "eIM %s: %s", a->url, r.error);
	else
		db_put(resp, r.body.d, r.body.len);
	db_free(&r.body);
	return rc;
}

/* a request that expects an answer tagged `tag`; t is that answer's TLV */
static int esipa_call(ipa *a, const char *fn, const dbuf *msg, uint32_t tag, dbuf *resp, der_tlv *t)
{
	int status;

	if (esipa(a, msg, &status, resp) < 0)
		return -1;
	if (status != 200 || der_parse(resp->d, resp->len, t) < 0 || t->tag != tag) {
		say(a, LOG_WARNING, "%s: the eIM answered HTTP %d without the expected %X", fn, status, (unsigned)tag);
		return -1;
	}
	return 0;
}

/* HandleNotification has no response message (5.14.7): 204, or 200 */
/* 0 delivered; -1 the eIM was not reached; -2 it answered and did not
 * take this one (an error status: the eIM keeps it for later, e.g. a PIR it
 * cannot attribute yet, eIM decision D-85) */
static int esipa_notify(ipa *a, const dbuf *msg)
{
	dbuf resp;
	int status, rc;

	db_init(&resp);
	rc = esipa(a, msg, &status, &resp);
	db_free(&resp);
	if (rc < 0)
		return -1;
	return (status == 204 || status == 200) ? 0 : -2;
}

/* ---- notifications ---- */

/* NotificationMetadata of a PendingNotification as the card stores it:
 * inside BF37's BF27 for a PIR, directly in an OtherSignedNotification 30 */
static int notif_meta(const der_tlv *n, der_tlv *md)
{
	der_tlv a;
	const uint8_t *p = n->val;
	size_t len = n->len;

	if (n->tag == 0xBF37) {
		if (der_find(n->val, n->len, 0xBF27, &a) < 0)
			return -1;
		p = a.val;
		len = a.len;
	}
	return der_find(p, len, 0xBF2F, md);
}

static int meta_seq(const der_tlv *md, int64_t *seq)
{
	der_tlv s;

	if (der_find(md->val, md->len, 0x80, &s) < 0)
		return -1;
	return der_get_int(&s, seq);
}

/* seqNumber of a PendingNotification */
static int notif_seq(const der_tlv *n, int64_t *seq)
{
	der_tlv md;

	if (notif_meta(n, &md) < 0)
		return -1;
	return meta_seq(&md, seq);
}

static int remove_seq(ipa *a, int64_t seq)
{
	dbuf q, r;
	der_tlv t, x;
	int64_t v = -1;
	size_t m;

	a->nl_ok = false;
	db_init(&q);
	db_init(&r);
	m = der_begin(&q, 0xBF30);
	der_put_int(&q, 0x80, seq);
	der_end(&q, m);
	if (es10(a->c.eu, q.d, q.len, &r, &t) == 0 && der_find(t.val, t.len, 0x80, &x) == 0)
		der_get_int(&x, &v);
	db_free(&q);
	db_free(&r);
	if (v != 0)
		say(a, LOG_NOTICE, "RemoveNotificationFromList %lld: result %lld", (long long)seq, (long long)v);
	return v == 0 ? 0 : -1;
}

/* RetrieveNotificationsList (5.9.11); criteria: the content of the
 * searchCriteria CHOICE (80 seq / 81 events / 82 EPRs), NULL for none */
static int retrieve(ipa *a, const uint8_t *crit, size_t clen, dbuf *resp, der_tlv *t)
{
	dbuf q;
	size_t m;
	int rc;

	if (!crit && a->nl_ok) {
		resp->len = 0;
		db_put(resp, a->nl.d, a->nl.len);
		return resp->err || der_parse(resp->d, resp->len, t) < 0 ? -1 : 0;
	}
	db_init(&q);
	m = der_begin(&q, 0xBF2B);
	if (crit)
		der_put(&q, 0xA0, crit, clen);
	der_end(&q, m);
	rc = es10(a->c.eu, q.d, q.len, resp, t);
	db_free(&q);
	if (rc == 0 && !crit) {
		a->nl.len = 0;
		db_put(&a->nl, resp->d, resp->len);
		a->nl_ok = !a->nl.err;
	}
	return rc;
}

/* ---- a direct download's PIR: ES9+ through the host ----
 *
 * SGP.32 3.2.3.1 has the IPA send the PIR to the SM-DP+ (Figure 9 step [14]:
 * IPA -> SM-DP+ ES9+.HandleNotification; 3.7 [2a] when a direct ES9+
 * interface is used). The eIM gets it only inside the
 * ProfileDownloadTriggerResult (step 13), and it forwards a PIR only when it
 * belongs to an Indirect Profile Download session it runs (5.7.4), so a PIR
 * of a direct download handed to it alone reaches no SM-DP+. The record
 * below is what keeps such a PIR on the ES9+ route across runs: written
 * before the delivery is tried, cleared once the host confirmed it. */

static void es9_save(const ipa *a)
{
	char tmp[600];
	FILE *f;
	int i;

	if (!a->c.es9_path)
		return;
	if (!a->nes9) {
		remove(a->c.es9_path);
		return;
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", a->c.es9_path);
	if (!(f = fopen(tmp, "w"))) {
		say(a, LOG_WARNING, "%s: cannot write the ES9+ record", tmp);
		return;
	}
	for (i = 0; i < a->nes9; i++)
		fprintf(f, "%lld\n", (long long)a->es9[i]);
	if (fclose(f) != 0 || rename(tmp, a->c.es9_path) != 0) {
		remove(tmp);
		say(a, LOG_WARNING, "%s: cannot write the ES9+ record", a->c.es9_path);
	}
}

static void es9_load(ipa *a)
{
	FILE *f;
	long long v;

	a->nes9 = 0;
	if (!a->c.es9_path || !(f = fopen(a->c.es9_path, "r")))
		return;
	while (a->nes9 < ES9_MAX && fscanf(f, "%lld", &v) == 1)
		a->es9[a->nes9++] = v;
	fclose(f);
}

static bool es9_owed(const ipa *a, int64_t seq)
{
	int i;

	for (i = 0; i < a->nes9; i++)
		if (a->es9[i] == seq)
			return true;
	return false;
}

static void es9_set(ipa *a, int64_t seq, bool owed)
{
	int i;

	if (owed == es9_owed(a, seq))
		return;
	if (owed) {
		/* full: the oldest goes, and with it only the ES9+ preference;
		 * the PIR itself stays on the card and goes to the eIM */
		if (a->nes9 == ES9_MAX) {
			memmove(a->es9, a->es9 + 1, (ES9_MAX - 1) * sizeof(a->es9[0]));
			a->nes9--;
		}
		a->es9[a->nes9++] = seq;
	} else {
		for (i = 0; i < a->nes9 && a->es9[i] != seq; i++)
			;
		memmove(a->es9 + i, a->es9 + i + 1, (size_t)(a->nes9 - i - 1) * sizeof(a->es9[0]));
		a->nes9--;
	}
	es9_save(a);
}

/* 0 once the host delivered it (and removed it from the card) */
static int es9_deliver(ipa *a, int64_t seq)
{
	int rc;

	/* the host's ES9+ client (lpac) reads and removes the notification on
	 * the ISD-R itself, over the one channel the bridge relays: give ours
	 * back; card_es10 reopens it afterwards */
	card_close(a->c.eu->card);
	rc = a->c.host.notify(a->c.host.ud, seq);
	a->nl_ok = false;
	if (rc == 0) {
		es9_set(a, seq, false);
		say(a, LOG_NOTICE, "PIR %lld delivered to the SM-DP+ over ES9+", (long long)seq);
	} else {
		say(a, LOG_WARNING, "PIR %lld not delivered to the SM-DP+ over ES9+, kept for the next run",
		    (long long)seq);
	}
	return rc;
}

/* The backoff's records hold for the eIM configurations they were made
 * under (nbo.h): checked once per delivery run, against
 * GetEimConfigurationData (5.9.18, which carries no counterValue, so a
 * package does not count as a change). A card that does not answer leaves
 * the records as they are. */
static void nb_sync(ipa *a)
{
	dbuf r;
	der_tlv t;
	uint8_t fp[8];

	if (a->nb_synced)
		return;
	a->nb_synced = true;
	db_init(&r);
	if (es10_empty(a->c.eu, 0xBF55, &r, &t) == 0) {
		nbo_fp(t.raw, t.raw_len, fp);
		nbo_eims(&a->nb, fp);
	}
	db_free(&r);
}

#define SEEN_MAX 64

int ipa_deliver_notifications(ipa *a)
{
	dbuf r, msg;
	der_tlv t, list, n;
	const uint8_t *p, *end;
	int sent = 0, held = 0;
	/* the seqNumbers still on the card after this run, for dropping stale
	 * records (ES9+ and backoff); only once the whole list was seen */
	int64_t seen[SEEN_MAX];
	int nseen = 0, i, rc;
	bool listed = false;
	int64_t now = a->c.clock ? a->c.clock() : (int64_t)time(NULL);

#define SEEN(s) (nseen < SEEN_MAX ? (void)(seen[nseen++] = (s)) : (void)(listed = false))

	db_init(&r);
	db_init(&msg);
	a->nb_synced = false;
	if (retrieve(a, NULL, 0, &r, &t) == 0 && der_find(t.val, t.len, 0xA0, &list) == 0) {
		listed = true;
		for (p = list.val, end = list.val + list.len; p < end; ) {
			int64_t seq;
			size_t m, k;
			der_tlv md;
			uint8_t fp[8];

			/* a list that does not parse to its end, or a notification
			 * without a seqNumber, leaves notifications unseen: every
			 * record stays, as one of them may be theirs */
			if (der_next(&p, end, &n) < 0) {
				say(a, LOG_WARNING, "notification list does not parse to its end, the rest skipped");
				listed = false;
				break;
			}
			if (notif_meta(&n, &md) < 0 || meta_seq(&md, &seq) < 0) {
				say(a, LOG_WARNING, "notification without a sequence number, skipped");
				listed = false;
				continue;
			}
			if (a->c.host.notify && es9_owed(a, seq)) {
				if (es9_deliver(a, seq) == 0)
					sent++;
				else
					SEEN(seq);
				continue;
			}
			/* the metadata identifies the notification: what a
			 * metadata-only listing gives as well */
			nbo_fp(md.raw, md.raw_len, fp);
			if (a->nb.n)
				nb_sync(a);
			if (!nbo_due(&a->nb, seq, fp, now)) {
				held++;
				SEEN(seq);
				continue;
			}
			/* HandleNotificationEsipa { pendingNotification [0] } (5.14.7);
			 * [0] is explicit because PendingNotification is a CHOICE */
			msg.len = 0;
			m = der_begin(&msg, 0xBF3D);
			k = der_begin(&msg, 0xA0);
			db_put(&msg, n.raw, n.raw_len);
			der_end(&msg, k);
			der_end(&msg, m);
			rc = esipa_notify(a, &msg);
			/* One the eIM answers but does not take stays on the card
			 * (3.7: only an acknowledged one is removed) and the next one
			 * goes out: stopping here let a single notification the eIM
			 * keeps refusing (a PIR it cannot attribute) hold back every
			 * later one of the card. It then waits out a backoff (nbo.h). */
			if (rc == -2) {
				nb_sync(a);
				say(a, LOG_WARNING, "notification %lld not taken by the eIM, kept; offered again in %llds",
				    (long long)seq, (long long)nbo_refused(&a->nb, seq, fp, now));
				SEEN(seq);
				continue;
			}
			if (rc < 0) {
				say(a, LOG_WARNING, "notification %lld not delivered, kept", (long long)seq);
				listed = false;   /* not all seen: no record is dropped */
				break;   /* the eIM is unreachable; the rest waits too */
			}
			if (remove_seq(a, seq) < 0)
				SEEN(seq);
			sent++;
		}
	}
#undef SEEN
	if (held)
		say(a, LOG_DEBUG, "%d notification(s) the eIM did not take held back until their retry time", held);
	/* a record whose notification is no longer on the card (removed by
	 * other means) is dropped; a list the card did not give, or not all
	 * of, leaves the records alone */
	if (listed && a->c.host.notify) {
		for (i = a->nes9 - 1; i >= 0; i--) {
			int j;

			for (j = 0; j < nseen && seen[j] != a->es9[i]; j++)
				;
			if (j == nseen)
				es9_set(a, a->es9[i], false);
		}
	}
	if (listed)
		nbo_keep(&a->nb, seen, nseen);
	a->nl_ok = false;   /* the run's last reader; others change the card */
	db_free(&r);
	db_free(&msg);
	return sent;
}

/* ---- ProvideEimPackageResult (5.14.6) ---- */

/* result: one EimPackageResult alternative as encoded (BF51 / BF52 / BF54 /
 * A0 error / 30 ePRAndNotifications). Removes what the eIM acknowledged;
 * returns the count, or -1 when the eIM was not reached. */
static int provide(ipa *a, const uint8_t *result, size_t len, bool as_notification)
{
	dbuf msg, resp;
	der_tlv t, acks, s;
	const uint8_t *p, *end;
	size_t m, k = 0;
	int n = 0;

	db_init(&msg);
	db_init(&resp);
	if (as_notification)
		k = der_begin(&msg, 0xBF3D);   /* HandleNotificationEsipa.provideEimPackageResult */
	m = der_begin(&msg, 0xBF50);
	der_put(&msg, 0x5A, a->eid, 16);
	db_put(&msg, result, len);
	der_end(&msg, m);
	if (as_notification) {
		der_end(&msg, k);
		n = esipa_notify(a, &msg);
		goto out;
	}

	if (esipa_call(a, "ProvideEimPackageResult", &msg, 0xBF50, &resp, &t) < 0) {
		n = -1;
		goto out;
	}
	/* eimAcknowledgements BF53 { 80 seq ... } | emptyResponse 30 00 | error 02 */
	if (der_find(t.val, t.len, 0xBF53, &acks) == 0) {
		for (p = acks.val, end = acks.val + acks.len; p < end; ) {
			int64_t seq;

			if (der_next(&p, end, &s) < 0 || s.tag != 0x80 || der_get_int(&s, &seq) < 0)
				break;
			if (remove_seq(a, seq) == 0)
				n++;
		}
	} else if (der_find(t.val, t.len, 0x02, &s) == 0) {
		int64_t e = 0;

		der_get_int(&s, &e);
		say(a, LOG_WARNING, "eIM refused the result: provideEimPackageResultError %lld (%s)", (long long)e,
		    code_of(PKG_ERR, e));
	}
out:
	db_free(&msg);
	db_free(&resp);
	return n;
}

/* ---- eUICC Package (3.3.1, 3.3.2) ---- */

static int handle_package(ipa *a, const der_tlv *pkg, ipa_summary *sum)
{
	char before[21], after[21];
	dbuf r, rb;
	der_tlv t, x;
	bool changed, online = true;
	int n;

	db_init(&r);
	db_init(&rb);
	if (ipa_enabled_iccid(a->c.eu, before) < 0)
		before[0] = 0;
	if (es10(a->c.eu, pkg->raw, pkg->raw_len, &r, &t) < 0 || t.tag != 0xBF51) {
		say(a, LOG_ERR, "the eUICC did not execute the eUICC Package");
		db_free(&r);
		return -1;
	}
	if (ipa_enabled_iccid(a->c.eu, after) < 0)
		strcpy(after, before);
	changed = strcmp(before, after) != 0;
	if (changed) {
		sum->profile_changed = true;
		say(a, LOG_NOTICE, "enabled profile %s -> %s", before[0] ? before : "none",
		    after[0] ? after : "none");
		/* The host applies the switch with a SIM reset, which closes every
		 * logical channel on the card. Kept, ours would carry the
		 * ProfileRollback below — the one call that must work when the new
		 * profile does not — to a channel that no longer exists. Closed
		 * while the card still answers; card_es10 opens a fresh one. */
		card_close(a->c.eu->card);
		if (a->c.host.profile_changed)
			online = a->c.host.profile_changed(a->c.host.ud, after);
	}

	n = online ? provide(a, r.d, r.len, false) : -1;
	if (n < 0 && changed) {
		/* 3.3.2: the result could not reach the eIM over the new profile */
		static const uint8_t req[] = { 0xBF, 0x58, 0x03, 0x01, 0x01, 0x00 };   /* refreshFlag FALSE: the host resets */
		int64_t v = -1;

		if (es10(a->c.eu, req, sizeof(req), &rb, &t) == 0 && der_find(t.val, t.len, 0x02, &x) == 0)
			der_get_int(&x, &v);
		if (v == 0 && der_find(t.val, t.len, 0xBF51, &x) == 0) {
			say(a, LOG_NOTICE, "profile rolled back to %s", before[0] ? before : "none");
			sum->rolled_back = true;
			card_close(a->c.eu->card);   /* the host resets the SIM again */
			if (a->c.host.profile_changed)
				a->c.host.profile_changed(a->c.host.ud, before);
			/* the rollback's result replaces the package's (NOTE1) */
			n = provide(a, x.raw, x.raw_len, false);
		} else {
			say(a, LOG_WARNING, "ProfileRollback: %lld; the result stays on the eUICC", (long long)v);
		}
	}
	if (n > 0)
		sum->acknowledged += n;
	db_free(&r);
	db_free(&rb);
	return n < 0 ? -1 : 0;
}

/* ---- IpaEuiccDataRequest (2.11.1.2, answered per 2.11.2.2) ---- */

static bool has_tag(const der_tlv *list, uint32_t want)
{
	const uint8_t *p = list->val, *end = list->val + list->len;

	while (p < end) {
		uint32_t tag = *p++;

		if ((tag & 0x1F) == 0x1F)
			do
				tag = (tag << 8) | (p < end ? *p : 0);
			while (p < end && (*p++ & 0x80));
		if (tag == want)
			return true;
	}
	return false;
}

void ipa_put_capabilities(dbuf *b, uint32_t tag, bool direct)
{
	/* ipaFeatures: directRspServerCommunication(0) when the host downloads,
	 * indirectRspServerCommunication(1) and eimDownloadDataHandling(2)
	 * always: the eIM may keep the activation code and send an empty
	 * trigger (2.11.1.3); ipaSupportedProtocols: ipaRetrieveHttps(0) (4.1) */
	const uint8_t feat[3] = { direct, 1, 1 }, proto[1] = { 1 };   /* one byte per named bit */
	size_t m = der_begin(b, tag);

	der_put_bits(b, 0x80, feat, 3);
	der_put_bits(b, 0x81, proto, 1);
	der_end(b, m);
}

/* DeviceInfo (SGP.22 4.2) under `tag`; the releases are what an LTE/NR
 * module of this generation implements, R15 */
static void put_device_info(const ipa *a, dbuf *b, uint32_t tag)
{
	static const uint8_t r15[3] = { 15, 0, 0 };
	size_t m = der_begin(b, tag), k;

	der_put(b, 0x80, a->c.tac, 4);
	k = der_begin(b, 0xA1);
	der_put(b, 0x80, r15, 3);   /* gsmSupportedRelease */
	der_put(b, 0x81, r15, 3);   /* utranSupportedRelease */
	der_put(b, 0x85, r15, 3);   /* eutranEpcSupportedRelease */
	der_end(b, k);
	if (a->c.has_imei)
		der_put(b, 0x82, a->c.imei, 8);
	der_end(b, m);
}

/* the associationToken of the eIM we talk to, from its configuration */
static bool assoc_token(ipa *a, int64_t *tok)
{
	dbuf r;
	der_tlv t, list, c, x;
	const uint8_t *p, *end;
	bool found = false;

	db_init(&r);
	if (es10_empty(a->c.eu, 0xBF55, &r, &t) == 0 && der_find(t.val, t.len, 0xA0, &list) == 0)
		for (p = list.val, end = list.val + list.len; p < end && !found; ) {
			if (der_next(&p, end, &c) < 0)
				break;
			if (der_find(c.val, c.len, 0x80, &x) == 0 && x.len == strlen(a->eim_id) &&
			    !memcmp(x.val, a->eim_id, x.len) && der_find(c.val, c.len, 0x84, &x) == 0)
				found = der_get_int(&x, tok) == 0;
		}
	db_free(&r);
	return found;
}

static int handle_data(ipa *a, const der_tlv *req, ipa_summary *sum)
{
	dbuf out, r, crit;
	der_tlv tags, t, x, y, txid = { 0 };
	bool has_txid = der_find(req->val, req->len, 0x83, &txid) == 0;
	size_t m, d;
	int n;

	db_init(&out);
	db_init(&r);
	db_init(&crit);
	m = der_begin(&out, 0xBF52);

	if (der_find(req->val, req->len, 0x5C, &tags) < 0) {
		/* IpaEuiccDataResponseError { [0] txid, code } -> A1 */
		d = der_begin(&out, 0xA1);
		if (has_txid)
			der_put(&out, 0x80, txid.val, txid.len);
		der_put_int(&out, 0x02, 1);   /* incorrectTagList */
		der_end(&out, d);
		goto send;
	}

	d = der_begin(&out, 0xA0);   /* IpaEuiccData, components in declaration order */
	if (has_tag(&tags, 0xA0)) {
		const uint8_t *c = NULL;
		size_t cl = 0;

		if (der_find(req->val, req->len, 0xA1, &x) == 0) {   /* searchCriteriaNotification */
			c = x.val;
			cl = x.len;
		}
		if (retrieve(a, c, cl, &r, &t) == 0 && der_find(t.val, t.len, 0xA0, &y) == 0)
			der_put(&out, 0xA0, y.val, y.len);
	}
	if (has_tag(&tags, 0x81) || has_tag(&tags, 0x83)) {
		if (es10_empty(a->c.eu, 0xBF3C, &r, &t) == 0) {
			if (has_tag(&tags, 0x81) && der_find(t.val, t.len, 0x80, &x) == 0)
				der_put(&out, 0x81, x.val, x.len);
		}
	}
	if (has_tag(&tags, 0xA2)) {
		static const uint8_t all[] = { 0x82, 0x00 };
		const uint8_t *c = all;
		size_t cl = sizeof(all);

		if (der_find(req->val, req->len, 0xA2, &x) == 0 && der_find(x.val, x.len, 0x80, &y) == 0) {
			c = y.raw;   /* one result by seqNumber */
			cl = y.raw_len;
		}
		if (retrieve(a, c, cl, &r, &t) == 0 && der_find(t.val, t.len, 0xA2, &y) == 0)
			der_put(&out, 0xA2, y.val, y.len);
	}
	if (has_tag(&tags, 0xBF20) && es10_empty(a->c.eu, 0xBF20, &r, &t) == 0)
		db_put(&out, t.raw, t.raw_len);
	if (has_tag(&tags, 0xBF22) && es10_empty(a->c.eu, 0xBF22, &r, &t) == 0)
		db_put(&out, t.raw, t.raw_len);
	if (has_tag(&tags, 0x83) && es10_empty(a->c.eu, 0xBF3C, &r, &t) == 0 &&
	    der_find(t.val, t.len, 0x81, &x) == 0)
		der_put(&out, 0x83, x.val, x.len);
	if (has_tag(&tags, 0x84)) {
		int64_t tok;

		if (assoc_token(a, &tok))
			der_put_int(&out, 0x84, tok);
	}
	if (has_tag(&tags, 0xA5) || has_tag(&tags, 0xA6)) {
		/* GetCerts (5.9.10), with the CI key id the eIM chose */
		size_t q = der_begin(&crit, 0xBF56);

		if (der_find(req->val, req->len, 0x04, &x) == 0)
			der_put(&crit, 0x04, x.val, x.len);
		der_end(&crit, q);
		if (es10(a->c.eu, crit.d, crit.len, &r, &t) == 0 && der_find(t.val, t.len, 0xA0, &y) == 0) {
			if (has_tag(&tags, 0xA5) && der_find(y.val, y.len, 0xA5, &x) == 0)
				db_put(&out, x.raw, x.raw_len);
			if (has_tag(&tags, 0xA6) && der_find(y.val, y.len, 0xA6, &x) == 0)
				db_put(&out, x.raw, x.raw_len);
		}
	}
	if (has_txid)
		der_put(&out, 0x87, txid.val, txid.len);
	if (has_tag(&tags, 0xA8))
		ipa_put_capabilities(&out, 0xA8, a->c.host.download != NULL);
	if (has_tag(&tags, 0xA9))
		put_device_info(a, &out, 0xA9);
	der_end(&out, d);

send:
	der_end(&out, m);
	n = provide(a, out.d, out.len, false);
	if (n > 0)
		sum->acknowledged += n;
	db_free(&out);
	db_free(&r);
	db_free(&crit);
	return n < 0 ? -1 : 0;
}

/* ---- Profile download (3.2.3) ---- */

/* SGP.22 4.1: [LPA:]1$SM-DP+ address$AC token[$SM-DP+ OID[$CC flag]]; the
 * token (MatchingID) for ctxParams1. The address stays with the eIM (5.14.1). */
static int parse_ac(const char *ac, char *mid, size_t midl)
{
	const char *p, *q;

	if (!strncmp(ac, "LPA:", 4))
		ac += 4;
	if (strncmp(ac, "1$", 2))
		return -1;
	p = ac + 2;
	if (!(q = strchr(p, '$')) || q == p)
		return -1;
	p = q + 1;
	q = strchr(p, '$');
	if (!q)
		q = p + strlen(p);
	if ((size_t)(q - p) >= midl)
		return -1;
	memcpy(mid, p, (size_t)(q - p));
	mid[q - p] = 0;
	return 0;
}

/* ES10b.CancelSession then ESipa.CancelSession (3.2.3.3) */
static void cancel_session(ipa *a, const der_tlv *txid, int reason)
{
	dbuf q, r, msg, resp;
	der_tlv t;
	size_t m, k;

	db_init(&q);
	db_init(&r);
	db_init(&msg);
	db_init(&resp);
	m = der_begin(&q, 0xBF41);
	der_put(&q, 0x80, txid->val, txid->len);
	der_put_int(&q, 0x81, reason);
	der_end(&q, m);
	if (es10(a->c.eu, q.d, q.len, &r, &t) == 0) {
		/* CancelSessionRequestEsipa { txid [0], response [1] }: automatic
		 * tags, [1] explicit over the CHOICE, so the card's BF41 content
		 * goes inside A1 */
		m = der_begin(&msg, 0xBF41);
		der_put(&msg, 0x80, txid->val, txid->len);
		k = der_begin(&msg, 0xA1);
		db_put(&msg, t.val, t.len);
		der_end(&msg, k);
		der_end(&msg, m);
		if (esipa_call(a, "CancelSession", &msg, 0xBF41, &resp, &t) < 0)
			say(a, LOG_WARNING, "CancelSession not confirmed by the eIM");
	}
	db_free(&q);
	db_free(&r);
	db_free(&msg);
	db_free(&resp);
}

/* LoadBoundProfilePackage in the segments SGP.22 2.5.5 prescribes (as lpac
 * v2.3.0 es10b.c sends them): BF36+BF23 header, A0, A1 header then each
 * 88, A2, A3 header then each 86. A non-empty answer is the Profile
 * Installation Result and ends the load, successful or not. */
static int load_bpp(ipa *a, const der_tlv *bpp, dbuf *pir)
{
	der_tlv x, s;
	const uint8_t *p, *end;
	static const uint32_t order[] = { 0xA0, 0xA1, 0xA2, 0xA3 };
	size_t i;

#define SEG(ptr, n)                                                             \
	do {                                                                    \
		if (euicc_es10(a->c.eu, (ptr), (n), pir) < 0)                   \
			return -1;                                              \
		if (pir->len)                                                   \
			return 0;                                               \
	} while (0)

	pir->len = 0;
	if (der_find(bpp->val, bpp->len, 0xBF23, &x) < 0)
		return -1;
	SEG(bpp->raw, (size_t)(x.raw + x.raw_len - bpp->raw));
	for (i = 0; i < sizeof(order) / sizeof(order[0]); i++) {
		if (der_find(bpp->val, bpp->len, order[i], &x) < 0) {
			if (order[i] == 0xA2)
				continue;   /* the only optional one */
			return -1;
		}
		if (order[i] == 0xA0 || order[i] == 0xA2) {
			SEG(x.raw, x.raw_len);
			continue;
		}
		SEG(x.raw, (size_t)(x.val - x.raw));
		for (p = x.val, end = x.val + x.len; p < end; ) {
			if (der_next(&p, end, &s) < 0)
				return -1;
			SEG(s.raw, s.raw_len);
		}
	}
#undef SEG
	return 0;
}

/* 3.2.3.2. Returns 0 when a BPP was loaded (the PIR then goes out with the
 * notifications, step 23), -1 otherwise. */
static int indirect_download(ipa *a, const char *ac, const der_tlv *eim_txid)
{
	char mid[256] = "";
	dbuf msg, resp, r, info1, chal, ctx, pir;
	der_tlv t, ok, x, ss1, sig1, ckid, cert, txid, y;
	const uint8_t *p, *end;
	int rc = -1, reason = 127;
	bool have_txid = false;
	size_t m, k;

	db_init(&msg);
	db_init(&resp);
	db_init(&r);
	db_init(&info1);
	db_init(&chal);
	db_init(&ctx);
	db_init(&pir);

	if (ac && parse_ac(ac, mid, sizeof(mid)) < 0) {
		say(a, LOG_ERR, "activation code not understood");
		goto out;
	}
	if (es10_empty(a->c.eu, 0xBF20, &info1, &t) < 0 ||
	    es10_empty(a->c.eu, 0xBF2E, &chal, &t) < 0 || der_find(t.val, t.len, 0x80, &x) < 0) {
		say(a, LOG_ERR, "no eUICC challenge");
		goto out;
	}

	/* InitiateAuthenticationRequestEsipa. No smdpAddress, even from an
	 * activation code: with eimDownloadDataHandling the IPA SHALL NOT send
	 * it (5.14.1), the eIM holds the address and checks serverSigned1
	 * against it; an empty trigger (3.2.3.2 step 3) has none anyway */
	m = der_begin(&msg, 0xBF39);
	der_put(&msg, 0x81, x.val, x.len);
	db_put(&msg, info1.d, info1.len);
	if (eim_txid)
		der_put(&msg, 0x82, eim_txid->val, eim_txid->len);
	der_end(&msg, m);
	if (esipa_call(a, "InitiateAuthentication", &msg, 0xBF39, &resp, &t) < 0)
		goto out;
	if (der_find(t.val, t.len, 0xA0, &ok) < 0) {
		int64_t e = -1;

		/* initiateAuthenticationErrorEsipa: the CHOICE's [1] (AUTOMATIC TAGS) */
		if (der_find(t.val, t.len, 0x81, &y) == 0)
			der_get_int(&y, &e);
		say(a, LOG_ERR, "InitiateAuthentication refused by the eIM: %lld (%s)", (long long)e,
		    code_of(IA_ERR, e));
		goto out;
	}
	/* 80 txid?, 30 serverSigned1, 5F37, 04 ciPKId, 30 serverCertificate,
	 * 0C matchingId?, A2 ctxParams1? */
	p = ok.val;
	end = ok.val + ok.len;
	memset(&ss1, 0, sizeof(ss1));
	memset(&cert, 0, sizeof(cert));
	while (p < end && der_next(&p, end, &y) == 0) {
		if (y.tag == 0x30 && !ss1.raw)
			ss1 = y;
		else if (y.tag == 0x30)
			cert = y;
	}
	if (!ss1.raw || !cert.raw || der_find(ok.val, ok.len, 0x5F37, &sig1) < 0 ||
	    der_find(ok.val, ok.len, 0x04, &ckid) < 0 || der_find(ss1.val, ss1.len, 0x80, &txid) < 0) {
		say(a, LOG_ERR, "InitiateAuthentication response incomplete");
		goto out;
	}
	have_txid = true;
	if (der_find(ok.val, ok.len, 0x0C, &y) == 0 && y.len < sizeof(mid)) {
		memcpy(mid, y.val, y.len);
		mid[y.len] = 0;
	}

	/* ES10b.AuthenticateServer (SGP.22 5.7.13) */
	m = der_begin(&r, 0xBF38);
	db_put(&r, ss1.raw, ss1.raw_len);
	db_put(&r, sig1.raw, sig1.raw_len);
	db_put(&r, ckid.raw, ckid.raw_len);
	db_put(&r, cert.raw, cert.raw_len);
	if (der_find(ok.val, ok.len, 0xA2, &y) == 0) {
		db_put(&r, y.val, y.len);   /* the eIM built ctxParams1 */
	} else {
		k = der_begin(&r, 0xA0);   /* ctxParamsForCommonAuthentication */
		if (mid[0])
			der_put_str(&r, 0x80, mid);
		put_device_info(a, &r, 0xA1);
		der_end(&r, k);
	}
	der_end(&r, m);
	if (es10(a->c.eu, r.d, r.len, &ctx, &t) < 0)
		goto cancel;

	/* AuthenticateClientRequestEsipa */
	msg.len = 0;
	m = der_begin(&msg, 0xBF3B);
	der_put(&msg, 0x80, txid.val, txid.len);
	db_put(&msg, ctx.d, ctx.len);
	der_end(&msg, m);
	if (esipa_call(a, "AuthenticateClient", &msg, 0xBF3B, &resp, &t) < 0)
		goto cancel;
	if (der_find(t.val, t.len, 0xA0, &ok) < 0) {
		int64_t e = -1;

		if (der_find(t.val, t.len, 0x82, &y) == 0)
			der_get_int(&y, &e);
		say(a, LOG_ERR, "AuthenticateClient refused by the eIM: %lld (%s)", (long long)e, code_of(AC_ERR, e));
		reason = e == 50 ? 3 : 127;   /* pprNotAllowed(50) -> reason pprNotAllowed(3) */
		goto cancel;
	}

	/* ES10b.PrepareDownload: 30 smdpSigned2, 5F37, 04 hashCc?, 30 cert */
	{
		der_tlv ss2 = { 0 }, cert2 = { 0 }, sig2, hcc;

		for (p = ok.val, end = ok.val + ok.len; p < end && der_next(&p, end, &y) == 0; ) {
			if (y.tag == 0x30 && !ss2.raw)
				ss2 = y;
			else if (y.tag == 0x30)
				cert2 = y;
		}
		if (!ss2.raw || !cert2.raw || der_find(ok.val, ok.len, 0x5F37, &sig2) < 0)
			goto cancel;
		r.len = 0;
		m = der_begin(&r, 0xBF21);
		db_put(&r, ss2.raw, ss2.raw_len);
		db_put(&r, sig2.raw, sig2.raw_len);
		if (der_find(ok.val, ok.len, 0x04, &hcc) == 0)
			db_put(&r, hcc.raw, hcc.raw_len);
		db_put(&r, cert2.raw, cert2.raw_len);
		der_end(&r, m);
	}
	if (es10(a->c.eu, r.d, r.len, &ctx, &t) < 0)
		goto cancel;

	/* GetBoundProfilePackageRequestEsipa; an error PrepareDownloadResponse
	 * is forwarded too, the SM-DP+ ends the session on it */
	msg.len = 0;
	m = der_begin(&msg, 0xBF3A);
	der_put(&msg, 0x80, txid.val, txid.len);
	db_put(&msg, ctx.d, ctx.len);
	der_end(&msg, m);
	if (esipa_call(a, "GetBoundProfilePackage", &msg, 0xBF3A, &resp, &t) < 0)
		goto cancel;
	if (der_find(t.val, t.len, 0xA0, &ok) < 0 || der_find(ok.val, ok.len, 0xBF36, &x) < 0) {
		int64_t e = -1;

		if (der_find(t.val, t.len, 0x81, &y) == 0)
			der_get_int(&y, &e);
		say(a, LOG_ERR, "GetBoundProfilePackage refused by the eIM: %lld (%s)", (long long)e, code_of(GBPP_ERR, e));
		reason = e == 50 ? 4 : 127;   /* metadataMismatch */
		goto cancel;
	}
	if (load_bpp(a, &x, &pir) < 0 || !pir.len) {
		reason = 5;   /* loadBppExecutionError: no PIR to report (step 20) */
		goto cancel;
	}
	say(a, LOG_NOTICE, "profile package loaded");
	rc = 0;
	goto out;

cancel:
	if (have_txid)
		cancel_session(a, &txid, reason);
out:
	db_free(&msg);
	db_free(&resp);
	db_free(&r);
	db_free(&info1);
	db_free(&chal);
	db_free(&ctx);
	db_free(&pir);
	return rc;
}

/* the newest Profile Installation Result on the card, seq > after */
static int newest_pir(ipa *a, int64_t after, dbuf *out, int64_t *seq)
{
	dbuf r;
	der_tlv t, list, n;
	const uint8_t *p, *end;
	int64_t best = after, s;

	db_init(&r);
	out->len = 0;
	if (retrieve(a, NULL, 0, &r, &t) == 0 && der_find(t.val, t.len, 0xA0, &list) == 0)
		for (p = list.val, end = list.val + list.len; p < end && der_next(&p, end, &n) == 0; )
			if (n.tag == 0xBF37 && notif_seq(&n, &s) == 0 && s > best) {
				best = s;
				out->len = 0;
				db_put(out, n.raw, n.raw_len);
			}
	db_free(&r);
	if (seq)
		*seq = best;
	return out->len ? 0 : -1;
}

static int handle_download(ipa *a, const der_tlv *req, ipa_summary *sum)
{
	der_tlv data, alt, txid;
	bool has_txid = der_find(req->val, req->len, 0x82, &txid) == 0;
	char ac[256] = "";
	int rc;

	sum->downloads++;
	if (der_find(req->val, req->len, 0xA0, &data) == 0 && der_parse(data.val, data.len, &alt) == 0 &&
	    alt.tag == 0x80) {
		if (alt.len >= sizeof(ac)) {
			say(a, LOG_ERR, "activation code too long");
			return -1;
		}
		memcpy(ac, alt.val, alt.len);
		ac[alt.len] = 0;
	}

	if (ac[0] && a->c.host.download) {
		/* 3.2.3.1 through the host; step 13: the result goes back as
		 * ProfileDownloadTriggerResult in a HandleNotification */
		dbuf pir, res;
		int64_t mark = -1, seq;
		size_t m, k;

		db_init(&pir);
		db_init(&res);
		newest_pir(a, -1, &pir, &mark);
		/* the host's ES9+ client (lpac) talks to the ISD-R itself while we
		 * wait, over the one channel the bridge relays: give ours back;
		 * card_es10 reopens it afterwards */
		card_close(a->c.eu->card);
		rc = a->c.host.download(a->c.host.ud, ac, NULL);
		a->nl_ok = false;
		m = der_begin(&res, 0xBF54);
		if (has_txid)
			der_put(&res, 0x82, txid.val, txid.len);
		if (newest_pir(a, mark, &pir, &seq) == 0) {
			db_put(&res, pir.d, pir.len);
			/* owed to the SM-DP+ from here on, recorded before anything
			 * else can fail (step 14 below) */
			if (a->c.host.notify)
				es9_set(a, seq, true);
		} else {
			k = der_begin(&res, 0x30);   /* profileDownloadError */
			der_put_int(&res, 0x80, 127);
			der_end(&res, k);
			if (rc == 0)
				rc = -1;
		}
		der_end(&res, m);
		say(a, rc == 0 ? LOG_NOTICE : LOG_ERR, "direct download %s", rc == 0 ? "done" : "failed");
		provide(a, res.d, res.len, true);
		/* step 14: the PIR to the SM-DP+ over ES9+ (SGP.22 3.1.3.3 step 7).
		 * A PIR of a failed install goes too: it tells the SM-DP+ the
		 * order ended in 'Error' (SGP.22 3.1.3.3 step 8). */
		if (pir.len && a->c.host.notify)
			es9_deliver(a, seq);
		db_free(&pir);
		db_free(&res);
		return rc;
	}

	/* no data, contactDefaultSmdp or contactSmds: the eIM knows the server */
	rc = indirect_download(a, ac[0] ? ac : NULL, has_txid ? &txid : NULL);
	if (rc < 0) {
		dbuf res;
		size_t m, k;

		db_init(&res);
		m = der_begin(&res, 0xBF54);
		if (has_txid)
			der_put(&res, 0x82, txid.val, txid.len);
		k = der_begin(&res, 0x30);
		der_put_int(&res, 0x80, 127);
		der_end(&res, k);
		der_end(&res, m);
		provide(a, res.d, res.len, true);
		db_free(&res);
	}
	return rc;
}

/* ---- the poll (3.1.1.1) ---- */

int ipa_poll(ipa *a, ipa_summary *sum)
{
	ipa_summary dummy;
	dbuf msg, resp;
	der_tlv t, alt;
	int i, max = a->c.max_packages > 0 ? a->c.max_packages : 16, rc = 0;
	size_t m;

	if (!sum)
		sum = &dummy;
	memset(sum, 0, sizeof(*sum));
	a->nl_ok = false;   /* read afresh once per poll */
	db_init(&msg);
	db_init(&resp);

	for (i = 0; i < max; i++) {
		msg.len = 0;
		m = der_begin(&msg, 0xBF4F);
		der_put(&msg, 0x5A, a->eid, 16);
		if (a->cause >= 0) {
			der_put_null(&msg, 0x80);
			der_put_int(&msg, 0x81, a->cause);
		}
		if (a->c.has_rplmn)
			der_put(&msg, 0x82, a->c.rplmn, 3);
		der_end(&msg, m);

		if (esipa_call(a, "GetEimPackage", &msg, 0xBF4F, &resp, &t) < 0 || der_parse(t.val, t.len, &alt) < 0) {
			rc = -1;
			break;
		}
		a->cause = -1;   /* delivered */

		if (alt.tag == 0x02) {
			int64_t e = 0;

			der_get_int(&alt, &e);
			if (e != 1) {   /* noEimPackageAvailable */
				say(a, LOG_WARNING, "GetEimPackage: eimPackageError %lld (%s)", (long long)e, code_of(PKG_ERR, e));
				rc = -1;
			}
			break;
		}
		sum->packages++;
		switch (alt.tag) {
		case 0xBF51:
			handle_package(a, &alt, sum);
			a->nl_ok = false;   /* an enable, disable or delete notifies */
			break;
		case 0xBF52:
			handle_data(a, &alt, sum);
			break;
		case 0xBF54:
			handle_download(a, &alt, sum);
			a->nl_ok = false;   /* a new PIR */
			break;
		default: {
			/* eimPackageResultResponseError [0] { code unknownPackage } */
			dbuf e;
			size_t k;

			db_init(&e);
			k = der_begin(&e, 0xA0);
			der_put_int(&e, 0x02, 2);
			der_end(&e, k);
			provide(a, e.d, e.len, false);
			db_free(&e);
			break;
		}
		}
	}

	if (rc == 0)
		sum->notifications = ipa_deliver_notifications(a);
	db_free(&msg);
	db_free(&resp);
	return rc;
}

/* ---- connectivity (5.9.24) ---- */

int ipa_connectivity(ipa *a)
{
	char iccid[21];
	dbuf r;
	der_tlv t, ok, hp;
	conn_params cp;
	const conn_params *p = NULL;

	if (ipa_enabled_iccid(a->c.eu, iccid) < 0)
		return -1;
	db_init(&r);
	if (iccid[0] && es10_empty(a->c.eu, 0xBF5F, &r, &t) == 0 && der_find(t.val, t.len, 0xA0, &ok) == 0 &&
	    der_find(ok.val, ok.len, 0x81, &hp) == 0 && conn_parse(hp.val, hp.len, &cp) == 0)
		p = &cp;
	db_free(&r);
	if (a->c.host.connectivity)
		a->c.host.connectivity(a->c.host.ud, iccid, p, a->c.eu->kind == EUICC_EMU);
	return 0;
}

/* ---- set-up ---- */

int ipa_add_initial_eim(euicc *eu, const uint8_t *cfg, size_t len, char *err, size_t errlen)
{
	dbuf q, r;
	der_tlv c, t, x;
	size_t m, k;
	int rc = -1;

	db_init(&q);
	db_init(&r);
	if (der_parse(cfg, len, &c) < 0 || c.raw_len != len ||
	    (c.tag != 0x30 && c.tag != 0xBF57 && c.tag != 0xBF55)) {
		snprintf(err, errlen, "not an EimConfigurationData, AddInitialEimRequest or GetEimConfigurationDataResponse (DER)");
		goto out;
	}
	if (c.tag == 0xBF57) {
		db_put(&q, cfg, len);   /* already the request, as eimctl eim-config writes it */
	} else if (c.tag == 0xBF55) {
		/* GetEimConfigurationDataResponse: the same [0] SEQUENCE OF
		 * EimConfigurationData as the request carries, under another tag */
		if (der_find(c.val, c.len, 0xA0, &x) < 0) {
			snprintf(err, errlen, "GetEimConfigurationDataResponse without a list");
			goto out;
		}
		m = der_begin(&q, 0xBF57);
		db_put(&q, x.raw, x.raw_len);
		der_end(&q, m);
	} else {
		m = der_begin(&q, 0xBF57);
		k = der_begin(&q, 0xA0);
		db_put(&q, cfg, len);
		der_end(&q, k);
		der_end(&q, m);
	}
	if (es10(eu, q.d, q.len, &r, &t) < 0) {
		snprintf(err, errlen, "the eUICC did not answer AddInitialEim");
		goto out;
	}
	if (der_find(t.val, t.len, 0x81, &x) == 0) {
		int64_t e = 0;

		der_get_int(&x, &e);
		snprintf(err, errlen, "AddInitialEim refused: %lld%s", (long long)e,
		         e == 2 ? " (an eIM is already associated)" : "");
		goto out;
	}
	rc = 0;
out:
	db_free(&q);
	db_free(&r);
	return rc;
}

/* the eIM to talk to and how to trust it (EimConfigurationData, 5.9.18) */
static int pick_eim(ipa *a)
{
	dbuf r;
	der_tlv t, list, c, x, y;
	const uint8_t *p, *end;
	int rc = -1;
	bool tls_given;

	db_init(&r);
	if (es10_empty(a->c.eu, 0xBF55, &r, &t) < 0 || der_find(t.val, t.len, 0xA0, &list) < 0)
		goto out;
	for (p = list.val, end = list.val + list.len; p < end; ) {
		if (der_next(&p, end, &c) < 0 || der_find(c.val, c.len, 0x80, &x) < 0 || x.len >= sizeof(a->eim_id))
			break;
		if (a->c.eim_id ? (strlen(a->c.eim_id) != x.len || memcmp(a->c.eim_id, x.val, x.len))
		                : der_find(c.val, c.len, 0x81, &y) < 0)
			continue;
		memcpy(a->eim_id, x.val, x.len);
		a->eim_id[x.len] = 0;

		if (a->c.eim_url)
			snprintf(a->url, sizeof(a->url), "%s", a->c.eim_url);
		else if (der_find(c.val, c.len, 0x81, &y) == 0 && y.len < 256)
			snprintf(a->url, sizeof(a->url), "https://%.*s" DAP_URL_PATH, (int)y.len, (const char *)y.val);
		else
			break;

		/* trustedPublicKeyDataTls [6]: A0 key | A1 certificate of the
		 * eIM or of its CA; without it the system CAs decide */
		tls_given = der_find(c.val, c.len, 0xA6, &x) == 0;
		if (tls_given && der_parse(x.val, x.len, &y) < 0) {
			tls_unusable(a, "not one DER value");
		} else if (tls_given) {
			dbuf w;
			int is_ca = 0, n;

			db_init(&w);
			der_put(&w, 0x30, y.val, y.len);   /* back to the universal SEQUENCE */
			if (y.tag == 0xA0 && w.len <= sizeof(a->pin)) {
				memcpy(a->pin, w.d, w.len);
				a->c.tls.pin_spki = a->pin;
				a->c.tls.pin_spki_len = w.len;
			} else if (y.tag == 0xA1 &&
			           (n = crypto_cert_spki(w.d, w.len, a->pin, sizeof(a->pin), &is_ca)) > 0) {
				if (is_ca) {
					db_put(&a->ca, w.d, w.len);
					a->c.tls.ca_der = a->ca.d;
					a->c.tls.ca_der_len = a->ca.len;
				} else {
					a->c.tls.pin_spki = a->pin;
					a->c.tls.pin_spki_len = (size_t)n;
				}
			} else {
				tls_unusable(a, y.tag == 0xA0 ? "key too large" : y.tag == 0xA1 ? "certificate does not parse"
				                                                   : "neither a key nor a certificate");
			}
			db_free(&w);
		}
		rc = 0;
		break;
	}
out:
	db_free(&r);
	return rc;
}

ipa *ipa_open(const ipa_config *cfg)
{
	static const uint8_t geteid[] = { 0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A };
	ipa *a = calloc(1, sizeof(*a));
	dbuf r;
	der_tlv t, x;

	if (!a)
		return NULL;
	a->c = *cfg;
	a->cause = cfg->state_change_cause;
	es9_load(a);
	nbo_load(&a->nb, cfg->nbo_path);
	db_init(&a->ca);
	db_init(&a->nl);
	db_init(&r);
	if (es10(a->c.eu, geteid, sizeof(geteid), &r, &t) < 0 || der_find(t.val, t.len, 0x5A, &x) < 0 ||
	    x.len != 16) {
		say(a, LOG_ERR, "no EID from the eUICC");
		goto fail;
	}
	memcpy(a->eid, x.val, 16);
	if (pick_eim(a) < 0) {
		say(a, LOG_ERR, "no usable eIM configured on the eUICC");
		goto fail;
	}
	db_free(&r);
	return a;
fail:
	db_free(&r);
	ipa_close(a);
	return NULL;
}

void ipa_close(ipa *a)
{
	if (!a)
		return;
	db_free(&a->ca);
	db_free(&a->nl);
	free(a);
}

const uint8_t *ipa_eid(const ipa *a)
{
	return a->eid;
}

const char *ipa_url(const ipa *a)
{
	return a->url;
}

const char *ipa_eim_id(const ipa *a)
{
	return a->eim_id;
}

const http_tls *ipa_tls(const ipa *a)
{
	return &a->c.tls;
}
