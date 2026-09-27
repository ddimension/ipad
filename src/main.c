/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * ipad: an SGP.32 v1.3 IoT Profile Assistant. The card is reached through
 * the host over stdio (host.h), so the same binary runs under wwand's
 * esim_bridge on any modem wwand can send APDUs to.
 */
#define _POSIX_C_SOURCE 200809L
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <dirent.h>

#include <mbedtls/base64.h>
#include <mbedtls/platform_util.h>

#include "bundle.h"
#include "crypto.h"
#include "emu.h"
#include "euicc.h"
#include "hex.h"
#include "host.h"
#include "http.h"
#include "ipa.h"

#define IMPORT_FORMAT "eim-euicc-import/1"

/* exit codes: 0 done, 1 failed, 2 usage, 3 no eIM configured on the card
 * (provision first) — the one failure the host acts on by itself */
#define EXIT_NO_EIM 3

/* the binding a bundle leaves to the next poll (D-69) */
#define BIND_PENDING "bind.pending"
#define BIND_REFUSED_FILE "bind.refused"
#define BIND_DONE_FILE "bind.done"
#define BIND_AFTER_FILE "bind.after"   /* a 429's Retry-After: not before this time */
#define EXIT_BIND_REFUSED 4

static void usage(FILE *f)
{
	fprintf(f,
	        "usage: ipad [options] <command>\n"
	        "commands:\n"
	        "  poll               run the eIM's packages, deliver notifications,\n"
	        "                     report the connectivity parameters\n"
	        "  provision <file>   AddInitialEim: EimConfigurationData or the whole request\n"
	        "                     (DER or hex; eimctl eim-config writes the request),\n"
	        "                     or a provisioning bundle (" BUNDLE_FORMAT " JSON, D-69):\n"
	        "                     eIM configuration and device key, bound at the next poll;\n"
	        "                     the file is deleted once stored\n"
	        "  export <file>      the eIM import file for an emulated card (" IMPORT_FORMAT ")\n"
	        "  connectivity       report the enabled profile's connectivity parameters\n"
	        "  notify             deliver pending notifications only\n"
	        "  info               EID, backend, eIMs, device key (JSON on stdout)\n"
	        "  reset <EID>|all    emulation: forget that card's state (<EID>.state), or with\n"
	        "                     'all' every card's, the device key and the binding; no card\n"
	        "                     needed\n"
	        "options:\n"
	        "  -b auto|iot|emu    card backend (default auto: probe for SGP.32)\n"
	        "  -s <dir>           emulation state and device key (default /etc/wwand/ipa)\n"
	        "  -e <eimId>         the eIM to talk to (default: the first with an FQDN)\n"
	        "  -u <url>           eIM URL instead of https://<eimFqdn>/gsma/rsp2/asn1\n"
	        "  -c <file>          CA bundle when the eIM config pins nothing\n"
	        "  -k                 do not verify the eIM's TLS certificate (testing)\n"
	        "  -i <imei>          device IMEI (DeviceInfo; its first 8 digits are the TAC)\n"
	        "  -r <hex6>          rPLMN, TS 24.008 coding\n"
	        "  -C <n>             notify a state change with this cause on the next poll\n"
	        "  -D                 offer direct download (the host runs ES9+, and delivers\n"
	        "                     the download's PIR to the SM-DP+ over ES9+)\n"
	        "  -F                 emulation: every profile may be the fallback (not SGP.32)\n"
	        "  -v                 log to stderr too\n");
}

/* The file may be a bundle with a private key in clear (D-69): read in one
 * piece into one buffer, so no copy is left behind in a freed or grown
 * buffer, and the staging buffer is wiped. An eIM configuration or a bundle
 * is a few kB at most; anything past READ_MAX is not one of them. */
#define READ_MAX 65536

static int read_file(const char *path, dbuf *out)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	size_t n;

	if (!f)
		return -1;
	if (!(buf = malloc(READ_MAX + 1))) {
		fclose(f);
		return -1;
	}
	n = fread(buf, 1, READ_MAX + 1, f);
	fclose(f);
	if (n > 0 && n <= READ_MAX)
		db_put(out, buf, n);
	mbedtls_platform_zeroize(buf, n);
	free(buf);
	return n > 0 && n <= READ_MAX && !out->err ? 0 : -1;
}

/* DER as is; a hex dump (whitespace allowed) decoded */
static int der_or_hex(dbuf *d)
{
	dbuf h;
	size_t i;
	int n;

	if (d->len && (d->d[0] == 0x30 || d->d[0] == 0xBF))
		return 0;
	db_init(&h);
	for (i = 0; i < d->len; i++)
		if (!strchr(" \t\r\n", d->d[i]))
			db_put(&h, &d->d[i], 1);
	db_put(&h, "", 1);
	d->len = 0;
	if (h.len > 1) {
		uint8_t *b = malloc(h.len / 2 + 1);

		if (b && (n = hex_decode((const char *)h.d, b, h.len / 2)) > 0)
			db_put(d, b, (size_t)n);
		free(b);
	}
	db_free(&h);
	return d->len && (d->d[0] == 0x30 || d->d[0] == 0xBF) ? 0 : -1;
}

static void b64(FILE *f, const uint8_t *p, size_t n)
{
	size_t olen = 0;
	unsigned char *o = malloc(n * 4 / 3 + 8);

	if (o && mbedtls_base64_encode(o, n * 4 / 3 + 8, &olen, p, n) == 0)
		fwrite(o, 1, olen, f);
	free(o);
}

static int read_eid(card *c, uint8_t eid[16])
{
	static const uint8_t q[] = { 0xBF, 0x3E, 0x03, 0x5C, 0x01, 0x5A };
	dbuf r;
	der_tlv t, x;
	int rc = -1;

	db_init(&r);
	if (card_es10(c, q, sizeof(q), &r) == 0 && der_parse(r.d, r.len, &t) == 0 &&
	    der_find(t.val, t.len, 0x5A, &x) == 0 && x.len == 16) {
		memcpy(eid, x.val, 16);
		rc = 0;
	}
	db_free(&r);
	return rc;
}

static void mkdir_p(const char *dir)
{
	char p[512], *s;

	snprintf(p, sizeof(p), "%s", dir);
	for (s = p + 1; *s; s++)
		if (*s == '/') {
			*s = 0;
			mkdir(p, 0755);
			*s = '/';
		}
	mkdir(p, 0700);   /* the last one holds the key */
}

/* The state directory's lock, for as long as a key is looked for and
 * created: two first runs at once (the host's poll and an `export`) would
 * otherwise each generate a key, one would win the rename, and the other
 * could already have exported its public key. -1 when it cannot be taken;
 * the caller goes on unlocked (a read-only directory has nothing to race
 * over). */
static int lock_dir(const char *dir)
{
	int fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd >= 0 && flock(fd, LOCK_EX) != 0) {
		close(fd);
		fd = -1;
	}
	return fd;
}

static void unlock_dir(int fd)
{
	if (fd >= 0)
		close(fd);   /* releases the flock */
}

static crypto_key *device_key(const char *dir)
{
	char path[512];
	crypto_key *k;
	int lk;

	snprintf(path, sizeof(path), "%s/device.key", dir);
	lk = lock_dir(dir);
	/* looked for under the lock: a run that waited finds the key the
	 * other one created */
	if (access(path, F_OK) == 0) {
		if (!(k = crypto_key_load(path)))
			/* never replaced: a new key would orphan every eIM that
			 * imported the old one */
			syslog(LOG_ERR, "device key %s unreadable; not replacing it", path);
		unlock_dir(lk);
		return k;
	}
	if (!(k = crypto_key_generate()) || crypto_key_save(k, path) < 0) {
		syslog(LOG_ERR, "cannot create the device key %s", path);
		crypto_key_free(k);
		unlock_dir(lk);
		return NULL;
	}
	unlock_dir(lk);
	syslog(LOG_NOTICE, "created device key %s", path);
	return k;
}

static void fingerprint(const crypto_key *k, char out[65])
{
	uint8_t spki[256], h[32];
	int n = crypto_key_spki(k, spki, sizeof(spki));

	out[0] = 0;
	if (n > 0) {
		crypto_sha256(spki, (size_t)n, h);
		hex_encode(h, 32, out);
	}
}

/* The eim-euicc-import/1 file into a memory stream: what `export` writes to
 * a file and what the self-binding posts (D-69 takes the import file as it
 * is). One builder, so both sign the very same text. */
static int build_import(euicc *eu, crypto_key *key, const char *eim_id, const char *imei, bool direct,
                        const uint8_t eid[16], char **body, size_t *blen)
{
	char eidhex[33], ctr[24];
	uint8_t spki[256], sig[CRYPTO_SIG_LEN];
	int64_t counter = 0, token = 0;
	bool has_token = false;
	int n;
	dbuf proof, info1, caps, pk64;
	der_tlv t;
	FILE *f;
	size_t olen = 0;

	if (eu->kind != EUICC_EMU) {
		fprintf(stderr, "ipad: the import file is for emulated cards; an IoT eUICC signs with its own certificate\n");
		return 1;
	}
	hex_encode(eid, 16, eidhex);
	if ((n = crypto_key_spki(key, spki, sizeof(spki))) <= 0)
		return 1;
	emu_eim_state(eu->emu, eim_id, &counter, &has_token, &token);

	/* the proof signs the base64 TEXT of the key (eim-domain import.rs
	 * proof_input), so both sides sign the very same bytes */
	db_init(&pk64);
	{
		unsigned char o[400];

		if (mbedtls_base64_encode(o, sizeof(o), &olen, spki, (size_t)n) != 0)
			return 1;
		db_put(&pk64, o, olen);
	}
	db_init(&proof);
	db_put(&proof, IMPORT_FORMAT "\n", strlen(IMPORT_FORMAT) + 1);
	db_put(&proof, eidhex, 32);
	db_put(&proof, "\n", 1);
	db_put(&proof, pk64.d, pk64.len);
	snprintf(ctr, sizeof(ctr), "\n%lld\n", (long long)counter);
	db_put(&proof, ctr, strlen(ctr));
	if (proof.err || crypto_sign(key, proof.d, proof.len, sig) < 0)
		return 1;

	db_init(&info1);
	db_init(&caps);
	{
		static const uint8_t q[] = { 0xBF, 0x20, 0x00 };

		if (euicc_es10(eu, q, sizeof(q), &info1) < 0 || der_parse(info1.d, info1.len, &t) < 0 ||
		    t.tag != 0xBF20)
			info1.len = 0;
	}
	ipa_put_capabilities(&caps, 0x30, direct);

	if (!(f = open_memstream(body, blen)))
		return 1;
	fprintf(f, "{\"format\":\"" IMPORT_FORMAT "\",\"eid\":\"%s\",\"emulated\":true,\"ipa_public_key\":\"", eidhex);
	fwrite(pk64.d, 1, pk64.len, f);
	fprintf(f, "\",\"counter\":%lld", (long long)counter);
	if (has_token)
		fprintf(f, ",\"association_token\":%lld", (long long)token);
	if (info1.len) {
		fprintf(f, ",\"euicc_info1\":\"");
		b64(f, info1.d, info1.len);
		fputc('"', f);
	}
	fprintf(f, ",\"ipa_capabilities\":\"");
	b64(f, caps.d, caps.len);
	fputc('"', f);
	if (imei) {
		fprintf(f, ",\"device\":{\"imei\":");
		host_json_str(f, imei);
		fputc('}', f);
	}
	fprintf(f, ",\"proof\":\"");
	b64(f, sig, sizeof(sig));
	fprintf(f, "\"}\n");
	n = fclose(f);
	db_free(&pk64);
	db_free(&proof);
	db_free(&info1);
	db_free(&caps);
	return n == 0 ? 0 : 1;
}

/* where the self-binding stands (D-69), from the markers provision and poll
 * leave in the state directory */
static const char *bind_state(const char *dir)
{
	char p[512];

	snprintf(p, sizeof(p), "%s/" BIND_REFUSED_FILE, dir);
	if (access(p, F_OK) == 0)
		return "refused";
	snprintf(p, sizeof(p), "%s/" BIND_PENDING, dir);
	if (access(p, F_OK) == 0)
		return "pending";
	snprintf(p, sizeof(p), "%s/" BIND_DONE_FILE, dir);
	return access(p, F_OK) == 0 ? "done" : "none";
}

/* A bundle (D-69): the eIM configuration through AddInitialEim as usual; the
 * device key replaces the one ipad would generate, because the eIM issued it
 * and holds its public half; a marker leaves the binding to the next poll,
 * which reads the card's EID for it. The file is deleted once all of it is
 * stored: it holds the private key. */
static int provision_bundle(euicc *eu, const char *dir, const char *path, const dbuf *file,
                            char *err, size_t errlen)
{
	bundle b;
	crypto_key *k = NULL;
	time_t exp;
	char kpath[512], mpath[512], mtmp[520];
	FILE *f;
	int rc = 1;

	if (bundle_parse(file->d, file->len, &b, err, errlen) < 0)
		return 1;

	/* the eIM refuses an expired bundle at binding anyway; saying so here
	 * spares a configuration that can never bind. A clock that has not been
	 * set (before 2024) proves nothing either way. */
	if (rfc3339_time(b.expires_at, &exp) < 0) {
		snprintf(err, errlen, "bundle: expires_at is not RFC 3339");
		goto out;
	}
	if (time(NULL) > 1704067200 && time(NULL) >= exp) {
		snprintf(err, errlen, "bundle %s expired at %s", b.issuance_id, b.expires_at);
		goto out;
	}
	if (eu->kind == EUICC_EMU && !(k = crypto_key_parse(b.device_key.d, b.device_key.len))) {
		snprintf(err, errlen, "bundle %s: device_key is not a consistent P-256 private key", b.issuance_id);
		goto out;
	}

	/* configuration first: it is the step the card can refuse (one initial
	 * eIM, SGP.32 3.5.2) — a refused one must not leave a new key behind */
	if (ipa_add_initial_eim(eu, b.eim_config.d, b.eim_config.len, err, errlen) < 0)
		goto out;

	if (eu->kind == EUICC_EMU) {
		int lk, saved;

		snprintf(kpath, sizeof(kpath), "%s/device.key", dir);
		snprintf(mpath, sizeof(mpath), "%s/" BIND_PENDING, dir);
		snprintf(mtmp, sizeof(mtmp), "%s.tmp", mpath);
		lk = lock_dir(dir);
		saved = crypto_key_save(k, kpath);
		unlock_dir(lk);
		if (saved < 0) {
			snprintf(err, errlen, "cannot store the device key in %.150s", kpath);
			goto out;
		}
		if (!(f = fopen(mtmp, "w"))) {
			snprintf(err, errlen, "cannot write %.150s", mtmp);
			goto out;
		}
		fprintf(f, "%s\n%lld\n", b.issuance_id, b.counter);
		if (fclose(f) != 0 || rename(mtmp, mpath) != 0) {
			unlink(mtmp);
			snprintf(err, errlen, "cannot write %.150s", mpath);
			goto out;
		}
		/* an outcome of an earlier binding does not describe this one */
		snprintf(mtmp, sizeof(mtmp), "%s/" BIND_REFUSED_FILE, dir);
		unlink(mtmp);
		snprintf(mtmp, sizeof(mtmp), "%s/" BIND_DONE_FILE, dir);
		unlink(mtmp);
		snprintf(mtmp, sizeof(mtmp), "%s/" BIND_AFTER_FILE, dir);
		unlink(mtmp);
	} else {
		/* an IoT eUICC signs with its own certificate: the bundle's key has
		 * nothing to sign, and the card is registered by its EUM data */
		syslog(LOG_NOTICE, "bundle %s: IoT eUICC — its device key is not used, no self-binding", b.issuance_id);
	}

	if (unlink(path) != 0)
		syslog(LOG_WARNING, "bundle %s stored, but the file %s could not be deleted: delete it by hand", b.issuance_id, path);
	syslog(LOG_NOTICE, "bundle %s provisioned (counter %lld, valid until %s)%s", b.issuance_id, b.counter,
	       b.expires_at, eu->kind == EUICC_EMU ? "; the card binds itself on the next poll" : "");
	rc = 0;
out:
	crypto_key_free(k);
	bundle_free(&b);
	return rc;
}

/* The self-binding (D-69), before the first GetEimPackage: the import file of
 * the card now in hand, signed with the bundle key, POSTed to the eIM that
 * ESipa talks to, over the same TLS. 0 bound (or nothing to bind), 1 retry
 * later, EXIT_BIND_REFUSED when the eIM said no. */
static int bind_card(ipa *a, euicc *eu, crypto_key *key, const char *dir, const char *eim_id,
                     const char *imei, bool direct, const uint8_t eid[16],
                     void (*logf)(void *, int, const char *), void *lud)
{
	char mpath[512], rpath[512], apath[512], url[512], msg[300];
	static const char *const hdrs[] = { "Content-Type: application/json", NULL };
	char *body = NULL;
	size_t blen = 0;
	http_resp r;
	int rc = 1;

	snprintf(mpath, sizeof(mpath), "%s/" BIND_PENDING, dir);
	snprintf(rpath, sizeof(rpath), "%s/" BIND_REFUSED_FILE, dir);
	if (access(rpath, F_OK) == 0) {
		logf(lud, LOG_ERR, "the eIM refused to bind this card: not polling until an operator acts (a new bundle, or ipad reset all)");
		return EXIT_BIND_REFUSED;
	}
	if (eu->kind != EUICC_EMU || access(mpath, F_OK) != 0)
		return 0;
	/* RFC 6585 4 / RFC 9110 10.2.3: a 429 may say how long to wait. The
	 * host's poll backoff decides when ipad runs; until then each run
	 * leaves the eIM alone and ends as a retry. A time more than a day
	 * ahead means the clock went back since (routers set it late): it
	 * is dropped rather than obeyed. */
	snprintf(apath, sizeof(apath), "%s/" BIND_AFTER_FILE, dir);
	{
		FILE *m = fopen(apath, "r");
		long long after = 0;
		time_t now = time(NULL);

		if (m) {
			if (fscanf(m, "%lld", &after) != 1)
				after = 0;
			fclose(m);
			if (after > (long long)now && after - (long long)now <= HTTP_MAX_RETRY_AFTER) {
				snprintf(msg, sizeof(msg), "binding deferred: the eIM asked to wait %lld s more (Retry-After)",
				         after - (long long)now);
				logf(lud, LOG_WARNING, msg);
				return 1;
			}
			unlink(apath);
		}
	}
	if (bind_url(ipa_url(a), url, sizeof(url)) < 0) {
		logf(lud, LOG_ERR, "no eIM URL to bind at");
		return 1;
	}
	/* D-69: the eIM binds only at the bundle's start counter. The emulation
	 * holds it from AddInitialEim and nothing can have moved it before the
	 * binding; if it did (state edited, another configuration), the eIM would
	 * answer 403 and the card would stop polling for good — said here
	 * instead, with the bundle still pending. */
	{
		FILE *m = fopen(mpath, "r");
		char idl[80];
		long long want = -1;
		int64_t have = -1, tok = 0;
		bool ht = false;

		if (!m || !fgets(idl, sizeof(idl), m) || fscanf(m, "%lld", &want) != 1)
			want = -1;
		if (m)
			fclose(m);
		emu_eim_state(eu->emu, eim_id, &have, &ht, &tok);
		if (want < 0 || have != want) {
			snprintf(msg, sizeof(msg), "not binding: the emulation's counter %lld is not the bundle's %lld",
			         (long long)have, want);
			logf(lud, LOG_ERR, msg);
			return 1;
		}
	}
	if (build_import(eu, key, eim_id, imei, direct, eid, &body, &blen) != 0) {
		free(body);
		return 1;
	}

	memset(&r, 0, sizeof(r));
	db_init(&r.body);
	if (http_post(url, hdrs, (const uint8_t *)body, blen, ipa_tls(a), &r) < 0)
		r.status = 0;

	switch (bind_outcome_of(r.status)) {
	case BIND_DONE: {
		char dpath[512];

		/* kept, with the issuance id: `info` tells a bound card from one
		 * that never had a bundle */
		snprintf(dpath, sizeof(dpath), "%s/" BIND_DONE_FILE, dir);
		rename(mpath, dpath);
		snprintf(msg, sizeof(msg), "card bound at the eIM (%s)", r.status == 409 ? "409: already registered" : "204");
		logf(lud, LOG_NOTICE, msg);
		rc = 0;
		break;
	}
	case BIND_REFUSED:
		rename(mpath, rpath);
		logf(lud, LOG_ERR, "the eIM refused the binding (403): not polling until an operator acts");
		rc = EXIT_BIND_REFUSED;
		break;
	case BIND_RETRY:
		if (r.status == 429 && r.retry_after > 0) {
			FILE *m = fopen(apath, "w");

			if (m) {
				fprintf(m, "%lld\n", (long long)time(NULL) + r.retry_after);
				fclose(m);
			}
			snprintf(msg, sizeof(msg), "binding not done (429 rate limited): again after %ld s (Retry-After)",
			         r.retry_after);
		} else {
			snprintf(msg, sizeof(msg), "binding not done (%s): again on the next poll",
			         r.status ? (r.status == 429 ? "429 rate limited" : "server error")
			                  : (r.error[0] ? r.error : "no answer"));
		}
		logf(lud, LOG_WARNING, msg);
		break;
	case BIND_BAD:
		snprintf(msg, sizeof(msg), "the eIM rejected the binding request (HTTP %d)", r.status);
		logf(lud, LOG_ERR, msg);
		break;
	}
	db_free(&r.body);
	free(body);
	return rc;
}

/* `reset <EID>`: the emulation forgets that card's eIM configuration and
 * state (its <EID>.state), and nothing else: the device key and the binding
 * belong to the state directory, which every card on the router shares, and
 * removing them would leave the other cards' results unverifiable at the eIM.
 * `reset all`: every .state, the device key and the binding, so that a fresh
 * bundle or a re-key starts from nothing; that is spelt out, not the default,
 * because it re-keys every card in the directory at once.
 * Needs no card. An IoT eUICC keeps its configuration on the card itself;
 * removing that is an eIM's eCO (deleteEim), not ours.
 * 0 done (nothing to remove is done too), 2 an argument that is neither. */
static int cmd_reset(const char *dir, const char *which)
{
	static const char *const fixed[] = { "device.key", BIND_PENDING, BIND_REFUSED_FILE, BIND_DONE_FILE,
	                                     BIND_AFTER_FILE };
	char p[768];
	DIR *d;
	struct dirent *e;
	size_t i, l;
	int n = 0;

	if (!which) {
		fprintf(stderr, "ipad: reset wants the card's EID (32 hex digits), or 'all' for every card, "
		                "the device key and the binding\n");
		return 2;
	}
	if (strcmp(which, "all")) {
		char eidhex[33];

		if (strlen(which) != 32 || strspn(which, "0123456789abcdefABCDEF") != 32) {
			fprintf(stderr, "ipad: reset: '%s' is neither an EID (32 hex digits) nor 'all'\n", which);
			return 2;
		}
		/* named as emu_open names it: hex_encode's upper case */
		for (i = 0; i < 32; i++)
			eidhex[i] = (char)toupper((unsigned char)which[i]);
		eidhex[32] = 0;
		snprintf(p, sizeof(p), "%s/%s.state", dir, eidhex);
		if (unlink(p) == 0)
			n++;
		syslog(LOG_NOTICE, "reset: card %s: %d file(s) removed from %s", eidhex, n, dir);
		return 0;
	}

	for (i = 0; i < sizeof(fixed) / sizeof(fixed[0]); i++) {
		snprintf(p, sizeof(p), "%s/%s", dir, fixed[i]);
		if (unlink(p) == 0)
			n++;
	}
	if ((d = opendir(dir))) {
		while ((e = readdir(d))) {
			l = strlen(e->d_name);
			if (l > 6 && !strcmp(e->d_name + l - 6, ".state")) {
				snprintf(p, sizeof(p), "%s/%s", dir, e->d_name);
				if (unlink(p) == 0)
					n++;
			}
		}
		closedir(d);
	}
	syslog(LOG_NOTICE, "reset: all cards: %d file(s) removed from %s", n, dir);
	return 0;
}

static int cmd_export(euicc *eu, crypto_key *key, const char *eim_id, const char *imei, bool direct,
                      const uint8_t eid[16], const char *path)
{
	char *body = NULL, tmp[520], eidhex[33];
	size_t blen = 0;
	FILE *f;
	int rc = 1;

	if (build_import(eu, key, eim_id, imei, direct, eid, &body, &blen) != 0) {
		free(body);
		return 1;
	}
	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (!(f = fopen(tmp, "w"))) {
		fprintf(stderr, "ipad: %s: %s\n", tmp, strerror(errno));
	} else if (fwrite(body, 1, blen, f) != blen || fclose(f) != 0 || rename(tmp, path) != 0) {
		fprintf(stderr, "ipad: %s: %s\n", path, strerror(errno));
		unlink(tmp);
	} else {
		hex_encode(eid, 16, eidhex);
		syslog(LOG_NOTICE, "import file for EID %s written to %s", eidhex, path);
		rc = 0;
	}
	free(body);
	return rc;
}

/* Everything the card says is collected first: stdout is also the APDU
 * channel, and a line printed in pieces around card calls would come out
 * interleaved with them. */
/* the emulation's counter for the eIM, -1 when not emulated or no eIM */
static long long emu_counter(euicc *eu, const char *eim_id)
{
	int64_t ctr = 0, tok = 0;
	bool ht = false;

	if (eu->kind != EUICC_EMU || emu_eim_state(eu->emu, eim_id, &ctr, &ht, &tok) != 0)
		return -1;
	return (long long)ctr;
}

static void cmd_info(euicc *eu, const crypto_key *key, const uint8_t eid[16], const char *dir, FILE *out)
{
	long long counter = emu_counter(eu, NULL);
	static const uint8_t q[] = { 0xBF, 0x55, 0x00 };
	char eidhex[33], iccid[21], fp[65];
	dbuf r;
	der_tlv t, list, c, x;
	const uint8_t *p, *end;
	bool first = true, have_iccid;
	char *body = NULL;
	size_t blen = 0;
	FILE *m;

	have_iccid = ipa_enabled_iccid(eu, iccid) == 0;
	db_init(&r);
	if (euicc_es10(eu, q, sizeof(q), &r) < 0)
		r.len = 0;

	if (!(m = open_memstream(&body, &blen)))
		return;
	hex_encode(eid, 16, eidhex);
	fprintf(m, "{\"type\":\"info\",\"payload\":{\"eid\":\"%s\",\"backend\":\"%s\"", eidhex,
	        eu->kind == EUICC_EMU ? "emulated" : "iot");
	if (key) {
		fingerprint(key, fp);
		fprintf(m, ",\"key_fingerprint\":\"%s\"", fp);
	}
	if (have_iccid)
		fprintf(m, ",\"iccid\":\"%s\"", iccid);
	if (eu->kind == EUICC_EMU) {
		fprintf(m, ",\"bind\":\"%s\"", bind_state(dir));
		if (counter >= 0)
			fprintf(m, ",\"counter\":%lld", counter);
	}
	fprintf(m, ",\"eims\":[");
	if (r.len && der_parse(r.d, r.len, &t) == 0 && der_find(t.val, t.len, 0xA0, &list) == 0)
		for (p = list.val, end = list.val + list.len; p < end && der_next(&p, end, &c) == 0; ) {
			char s[260];

			fprintf(m, "%s{", first ? "" : ",");
			first = false;
			if (der_find(c.val, c.len, 0x80, &x) == 0 && x.len < sizeof(s)) {
				memcpy(s, x.val, x.len);
				s[x.len] = 0;
				fprintf(m, "\"id\":");
				host_json_str(m, s);
			}
			if (der_find(c.val, c.len, 0x81, &x) == 0 && x.len < sizeof(s)) {
				memcpy(s, x.val, x.len);
				s[x.len] = 0;
				fprintf(m, ",\"fqdn\":");
				host_json_str(m, s);
			}
			/* trustedPublicKeyDataTls [6] (SGP.32 2.11.1.1.1): the eIM's
			 * key [0] or a certificate [1] (the eIM's or its CA, D-70);
			 * without it the system CAs decide */
			{
				der_tlv y;
				const char *tls = "system";

				if (der_find(c.val, c.len, 0xA6, &x) == 0)
					tls = der_parse(x.val, x.len, &y) < 0 ? "configuration"
					    : y.tag == 0xA1 ? "certificate" : y.tag == 0xA0 ? "key" : "configuration";
				fprintf(m, ",\"tls\":\"%s\"}", tls);
			}
		}
	fprintf(m, "]}}\n");
	fclose(m);
	fputs(body, out);
	fflush(out);
	free(body);
	db_free(&r);
}

/* any eIM configuration at all on the card (or in the emulation) */
static bool has_eim(euicc *eu)
{
	static const uint8_t q[] = { 0xBF, 0x55, 0x00 };
	dbuf r;
	der_tlv t, list;
	bool any = false;

	db_init(&r);
	if (euicc_es10(eu, q, sizeof(q), &r) == 0 && der_parse(r.d, r.len, &t) == 0 &&
	    der_find(t.val, t.len, 0xA0, &list) == 0)
		any = list.len > 0;
	db_free(&r);
	return any;
}

static void result_line(FILE *out, int code, const char *what, const ipa_summary *s)
{
	fprintf(out, "{\"type\":\"lpa\",\"payload\":{\"code\":%d,\"message\":\"%s\"", code, what);
	if (s)
		fprintf(out, ",\"data\":\"packages=%d acknowledged=%d downloads=%d notifications=%d changed=%d rolled_back=%d\"",
		        s->packages, s->acknowledged, s->downloads, s->notifications, s->profile_changed,
		        s->rolled_back);
	fprintf(out, "}}\n");
	fflush(out);
}

int main(int argc, char **argv)
{
	const char *backend = "auto", *dir = "/etc/wwand/ipa", *imei = NULL, *cmd;
	ipa_config cfg;
	host_link hl;
	card c;
	euicc eu;
	emu *em = NULL;
	crypto_key *key = NULL;
	uint8_t eid[16];
	char state[600];   /* function scope: the emulation opened below uses it until the end */
	char es9[600];     /* the same for ipa_config.es9_path */
	int opt, verbose = 0, rc = 1, fallback_all = 0;
	bool direct = false;

	memset(&cfg, 0, sizeof(cfg));
	cfg.state_change_cause = -1;

	while ((opt = getopt(argc, argv, "b:s:e:u:c:ki:r:C:DFvh")) != -1) {
		switch (opt) {
		case 'b': backend = optarg; break;
		case 's': dir = optarg; break;
		case 'e': cfg.eim_id = optarg; break;
		case 'u': cfg.eim_url = optarg; break;
		case 'c': cfg.tls.ca_file = optarg; break;
		case 'k': cfg.tls.insecure = true; break;
		case 'i': imei = optarg; break;
		case 'r':
			if (strlen(optarg) != 6 || hex_decode(optarg, cfg.rplmn, 3) != 3) {
				fprintf(stderr, "ipad: -r wants 6 hex digits\n");
				return 2;
			}
			cfg.has_rplmn = true;
			break;
		case 'C': cfg.state_change_cause = atoi(optarg); break;
		case 'D': direct = true; break;
		case 'F': fallback_all = 1; break;
		case 'v': verbose = 1; break;
		case 'h': usage(stdout); return 0;
		default: usage(stderr); return 2;
		}
	}
	if (optind >= argc) {
		usage(stderr);
		return 2;
	}
	cmd = argv[optind];

	/* TAC and IMEI for DeviceInfo (SGP.22 4.2): the TAC is the IMEI's first
	 * 8 digits, both BCD as the 3GPP identities are */
	if (imei) {
		size_t l = strlen(imei), i;
		char pad[17];

		if (l < 14 || l > 16 || strspn(imei, "0123456789") != l) {
			fprintf(stderr, "ipad: -i wants a 14..16 digit IMEI\n");
			return 2;
		}
		for (i = 0; i < 4; i++)
			cfg.tac[i] = (uint8_t)((imei[2 * i] - '0') << 4 | (imei[2 * i + 1] - '0'));
		snprintf(pad, sizeof(pad), "%-16s", imei);
		for (i = 0; i < 8; i++) {
			uint8_t lo = (uint8_t)(pad[2 * i] - '0'), hi = pad[2 * i + 1] == ' ' ? 0xF : (uint8_t)(pad[2 * i + 1] - '0');

			cfg.imei[i] = (uint8_t)(hi << 4 | lo);   /* TS 24.008 order: nibble-swapped */
		}
		cfg.has_imei = true;
	}

	openlog("ipad", LOG_PID, LOG_DAEMON);

	if (!strcmp(cmd, "reset")) {
		rc = cmd_reset(dir, optind + 1 < argc ? argv[optind + 1] : NULL);
		result_line(stdout, rc, "reset", NULL);
		closelog();
		return rc;
	}
	host_init(&hl, stdin, stdout);
	card_init(&c, &HOST_CARD_OPS, &hl);
	memset(&eu, 0, sizeof(eu));
	eu.card = &c;
	host_ipa_hooks(&hl, &cfg.host, verbose);
	if (!direct) {
		cfg.host.download = NULL;
		cfg.host.notify = NULL;
	}
	cfg.eu = &eu;

	if (read_eid(&c, eid) < 0) {
		cfg.host.log(&hl, LOG_ERR, "no EID: the card does not answer the ISD-R");
		goto out;
	}
	if (direct) {
		char eidhex[33];

		hex_encode(eid, 16, eidhex);
		mkdir_p(dir);
		snprintf(es9, sizeof(es9), "%s/%s.es9", dir, eidhex);
		cfg.es9_path = es9;
	}

	if (!strcmp(backend, "iot"))
		eu.kind = EUICC_IOT;
	else if (!strcmp(backend, "emu"))
		eu.kind = EUICC_EMU;
	else
		eu.kind = euicc_probe(&c);

	if (eu.kind == EUICC_EMU) {
		char eidhex[33];
		emu_config ec;

		hex_encode(eid, 16, eidhex);
		mkdir_p(dir);
		if (!(key = device_key(dir)))
			goto out;
		snprintf(state, sizeof(state), "%s/%s.state", dir, eidhex);
		memset(&ec, 0, sizeof(ec));
		ec.state_path = state;
		ec.key = key;
		ec.fallback_allowed = fallback_all;
		if (!(em = emu_open(&c, &ec))) {
			cfg.host.log(&hl, LOG_ERR, "emulation state unusable (written for another card?)");
			goto out;
		}
		eu.emu = em;
	}

	if (!strcmp(cmd, "info")) {
		char eidhex[33], fp[65];

		/* the event for a host that reads events only (wwand's bridge logs
		 * the JSON line below), the line for everyone else */
		hex_encode(eid, 16, eidhex);
		if (key)
			fingerprint(key, fp);
		host_event_info(&hl, eidhex, eu.kind == EUICC_EMU ? "emulated" : "iot", key ? fp : NULL,
		                eu.kind == EUICC_EMU ? bind_state(dir) : NULL, emu_counter(&eu, NULL));
		cmd_info(&eu, key, eid, dir, stdout);
		rc = 0;
	} else if (!strcmp(cmd, "provision")) {
		dbuf f;
		char err[200];

		db_init(&f);
		if (optind + 1 < argc && read_file(argv[optind + 1], &f) == 0 && bundle_is(f.d, f.len)) {
			if ((rc = provision_bundle(&eu, dir, argv[optind + 1], &f, err, sizeof(err))) != 0)
				cfg.host.log(&hl, LOG_ERR, err);
			else
				cfg.host.log(&hl, LOG_NOTICE, "eIM configuration and device key stored from the bundle");
			/* the file held the private key: nothing of it stays in memory */
			mbedtls_platform_zeroize(f.d, f.len);
		} else if (optind + 1 >= argc || f.err || der_or_hex(&f) < 0) {
			snprintf(hl.last_error, sizeof(hl.last_error), "provision needs a readable EimConfigurationData file or bundle");
			fprintf(stderr, "ipad: %s\n", hl.last_error);
			rc = 2;
		} else if (ipa_add_initial_eim(&eu, f.d, f.len, err, sizeof(err)) < 0) {
			cfg.host.log(&hl, LOG_ERR, err);
		} else {
			cfg.host.log(&hl, LOG_NOTICE, "eIM configuration stored");
			rc = 0;
		}
		db_free(&f);
		/* the card as it is now: a bundle has just replaced the device key
		 * loaded above, so its fingerprint is read back from the file */
		if (rc == 0) {
			char eidhex[33], fp[65], kp[512];
			crypto_key *nk = NULL;

			hex_encode(eid, 16, eidhex);
			if (eu.kind == EUICC_EMU) {
				snprintf(kp, sizeof(kp), "%s/device.key", dir);
				if ((nk = crypto_key_load(kp)))
					fingerprint(nk, fp);
			}
			host_event_info(&hl, eidhex, eu.kind == EUICC_EMU ? "emulated" : "iot", nk ? fp : NULL,
			                eu.kind == EUICC_EMU ? bind_state(dir) : NULL, emu_counter(&eu, NULL));
			crypto_key_free(nk);
		}
		host_event_summary(&hl, "provision", rc, NULL, eu.kind == EUICC_EMU ? bind_state(dir) : NULL);
		result_line(stdout, rc, "provision", NULL);
	} else if (!strcmp(cmd, "export")) {
		if (optind + 1 >= argc) {
			usage(stderr);
			rc = 2;
		} else {
			rc = cmd_export(&eu, key, cfg.eim_id, imei, direct, eid, argv[optind + 1]);
		}
		result_line(stdout, rc, "export", NULL);
	} else if (!strcmp(cmd, "poll") || !strcmp(cmd, "notify") || !strcmp(cmd, "connectivity")) {
		ipa *a = ipa_open(&cfg);
		ipa_summary s;
		char eidhex[33], fp[65];

		memset(&s, 0, sizeof(s));
		hex_encode(eid, 16, eidhex);
		if (key)
			fingerprint(key, fp);
		host_event_info(&hl, eidhex, eu.kind == EUICC_EMU ? "emulated" : "iot", key ? fp : NULL,
		                eu.kind == EUICC_EMU ? bind_state(dir) : NULL, emu_counter(&eu, cfg.eim_id));
		if (!a) {
			rc = has_eim(&eu) ? 1 : EXIT_NO_EIM;
			if (!strcmp(cmd, "poll"))
				host_event_summary(&hl, cmd, rc, NULL, eu.kind == EUICC_EMU ? bind_state(dir) : NULL);
			result_line(stdout, rc, rc == EXIT_NO_EIM ? "no eIM configured" : cmd, NULL);
			goto out;
		}
		if (!strcmp(cmd, "poll")) {
			/* bound first: the eIM knows nothing of the card before; with
			 * the eIM ipa_open picked, whose counter is the one bound */
			rc = bind_card(a, &eu, key, dir, ipa_eim_id(a), imei, direct, eid, cfg.host.log, &hl);
			if (rc != 0) {
				host_event_summary(&hl, cmd, rc, NULL, bind_state(dir));
				result_line(stdout, rc, rc == EXIT_BIND_REFUSED ? "bind refused" : "bind", NULL);
				ipa_close(a);
				goto out;
			}
			rc = ipa_poll(a, &s) < 0;
			/* the enabled profile's parameters after every poll, not only
			 * after a change: the host's copy may be gone (a config reset),
			 * and applying the same values again changes nothing */
			ipa_connectivity(a);
			host_event_summary(&hl, cmd, rc, &s, eu.kind == EUICC_EMU ? bind_state(dir) : NULL);
		} else if (!strcmp(cmd, "notify")) {
			s.notifications = ipa_deliver_notifications(a);
			rc = 0;
		} else {
			rc = ipa_connectivity(a) < 0;
		}
		result_line(stdout, rc, cmd, &s);
		ipa_close(a);
	} else {
		usage(stderr);
		rc = 2;
	}

out:
	emu_close(em);
	crypto_key_free(key);
	card_close(&c);
	host_free(&hl);
	closelog();
	return rc;
}
