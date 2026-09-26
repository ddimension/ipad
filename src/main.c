/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * ipad: an SGP.32 v1.3 IoT Profile Assistant. The card is reached through
 * the host over stdio (host.h), so the same binary runs under wwand's
 * esim_bridge on any modem wwand can send APDUs to.
 */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>

#include <mbedtls/base64.h>

#include "crypto.h"
#include "emu.h"
#include "euicc.h"
#include "hex.h"
#include "host.h"
#include "ipa.h"

#define IMPORT_FORMAT "eim-euicc-import/1"

/* exit codes: 0 done, 1 failed, 2 usage, 3 no eIM configured on the card
 * (provision first) — the one failure the host acts on by itself */
#define EXIT_NO_EIM 3

static void usage(FILE *f)
{
	fprintf(f,
	        "usage: ipad [options] <command>\n"
	        "commands:\n"
	        "  poll               run the eIM's packages, deliver notifications,\n"
	        "                     report the connectivity parameters\n"
	        "  provision <file>   AddInitialEim: EimConfigurationData or the whole request\n"
	        "                     (DER or hex; eimctl eim-config writes the request)\n"
	        "  export <file>      the eIM import file for an emulated card (" IMPORT_FORMAT ")\n"
	        "  connectivity       report the enabled profile's connectivity parameters\n"
	        "  notify             deliver pending notifications only\n"
	        "  info               EID, backend, eIMs, device key (JSON on stdout)\n"
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
	        "  -D                 offer direct download (the host runs ES9+)\n"
	        "  -F                 emulation: every profile may be the fallback (not SGP.32)\n"
	        "  -v                 log to stderr too\n");
}

static int read_file(const char *path, dbuf *out)
{
	FILE *f = fopen(path, "rb");
	uint8_t buf[4096];
	size_t n;

	if (!f)
		return -1;
	while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
		db_put(out, buf, n);
	fclose(f);
	return out->err ? -1 : 0;
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

static crypto_key *device_key(const char *dir)
{
	char path[512];
	crypto_key *k;

	snprintf(path, sizeof(path), "%s/device.key", dir);
	if (access(path, F_OK) == 0) {
		if (!(k = crypto_key_load(path)))
			/* never replaced: a new key would orphan every eIM that
			 * imported the old one */
			syslog(LOG_ERR, "device key %s unreadable; not replacing it", path);
		return k;
	}
	if (!(k = crypto_key_generate()) || crypto_key_save(k, path) < 0) {
		syslog(LOG_ERR, "cannot create the device key %s", path);
		crypto_key_free(k);
		return NULL;
	}
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

static int cmd_export(euicc *eu, crypto_key *key, const char *eim_id, const char *imei, bool direct,
                      const uint8_t eid[16], const char *path)
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
	char tmp[520];

	if (eu->kind != EUICC_EMU) {
		fprintf(stderr, "ipad: export is for emulated cards; an IoT eUICC signs with its own certificate\n");
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

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	if (!(f = fopen(tmp, "w"))) {
		fprintf(stderr, "ipad: %s: %s\n", tmp, strerror(errno));
		return 1;
	}
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
	if (fclose(f) != 0 || rename(tmp, path) != 0) {
		fprintf(stderr, "ipad: %s: %s\n", path, strerror(errno));
		unlink(tmp);
		return 1;
	}
	syslog(LOG_NOTICE, "import file for EID %s written to %s", eidhex, path);
	db_free(&pk64);
	db_free(&proof);
	db_free(&info1);
	db_free(&caps);
	return 0;
}

/* Everything the card says is collected first: stdout is also the APDU
 * channel, and a line printed in pieces around card calls would come out
 * interleaved with them. */
static void cmd_info(euicc *eu, const crypto_key *key, const uint8_t eid[16], FILE *out)
{
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
			fprintf(m, ",\"tls\":\"%s\"}", der_find(c.val, c.len, 0xA6, &x) == 0 ? "pinned" : "system");
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
	host_init(&hl, stdin, stdout);
	card_init(&c, &HOST_CARD_OPS, &hl);
	memset(&eu, 0, sizeof(eu));
	eu.card = &c;
	host_ipa_hooks(&hl, &cfg.host, verbose);
	if (!direct)
		cfg.host.download = NULL;
	cfg.eu = &eu;

	if (read_eid(&c, eid) < 0) {
		cfg.host.log(&hl, LOG_ERR, "no EID: the card does not answer the ISD-R");
		goto out;
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
		cmd_info(&eu, key, eid, stdout);
		rc = 0;
	} else if (!strcmp(cmd, "provision")) {
		dbuf f;
		char err[200];

		db_init(&f);
		if (optind + 1 >= argc || read_file(argv[optind + 1], &f) < 0 || der_or_hex(&f) < 0) {
			fprintf(stderr, "ipad: provision needs a readable EimConfigurationData file\n");
			rc = 2;
		} else if (ipa_add_initial_eim(&eu, f.d, f.len, err, sizeof(err)) < 0) {
			cfg.host.log(&hl, LOG_ERR, err);
		} else {
			cfg.host.log(&hl, LOG_NOTICE, "eIM configuration stored");
			rc = 0;
		}
		db_free(&f);
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
		host_event_info(&hl, eidhex, eu.kind == EUICC_EMU ? "emulated" : "iot", key ? fp : NULL);
		if (!a) {
			rc = has_eim(&eu) ? 1 : EXIT_NO_EIM;
			result_line(stdout, rc, rc == EXIT_NO_EIM ? "no eIM configured" : cmd, NULL);
			goto out;
		}
		if (!strcmp(cmd, "poll")) {
			rc = ipa_poll(a, &s) < 0;
			/* the enabled profile's parameters after every poll, not only
			 * after a change: the host's copy may be gone (a config reset),
			 * and applying the same values again changes nothing */
			ipa_connectivity(a);
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
