/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#define _POSIX_C_SOURCE 200809L
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "host.h"
#include "hex.h"

static int verbose_log;

void host_init(host_link *h, FILE *in, FILE *out)
{
	memset(h, 0, sizeof(*h));
	h->in = in;
	h->out = out;
	h->channel = -1;
}

void host_free(host_link *h)
{
	free(h->line);
	h->line = NULL;
}

/* Length of the well-formed UTF-8 sequence at s (RFC 3629 4: no overlong
 * forms, no surrogates, nothing above U+10FFFF), 0 when it is not one. */
static size_t utf8_len(const unsigned char *s)
{
	size_t n, i;
	uint32_t cp;

	if (s[0] < 0x80)
		return 1;
	if (s[0] >= 0xC2 && s[0] <= 0xDF)
		n = 2, cp = s[0] & 0x1F;
	else if (s[0] >= 0xE0 && s[0] <= 0xEF)
		n = 3, cp = s[0] & 0x0F;
	else if (s[0] >= 0xF0 && s[0] <= 0xF4)
		n = 4, cp = s[0] & 0x07;
	else
		return 0;
	for (i = 1; i < n; i++) {
		if ((s[i] & 0xC0) != 0x80)   /* also stops at the terminator */
			return 0;
		cp = (cp << 6) | (s[i] & 0x3F);
	}
	if ((n == 3 && cp < 0x800) || (n == 4 && (cp < 0x10000 || cp > 0x10FFFF)) ||
	    (cp >= 0xD800 && cp <= 0xDFFF))
		return 0;
	return n;
}

/* the whole string is well-formed UTF-8 */
static bool utf8_ok(const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	size_t n;

	for (; *p; p += n)
		if (!(n = utf8_len(p)))
			return false;
	return true;
}

/* JSON text is UTF-8 (RFC 8259 8.1). The strings come from the card (a
 * profile's APN and credentials are 8-bit text in whatever coding the
 * operator chose) and the eIM; a byte that is not UTF-8 would make the
 * whole line unreadable for the host's JSON parser, so it becomes U+FFFD —
 * in text for display. A value the host acts on is checked before it gets
 * here (ev_connectivity) and never altered. */
void host_json_str(FILE *f, const char *s)
{
	const unsigned char *p = (const unsigned char *)s;
	size_t n;

	fputc('"', f);
	while (*p) {
		unsigned char c = *p;

		if (c == '"' || c == '\\') {
			fprintf(f, "\\%c", c);
			p++;
		} else if (c < 0x20 || c == 0x7F) {
			fprintf(f, "\\u%04x", c);
			p++;
		} else if ((n = utf8_len(p)) > 0) {
			fwrite(p, 1, n, f);
			p += n;
		} else {
			fputs("\\ufffd", f);
			p++;
		}
	}
	fputc('"', f);
}

/* the next line whose "type" is `type`; anything else on stdin (there
 * should be nothing) is skipped. NULL at EOF: the host is gone. */
static const char *read_type(host_link *h, const char *type)
{
	char want[40];
	ssize_t n;

	snprintf(want, sizeof(want), "\"type\":\"%s\"", type);
	while ((n = getline(&h->line, &h->cap, h->in)) >= 0) {
		/* esim_bridge writes these without spaces; tolerate a space after ':' */
		char *p = strstr(h->line, "\"type\"");

		if (!p)
			continue;
		p += 6;
		while (*p == ' ' || *p == ':')
			p++;
		if (*p == '"' && !strncmp(p + 1, type, strlen(type)) && p[1 + strlen(type)] == '"')
			return h->line;
	}
	return NULL;
}

/* "key": <int> ; the default when absent */
static long json_int(const char *s, const char *key, long dflt)
{
	char k[40];
	const char *p;

	snprintf(k, sizeof(k), "\"%s\"", key);
	if (!(p = strstr(s, k)))
		return dflt;
	p += strlen(k);
	while (*p == ' ' || *p == ':')
		p++;
	return strtol(p, NULL, 10);
}

/* "key": true */
static int json_true(const char *s, const char *key)
{
	char k[40];
	const char *p;

	snprintf(k, sizeof(k), "\"%s\"", key);
	if (!(p = strstr(s, k)))
		return 0;
	p += strlen(k);
	while (*p == ' ' || *p == ':')
		p++;
	return !strncmp(p, "true", 4);
}

/* "key": "<hex>" into out */
static int json_hex(const char *s, const char *key, dbuf *out)
{
	char k[40];
	const char *p, *e;
	uint8_t byte;

	snprintf(k, sizeof(k), "\"%s\"", key);
	if (!(p = strstr(s, k)))
		return -1;
	p += strlen(k);
	while (*p == ' ' || *p == ':')
		p++;
	if (*p++ != '"' || !(e = strchr(p, '"')) || (e - p) % 2)
		return -1;
	for (; p < e; p += 2) {
		char two[3] = { p[0], p[1], 0 };

		if (hex_decode(two, &byte, 1) != 1)
			return -1;
		db_put(out, &byte, 1);
	}
	return 0;
}

static int apdu_call(host_link *h, const char *func, const uint8_t *param, size_t plen, long *ecode, dbuf *data)
{
	const char *line;
	size_t i;

	fprintf(h->out, "{\"type\":\"apdu\",\"payload\":{\"func\":\"%s\",\"param\":\"", func);
	for (i = 0; i < plen; i++)
		fprintf(h->out, "%02X", param[i]);
	fprintf(h->out, "\"}}\n");
	fflush(h->out);

	if (!(line = read_type(h, "apdu")))
		return -1;
	*ecode = json_int(line, "ecode", -1);
	if (data && json_hex(line, "data", data) < 0)
		return -1;
	return 0;
}

static int hc_open(void *ctx, const uint8_t *aid, size_t aid_len)
{
	host_link *h = ctx;
	long ec;

	if (apdu_call(h, "connect", NULL, 0, &ec, NULL) < 0)
		return -1;
	if (apdu_call(h, "logic_channel_open", aid, aid_len, &ec, NULL) < 0 || ec < 1)
		return -1;
	h->channel = (int)ec;
	return (int)ec;
}

static int hc_transmit(void *ctx, const uint8_t *apdu, size_t len, dbuf *rapdu)
{
	host_link *h = ctx;
	long ec;

	if (apdu_call(h, "transmit", apdu, len, &ec, rapdu) < 0 || ec != 0)
		return -1;
	return rapdu->len >= 2 ? 0 : -1;
}

static int hc_close(void *ctx, int channel)
{
	host_link *h = ctx;
	uint8_t ch = (uint8_t)channel;
	long ec;

	apdu_call(h, "logic_channel_close", &ch, 1, &ec, NULL);
	apdu_call(h, "disconnect", NULL, 0, &ec, NULL);
	h->channel = -1;
	return 0;
}

const card_ops HOST_CARD_OPS = { hc_open, hc_transmit, hc_close };

/* ---- events ---- */

static void ev_log(void *ud, int lvl, const char *msg);

static const char *event_answer(host_link *h)
{
	fprintf(h->out, "}}\n");
	fflush(h->out);
	return read_type(h, "event");
}

static bool ev_profile_changed(void *ud, const char *iccid)
{
	host_link *h = ud;
	const char *a;

	fprintf(h->out, "{\"type\":\"event\",\"payload\":{\"event\":\"profile_changed\",\"iccid\":");
	host_json_str(h->out, iccid);
	a = event_answer(h);
	return a && json_true(a, "online");
}

static int ev_download(void *ud, const char *ac, const char *cc)
{
	host_link *h = ud;
	const char *a;

	fprintf(h->out, "{\"type\":\"event\",\"payload\":{\"event\":\"download\",\"activation_code\":");
	host_json_str(h->out, ac);
	if (cc) {
		fprintf(h->out, ",\"confirmation_code\":");
		host_json_str(h->out, cc);
	}
	a = event_answer(h);
	return (a && json_true(a, "ok")) ? 0 : -1;
}

static int ev_notify(void *ud, int64_t seq)
{
	host_link *h = ud;
	const char *a;

	fprintf(h->out, "{\"type\":\"event\",\"payload\":{\"event\":\"notify\",\"seq\":%lld", (long long)seq);
	a = event_answer(h);
	return (a && json_true(a, "ok")) ? 0 : -1;
}

static void ev_connectivity(void *ud, const char *iccid, const conn_params *p, bool emulated)
{
	host_link *h = ud;

	/* U+FFFD is for text a person reads. An APN or a credential the host
	 * dials with must arrive as it is on the card or not at all: a
	 * replaced byte would be a wrong password the network rejects, with
	 * nothing to say why. The values themselves stay out of the log. */
	if (p && (!utf8_ok(p->apn) || !utf8_ok(p->username) || !utf8_ok(p->password))) {
		char msg[160];

		snprintf(msg, sizeof(msg), "profile %.24s: APN or credentials are not UTF-8; connectivity parameters "
		         "not handed to the host", iccid);
		ev_log(h, LOG_ERR, msg);
		return;
	}
	fprintf(h->out, "{\"type\":\"event\",\"payload\":{\"event\":\"connectivity\",\"iccid\":");
	host_json_str(h->out, iccid);
	fprintf(h->out, ",\"emulated\":%s,\"source\":\"%s\"", emulated ? "true" : "false", p ? "card" : "none");
	if (p) {
		fprintf(h->out, ",\"apn\":");
		host_json_str(h->out, p->apn);
		if (p->username[0] || p->password[0]) {
			fprintf(h->out, ",\"username\":");
			host_json_str(h->out, p->username);
			fprintf(h->out, ",\"password\":");
			host_json_str(h->out, p->password);
		}
		if (p->pdp_type)
			fprintf(h->out, ",\"pdp_type\":\"%s\"", p->pdp_type);
	}
	event_answer(h);
}

void host_event_info(host_link *h, const char *eid, const char *backend, const char *fp,
                     const char *bind, long long counter)
{
	fprintf(h->out, "{\"type\":\"event\",\"payload\":{\"event\":\"info\",\"eid\":\"%s\",\"backend\":\"%s\"",
	        eid, backend);
	if (fp)
		fprintf(h->out, ",\"key_fingerprint\":\"%s\"", fp);
	if (bind)
		fprintf(h->out, ",\"bind\":\"%s\"", bind);
	if (counter >= 0)
		fprintf(h->out, ",\"counter\":%lld", counter);
	event_answer(h);
}

void host_event_summary(host_link *h, const char *cmd, int code, const ipa_summary *s, const char *bind)
{
	fprintf(h->out, "{\"type\":\"event\",\"payload\":{\"event\":\"summary\",\"command\":\"%s\",\"code\":%d",
	        cmd, code);
	if (s)
		fprintf(h->out, ",\"packages\":%d,\"acknowledged\":%d,\"downloads\":%d,\"notifications\":%d,"
		        "\"changed\":%d,\"rolled_back\":%d", s->packages, s->acknowledged, s->downloads,
		        s->notifications, s->profile_changed, s->rolled_back);
	if (bind)
		fprintf(h->out, ",\"bind\":\"%s\"", bind);
	/* only what went wrong in a run that failed: a warning a good run got
	 * over (a retried connection) is not its outcome */
	if (code != 0 && h->last_error[0]) {
		fprintf(h->out, ",\"error\":");
		host_json_str(h->out, h->last_error);
	}
	event_answer(h);
}

static void ev_log(void *ud, int lvl, const char *msg)
{
	host_link *h = ud;

	/* the host reads the run's outcome from the summary event; the messages
	 * logged here never carry keys, bundles or activation codes */
	if (h && lvl <= LOG_WARNING)
		snprintf(h->last_error, sizeof(h->last_error), "%s", msg);
	syslog(lvl, "%s", msg);
	if (verbose_log)
		fprintf(stderr, "ipad: %s\n", msg);
}

void host_ipa_hooks(host_link *h, ipa_host *hooks, int verbose)
{
	verbose_log = verbose;
	hooks->profile_changed = ev_profile_changed;
	hooks->download = ev_download;
	hooks->notify = ev_notify;
	hooks->connectivity = ev_connectivity;
	hooks->log = ev_log;
	hooks->ud = h;
}
