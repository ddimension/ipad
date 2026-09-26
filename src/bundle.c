/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#define _DEFAULT_SOURCE   /* timegm */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mbedtls/base64.h>

#include "bundle.h"

bool bundle_is(const uint8_t *p, size_t len)
{
	size_t i = 0;

	while (i < len && (p[i] == ' ' || p[i] == '\t' || p[i] == '\r' || p[i] == '\n'))
		i++;
	return i < len && p[i] == '{';
}

static void set_err(char *err, size_t errlen, const char *msg)
{
	if (err && errlen)
		snprintf(err, errlen, "%s", msg);
}

static void skip_ws(const uint8_t **p, const uint8_t *end)
{
	while (*p < end && (**p == ' ' || **p == '\t' || **p == '\r' || **p == '\n'))
		(*p)++;
}

/* a JSON string without escapes: the value between the quotes */
static int read_str(const uint8_t **p, const uint8_t *end, const uint8_t **s, size_t *n)
{
	const uint8_t *q;

	if (*p >= end || **p != '"')
		return -1;
	for (q = *p + 1; q < end && *q != '"'; q++)
		if (*q == '\\' || *q < 0x20)
			return -1;   /* D-69: nothing in a bundle needs escaping */
	if (q >= end)
		return -1;
	*s = *p + 1;
	*n = (size_t)(q - *s);
	*p = q + 1;
	return 0;
}

static int b64_into(const uint8_t *s, size_t n, dbuf *out)
{
	size_t olen = 0;
	unsigned char *o;
	int rc;

	if (mbedtls_base64_decode(NULL, 0, &olen, s, n) == MBEDTLS_ERR_BASE64_INVALID_CHARACTER || !olen)
		return -1;
	if (!(o = malloc(olen)))
		return -1;
	rc = mbedtls_base64_decode(o, olen, &olen, s, n);
	if (rc == 0)
		db_put(out, o, olen);
	memset(o, 0, olen);   /* may be the private key */
	free(o);
	return rc == 0 && !out->err ? 0 : -1;
}

int bundle_parse(const uint8_t *p, size_t len, bundle *b, char *err, size_t errlen)
{
	const uint8_t *end = p + len, *k, *v;
	size_t kn, vn;
	bool fmt = false, have_ctr = false;

	memset(b, 0, sizeof(*b));
	db_init(&b->eim_config);
	db_init(&b->device_key);

	skip_ws(&p, end);
	if (p >= end || *p++ != '{') {
		set_err(err, errlen, "not a JSON object");
		return -1;
	}
	for (;;) {
		skip_ws(&p, end);
		if (p < end && *p == '}')
			break;
		if (read_str(&p, end, &k, &kn) < 0) {
			set_err(err, errlen, "malformed key");
			goto bad;
		}
		skip_ws(&p, end);
		if (p >= end || *p++ != ':') {
			set_err(err, errlen, "missing ':'");
			goto bad;
		}
		skip_ws(&p, end);

#define KEY(s) (kn == sizeof(s) - 1 && !memcmp(k, s, kn))
		if (p < end && *p == '"') {
			if (read_str(&p, end, &v, &vn) < 0) {
				set_err(err, errlen, "malformed string value");
				goto bad;
			}
			if (KEY("format")) {
				if (vn != sizeof(BUNDLE_FORMAT) - 1 || memcmp(v, BUNDLE_FORMAT, vn)) {
					set_err(err, errlen, "not an " BUNDLE_FORMAT " bundle");
					goto bad;
				}
				fmt = true;
			} else if (KEY("issuance_id")) {
				if (vn >= sizeof(b->issuance_id))
					goto toolong;
				memcpy(b->issuance_id, v, vn);
			} else if (KEY("expires_at")) {
				if (vn >= sizeof(b->expires_at))
					goto toolong;
				memcpy(b->expires_at, v, vn);
			} else if (KEY("eim_configuration")) {
				if (b64_into(v, vn, &b->eim_config) < 0) {
					set_err(err, errlen, "eim_configuration is not base64");
					goto bad;
				}
			} else if (KEY("device_key")) {
				if (b64_into(v, vn, &b->device_key) < 0) {
					set_err(err, errlen, "device_key is not base64");
					goto bad;
				}
			}
			/* an unknown string field: a later format revision, ignored */
		} else if (p < end && (*p == '-' || (*p >= '0' && *p <= '9'))) {
			char num[24];
			size_t n = 0;
			char *e;
			long long x;

			while (p < end && n < sizeof(num) - 1 && (*p == '-' || (*p >= '0' && *p <= '9')))
				num[n++] = (char)*p++;
			num[n] = 0;
			x = strtoll(num, &e, 10);
			if (*e) {
				set_err(err, errlen, "malformed number");
				goto bad;
			}
			if (KEY("counter")) {
				b->counter = x;
				have_ctr = true;
			}
		} else {
			/* D-69: strings and integers only; nesting would be a format
			 * this reader was not written for */
			set_err(err, errlen, "unexpected value type");
			goto bad;
		}
#undef KEY
		skip_ws(&p, end);
		if (p < end && *p == ',') {
			p++;
			continue;
		}
		if (p < end && *p == '}')
			break;
		set_err(err, errlen, "missing ',' or '}'");
		goto bad;
	}

	if (!fmt) {
		set_err(err, errlen, "no format field");
		goto bad;
	}
	if (!b->eim_config.len || !b->device_key.len || !have_ctr || !b->issuance_id[0] || !b->expires_at[0]) {
		set_err(err, errlen, "a required field is missing (issuance_id, eim_configuration, device_key, counter, expires_at)");
		goto bad;
	}
	if (b->eim_config.d[0] != 0x30 && b->eim_config.d[0] != 0xBF) {
		set_err(err, errlen, "eim_configuration is not DER");
		goto bad;
	}
	return 0;

toolong:
	set_err(err, errlen, "a field is too long");
bad:
	bundle_free(b);
	return -1;
}

void bundle_free(bundle *b)
{
	if (b->device_key.d)
		memset(b->device_key.d, 0, b->device_key.len);
	db_free(&b->device_key);
	db_free(&b->eim_config);
}

static int digits(const char *s, int n, int *out)
{
	int v = 0, i;

	for (i = 0; i < n; i++) {
		if (s[i] < '0' || s[i] > '9')
			return -1;
		v = v * 10 + (s[i] - '0');
	}
	*out = v;
	return 0;
}

int rfc3339_time(const char *s, time_t *out)
{
	struct tm tm;
	int y, mo, d, h, mi, sec, oh = 0, om = 0, sign = 0;
	const char *p;

	if (strlen(s) < 20 || s[4] != '-' || s[7] != '-' || (s[10] != 'T' && s[10] != 't' && s[10] != ' ') ||
	    s[13] != ':' || s[16] != ':' ||
	    digits(s, 4, &y) || digits(s + 5, 2, &mo) || digits(s + 8, 2, &d) ||
	    digits(s + 11, 2, &h) || digits(s + 14, 2, &mi) || digits(s + 17, 2, &sec))
		return -1;
	p = s + 19;
	if (*p == '.')
		for (p++; *p >= '0' && *p <= '9'; p++)
			;
	if (*p == 'Z' || *p == 'z') {
		p++;
	} else if (*p == '+' || *p == '-') {
		sign = (*p == '-') ? -1 : 1;
		if (p[3] != ':' || digits(p + 1, 2, &oh) || digits(p + 4, 2, &om))
			return -1;
		p += 6;
	} else {
		return -1;
	}
	if (*p || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || sec > 60)
		return -1;

	memset(&tm, 0, sizeof(tm));
	tm.tm_year = y - 1900;
	tm.tm_mon = mo - 1;
	tm.tm_mday = d;
	tm.tm_hour = h;
	tm.tm_min = mi;
	tm.tm_sec = sec;
	*out = timegm(&tm) - sign * (oh * 3600 + om * 60);
	return 0;
}

bind_outcome bind_outcome_of(int st)
{
	if (st == 204 || st == 409)
		return BIND_DONE;
	if (st == 403)
		return BIND_REFUSED;
	if (st == 0 || st == 429 || (st >= 500 && st <= 599))
		return BIND_RETRY;
	return BIND_BAD;
}

int bind_url(const char *url, char *out, size_t cap)
{
	const char *h = strstr(url, "://"), *slash;
	int n;

	if (!h || !h[3])
		return -1;
	slash = strchr(h + 3, '/');
	n = snprintf(out, cap, "%.*s/ipad/v1/bind", (int)(slash ? (size_t)(slash - url) : strlen(url)), url);
	return (n > 0 && (size_t)n < cap) ? 0 : -1;
}
