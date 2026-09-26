/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>

#include "http.h"


static void err(http_resp *r, const char *what, int rc)
{
	snprintf(r->error, sizeof(r->error), "%s (%d)", what, rc);
}

static int hexval(uint8_t c);

/* a dotted-quad IPv4 literal (RFC 3986 3.2.2 IPv4address) */
static bool is_ipv4(const char *s)
{
	int parts = 0, digits = 0, v = 0;

	for (;; s++) {
		if (*s >= '0' && *s <= '9') {
			v = v * 10 + (*s - '0');
			if (++digits > 3 || v > 255)
				return false;
		} else if (*s == '.' || !*s) {
			if (!digits || ++parts > 4)
				return false;
			if (!*s)
				return parts == 4;
			digits = v = 0;
		} else {
			return false;
		}
	}
}

int http_split_url(const char *url, http_url *u)
{
	const char *h, *e, *c, *x;
	size_t n;
	unsigned long port = 0;

	memset(u, 0, sizeof(*u));
	if (!strncmp(url, "https://", 8)) {
		u->tls = true;
		h = url + 8;
	} else if (!strncmp(url, "http://", 7)) {
		h = url + 7;
	} else {
		return -1;
	}
	/* the URL goes into the request line and Host: a space or control
	 * character (the FQDN can come from the card's eIM configuration) would
	 * be header injection */
	for (x = url; *x; x++)
		if ((unsigned char)*x <= 0x20 || (unsigned char)*x >= 0x7f)
			return -1;

	e = strchr(h, '/');
	u->path = e ? e : "/";
	if (!e)
		e = h + strlen(h);
	if (memchr(h, '@', (size_t)(e - h)))
		return -1;   /* no userinfo: nothing here would send it */

	if (*h == '[') {
		/* IP-literal (RFC 3986 3.2.2): only IPv6address, no zone and no
		 * IPvFuture */
		const char *rb = memchr(h, ']', (size_t)(e - h));

		if (!rb)
			return -1;
		n = (size_t)(rb - h - 1);
		if (n < 2 || n >= sizeof(u->host))
			return -1;
		for (x = h + 1; x < rb; x++)
			if (!(hexval((uint8_t)*x) >= 0 || *x == ':' || *x == '.'))
				return -1;
		memcpy(u->host, h + 1, n);
		u->ip = true;
		c = rb + 1;
		if (c < e && *c != ':')
			return -1;
		if (c == e)
			c = NULL;
	} else {
		c = memchr(h, ':', (size_t)(e - h));
		n = (size_t)((c ? c : e) - h);
		if (n == 0 || n >= sizeof(u->host))
			return -1;
		memcpy(u->host, h, n);
		u->ip = is_ipv4(u->host);
	}
	u->host[n] = '\0';

	if (c) {
		for (x = c + 1; x < e; x++) {
			if (*x < '0' || *x > '9' || (port = port * 10 + (unsigned long)(*x - '0')) > 65535)
				return -1;
		}
		if (x == c + 1 || port == 0)
			return -1;
	} else {
		port = u->tls ? 443 : 80;
	}
	snprintf(u->port, sizeof(u->port), "%lu", port);

	/* RFC 6066 3: HostName is a DNS name without the trailing dot, and an
	 * IP literal is never sent. The same name is what the certificate is
	 * checked against, where "eim.example." would never match. */
	if (!u->ip) {
		snprintf(u->sni, sizeof(u->sni), "%s", u->host);
		n = strlen(u->sni);
		if (u->sni[n - 1] == '.') {
			if (n == 1)
				return -1;
			u->sni[n - 1] = '\0';
		}
	}

	/* RFC 9110 7.2: Host is uri-host [":" port], the port given when it is
	 * not the scheme's default; an IPv6 literal keeps its brackets */
	n = (size_t)snprintf(u->host_hdr, sizeof(u->host_hdr), u->ip && strchr(u->host, ':') ? "[%s]" : "%s", u->host);
	if (port != (u->tls ? 443u : 80u))
		n += (size_t)snprintf(u->host_hdr + n, sizeof(u->host_hdr) - n, ":%lu", port);
	return 0;
}

/* ---- response parsing (RFC 9112) -------------------------------------------
 * Everything here reads bytes a server, or whoever sits in the path before the
 * TLS check has a say, chose. Nothing is parsed with the C string functions:
 * the buffer is not NUL-terminated, and a number is read digit by digit with
 * its own bound, so a length can never wrap an addition further down. */

static const uint8_t *find_crlf(const uint8_t *p, const uint8_t *end)
{
	for (; p + 1 < end; p++)
		if (p[0] == '\r' && p[1] == '\n')
			return p;
	return NULL;
}

static const uint8_t *find_crlf2(const uint8_t *p, const uint8_t *end)
{
	for (; p + 3 < end; p++)
		if (p[0] == '\r' && p[1] == '\n' && p[2] == '\r' && p[3] == '\n')
			return p;
	return NULL;
}

static bool is_digit(uint8_t c)
{
	return c >= '0' && c <= '9';
}

static int hexval(uint8_t c)
{
	if (is_digit(c))
		return c - '0';
	c |= 0x20;
	return (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

/* RFC 9110 5.6.2 tchar: what a field name and a transfer coding consist of */
static bool is_tchar(uint8_t c)
{
	return (c >= '0' && c <= '9') || ((c | 0x20) >= 'a' && (c | 0x20) <= 'z') ||
	       (c && strchr("!#$%&'*+-.^_`|~", c));
}

static bool ieq(const uint8_t *p, size_t n, const char *s)
{
	return strlen(s) == n && !strncasecmp((const char *)p, s, n);
}

/* A CR or LF on its own inside a line: RFC 9112 2.2 lets a recipient take a
 * bare LF as a line end, so a field hidden behind one would be seen by a
 * parser that does and missed by this one. Refused rather than guessed. */
static bool lone_free(const uint8_t *p, const uint8_t *e)
{
	return !memchr(p, '\n', (size_t)(e - p)) && !memchr(p, '\r', (size_t)(e - p));
}

/* trims OWS (SP / HTAB) from both ends of [*p, *e) */
static void trim_ows(const uint8_t **p, const uint8_t **e)
{
	while (*p < *e && (**p == ' ' || **p == '\t'))
		(*p)++;
	while (*e > *p && ((*e)[-1] == ' ' || (*e)[-1] == '\t'))
		(*e)--;
}

/* Content-Length = 1*DIGIT (RFC 9110 8.6); a list of equal values, which some
 * servers send after merging duplicates, is one value. Bounded at
 * HTTP_MAX_BODY: nothing larger could have been received anyway. */
static int parse_clen(const uint8_t *p, const uint8_t *e, size_t *out)
{
	bool have = false;
	size_t v = 0;

	while (p <= e) {
		const uint8_t *c = memchr(p, ',', (size_t)(e - p)), *ve = c ? c : e, *vp = p;
		size_t x = 0;

		trim_ows(&vp, &ve);
		if (vp == ve)
			return -1;
		for (; vp < ve; vp++) {
			if (!is_digit(*vp) || x > HTTP_MAX_BODY)
				return -1;
			x = x * 10 + (size_t)(*vp - '0');
		}
		if (x > HTTP_MAX_BODY || (have && x != v))
			return -1;
		v = x;
		have = true;
		if (!c)
			break;
		p = c + 1;
	}
	*out = v;
	return 0;
}

/* Transfer-Encoding is a list of codings, applied in order, possibly over
 * several field lines (RFC 9112 6.1). The message is framed by chunked only
 * when chunked is the final coding; ipad asks for no other coding and
 * decodes none, so any other coding anywhere is an error. */
static int parse_te(const uint8_t *p, const uint8_t *e, int *te)
{
	while (p <= e) {
		const uint8_t *c = memchr(p, ',', (size_t)(e - p)), *ve = c ? c : e, *vp = p, *q;

		trim_ows(&vp, &ve);
		if (vp != ve) {   /* empty list elements are allowed (RFC 9110 5.6.1) */
			for (q = vp; q < ve && is_tchar(*q); q++)
				;
			/* chunked has no parameters; codings are case-insensitive */
			if (q != ve || !ieq(vp, (size_t)(ve - vp), "chunked") || *te == 2)
				return -1;   /* another coding, or chunked twice */
			*te = 2;
		}
		if (!c)
			break;
		p = c + 1;
	}
	if (*te == 0)
		*te = 1;   /* present, but empty */
	return 0;
}

/* status-line = HTTP-version SP status-code SP [ reason-phrase ] (RFC 9112
 * 4); a missing SP before an empty reason phrase is tolerated. */
static int parse_status(const uint8_t *p, const uint8_t *eol, int *minor, int *status)
{
	if (eol - p < 12 || memcmp(p, "HTTP/1.", 7) || !is_digit(p[7]) || p[8] != ' ' ||
	    p[9] < '1' || p[9] > '5' || !is_digit(p[10]) || !is_digit(p[11]) ||
	    (eol - p > 12 && p[12] != ' '))
		return -1;
	*minor = p[7] - '0';
	*status = (p[9] - '0') * 100 + (p[10] - '0') * 10 + (p[11] - '0');
	return 0;
}

int http_parse_response(const uint8_t *p, size_t len, http_resp *r)
{
	const uint8_t *end = p + len, *hend, *q, *b;
	int minor, te;
	bool have_clen;
	size_t clen;

	r->retry_after = -1;

	/* interim 1xx answers (100 Continue, 103 Early Hints) come before the
	 * final one and carry no body (RFC 9110 15.2); 101 would switch
	 * protocols, which ipad never asks for */
	for (;;) {
		const uint8_t *eol = find_crlf(p, end), *prev = NULL;
		size_t prev_len = 0;

		if (!eol || !(hend = find_crlf2(p, end)) || parse_status(p, eol, &minor, &r->status) < 0 ||
		    !lone_free(p, eol))
			return -1;

		te = 0;
		have_clen = false;
		clen = 0;
		for (q = eol + 2; q < hend + 2; ) {
			const uint8_t *le = find_crlf(q, hend + 2), *colon, *vp, *ve;

			if (!lone_free(q, le))
				return -1;
			if (*q == ' ' || *q == '\t') {
				/* obs-fold: continues the previous field (RFC 9112 5.2).
				 * For the two fields that frame the body a continuation
				 * would change what the value means: refused. */
				if (!prev || ieq(prev, prev_len, "Content-Length") || ieq(prev, prev_len, "Transfer-Encoding"))
					return -1;
				q = le + 2;
				continue;
			}
			colon = memchr(q, ':', (size_t)(le - q));
			if (!colon || colon == q)
				return -1;
			/* no whitespace between name and colon (RFC 9112 5.1): a
			 * server that sends it is being read differently by someone */
			for (vp = q; vp < colon; vp++)
				if (!is_tchar(*vp))
					return -1;
			prev = q;
			prev_len = (size_t)(colon - q);
			vp = colon + 1;
			ve = le;
			trim_ows(&vp, &ve);
			if (ieq(q, (size_t)(colon - q), "Content-Length")) {
				size_t v;

				if (parse_clen(vp, ve, &v) < 0 || (have_clen && v != clen))
					return -1;
				clen = v;
				have_clen = true;
			} else if (ieq(q, (size_t)(colon - q), "Transfer-Encoding")) {
				if (parse_te(vp, ve, &te) < 0)
					return -1;
			} else if (ieq(q, (size_t)(colon - q), "Retry-After")) {
				/* delay-seconds = 1*DIGIT (RFC 9110 10.2.3); the
				 * HTTP-date form is left unread (-1), a caller then
				 * keeps its own backoff */
				const uint8_t *d0 = vp;
				long v = 0;

				for (r->retry_after = -1; vp < ve && is_digit(*vp) && v <= HTTP_MAX_RETRY_AFTER; vp++)
					v = v * 10 + (*vp - '0');
				if (vp == ve && vp > d0 && v <= HTTP_MAX_RETRY_AFTER)
					r->retry_after = v;
			}
			q = le + 2;
		}
		b = hend + 4;
		if (r->status >= 200)
			break;
		if (r->status == 101)
			return -1;
		p = b;
	}

	/* RFC 9112 6.1: Transfer-Encoding in an HTTP/1.0 message means the
	 * framing is faulty. 6.3: with both fields, Transfer-Encoding would win,
	 * but a sender MUST NOT send both (6.2) and the RFC says the message
	 * "ought to be handled as an error" — a response framed two ways is read
	 * one way here and another way by a middlebox, so it is refused. */
	if ((te && minor == 0) || (te && have_clen) || te == 1)
		return -1;

	/* 204 and 304 have no body whatever the fields say (RFC 9112 6.3) */
	if (r->status == 204 || r->status == 304)
		return 0;

	if (te) {
		for (;;) {
			const uint8_t *eol = find_crlf(b, end), *x;
			uint64_t n = 0;
			int d, digits = 0;

			if (!eol)
				return -1;
			/* chunk-size = 1*HEXDIG, read by hand: at most 16 digits, so the
			 * value fits 64 bits and is compared against what is there
			 * before anything is added to it */
			for (x = b; x < eol && (d = hexval(*x)) >= 0; x++) {
				if (++digits > 16)
					return -1;
				n = (n << 4) | (uint64_t)d;
			}
			if (!digits)
				return -1;   /* not a chunk size; never a last chunk */
			/* chunk-ext (RFC 9112 7.1.1) is allowed and ignored:
			 * BWS ";" ... up to the line end */
			while (x < eol && (*x == ' ' || *x == '\t'))
				x++;
			if (x < eol && *x != ';')
				return -1;
			for (; x < eol; x++)
				if (*x == '\n' || *x == '\r')
					return -1;
			b = eol + 2;
			if (n == 0) {
				/* the trailer section ends with an empty line; it is
				 * read past, not interpreted (RFC 9112 7.1.2) */
				if (end - b >= 2 && b[0] == '\r' && b[1] == '\n')
					return 0;
				return find_crlf2(b, end) ? 0 : -1;
			}
			if (n > (uint64_t)(end - b) || (size_t)(end - b) - (size_t)n < 2)
				return -1;
			if (b[n] != '\r' || b[n + 1] != '\n')
				return -1;   /* chunk data is followed by CRLF */
			db_put(&r->body, b, (size_t)n);
			if (r->body.err)
				return -1;
			b += n + 2;
		}
	}

	if (have_clen) {
		if ((size_t)(end - b) < clen)
			return -1;
		db_put(&r->body, b, clen);
		return r->body.err ? -1 : 0;
	}

	db_put(&r->body, b, (size_t)(end - b));   /* read to close */
	return r->body.err ? -1 : 0;
}

/* the server's leaf key must be the pinned one; checked after the handshake
 * rather than in a verify callback, so it cannot be skipped by authmode */
static int pinned_ok(const mbedtls_ssl_context *ssl, const http_tls *t)
{
	const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(ssl);
	uint8_t buf[512];
	int n;

	if (!peer)
		return 0;
	n = mbedtls_pk_write_pubkey_der((mbedtls_pk_context *)&peer->pk, buf, sizeof(buf));
	return n > 0 && (size_t)n == t->pin_spki_len &&
	       !memcmp(buf + sizeof(buf) - n, t->pin_spki, (size_t)n);
}

/* appends to the request head; -1 once it would not fit, so the offset can
 * never pass the buffer and turn the remaining size negative */
static int hdr_add(char *buf, size_t cap, size_t *off, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf + *off, cap - *off, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= cap - *off)
		return -1;
	*off += (size_t)n;
	return 0;
}

int http_post(const char *url, const char *const *headers, const uint8_t *body, size_t len,
              const http_tls *t, http_resp *r)
{
	char hdr[2048];
	http_url u;
	bool tls;
	int rc = -1, i, k;
	size_t hn;
	mbedtls_net_context net;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_entropy_context ent;
	mbedtls_ctr_drbg_context drbg;
	dbuf raw;
	int timeout = (t && t->timeout_ms) ? t->timeout_ms : 30000;

	memset(r, 0, sizeof(*r));
	r->retry_after = -1;
	db_init(&r->body);
	db_init(&raw);

	if (http_split_url(url, &u) < 0) {
		err(r, "bad url", 0);
		return -1;
	}
	tls = u.tls;

	hn = 0;
	i = hdr_add(hdr, sizeof(hdr), &hn, "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ipad\r\n"
	            "Content-Length: %zu\r\nConnection: close\r\n", u.path, u.host_hdr, len);
	for (k = 0; i == 0 && headers && headers[k]; k++)
		i = hdr_add(hdr, sizeof(hdr), &hn, "%s\r\n", headers[k]);
	if (i < 0 || hdr_add(hdr, sizeof(hdr), &hn, "\r\n") < 0) {
		err(r, "headers too long", (int)hn);
		return -1;
	}

	/* mbedTLS 3.6 runs TLS 1.3 key exchange through PSA, which must be set up
	 * once before any handshake (idempotent) */
	if (tls && psa_crypto_init() != PSA_SUCCESS) {
		err(r, "psa init failed", 0);
		return -1;
	}

	mbedtls_net_init(&net);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_x509_crt_init(&ca);
	mbedtls_entropy_init(&ent);
	mbedtls_ctr_drbg_init(&drbg);

	if ((i = mbedtls_net_connect(&net, u.host, u.port, MBEDTLS_NET_PROTO_TCP)) != 0) {
		err(r, "connect failed", i);
		goto out;
	}

	if (tls) {
		if ((i = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, NULL, 0)) != 0 ||
		    (i = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
		                                     MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
			err(r, "tls setup failed", i);
			goto out;
		}
		mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &drbg);
		mbedtls_ssl_conf_read_timeout(&conf, (uint32_t)timeout);

		if (t && t->insecure) {
			mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
		} else if (t && t->pin_spki) {
			/* the pin decides; the chain is not required to be known */
			mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		} else {
			if (t && t->ca_der)
				i = mbedtls_x509_crt_parse_der(&ca, t->ca_der, t->ca_der_len);
			else
				i = mbedtls_x509_crt_parse_file(&ca, (t && t->ca_file) ? t->ca_file
				                                     : "/etc/ssl/certs/ca-certificates.crt");
			if (i < 0) {
				err(r, "no usable CA", i);
				goto out;
			}
			mbedtls_ssl_conf_ca_chain(&conf, &ca, NULL);
			mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		}

		/* SNI and the name the certificate is checked against are one
		 * setting in mbedTLS. An IP literal must not go out as SNI (RFC
		 * 6066 3), so it gets none and its name is checked below. */
		if ((i = mbedtls_ssl_setup(&ssl, &conf)) != 0 ||
		    (i = mbedtls_ssl_set_hostname(&ssl, u.ip ? NULL : u.sni)) != 0) {
			err(r, "tls setup failed", i);
			goto out;
		}
		mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, NULL, mbedtls_net_recv_timeout);

		while ((i = mbedtls_ssl_handshake(&ssl)) != 0)
			if (i != MBEDTLS_ERR_SSL_WANT_READ && i != MBEDTLS_ERR_SSL_WANT_WRITE) {
				err(r, "tls handshake failed", i);
				goto out;
			}

		if (t && t->pin_spki && !t->insecure && !pinned_ok(&ssl, t)) {
			err(r, "server key does not match the pinned eIM TLS key", 0);
			goto out;
		}
		/* the chain was verified in the handshake; for an IP literal the
		 * name was not: once more with the address, which mbedTLS matches
		 * against the iPAddress entries of the subjectAltName */
		if (u.ip && !(t && (t->insecure || t->pin_spki))) {
			uint32_t flags = 0;
			const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);

			if (!peer || mbedtls_x509_crt_verify((mbedtls_x509_crt *)peer, &ca, NULL, u.host, &flags,
			                                     NULL, NULL) != 0) {
				err(r, "certificate not issued for this address", (int)flags);
				goto out;
			}
		}
	}

#define SEND(buf, n) (tls ? mbedtls_ssl_write(&ssl, (buf), (n)) : mbedtls_net_send(&net, (buf), (n)))
#define RECV(buf, n) (tls ? mbedtls_ssl_read(&ssl, (buf), (n)) : mbedtls_net_recv_timeout(&net, (buf), (n), (uint32_t)timeout))
	{
		const uint8_t *parts[2] = { (const uint8_t *)hdr, body };
		size_t lens[2] = { (size_t)hn, len };

		for (k = 0; k < 2; k++) {
			size_t off = 0;

			while (off < lens[k]) {
				i = SEND(parts[k] + off, lens[k] - off);
				if (i == MBEDTLS_ERR_SSL_WANT_WRITE)
					continue;
				if (i <= 0) {
					err(r, "send failed", i);
					goto out;
				}
				off += (size_t)i;
			}
		}
	}

	for (;;) {
		uint8_t buf[4096];

		i = RECV(buf, sizeof(buf));
		if (i == MBEDTLS_ERR_SSL_WANT_READ)
			continue;
		if (i == 0 || i == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			break;
		if (i < 0) {
			/* a peer that closes without close_notify still ends the answer */
			if (i == MBEDTLS_ERR_NET_CONN_RESET && raw.len)
				break;
			err(r, "receive failed", i);
			goto out;
		}
		db_put(&raw, buf, (size_t)i);
		if (raw.len > HTTP_MAX_BODY) {
			err(r, "response too large", (int)raw.len);
			goto out;
		}
	}
#undef SEND
#undef RECV

	if (http_parse_response(raw.d, raw.len, r) < 0) {
		err(r, "malformed HTTP response", (int)raw.len);
		goto out;
	}
	rc = 0;

out:
	if (tls)
		mbedtls_ssl_close_notify(&ssl);
	mbedtls_net_free(&net);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_x509_crt_free(&ca);
	mbedtls_ctr_drbg_free(&drbg);
	mbedtls_entropy_free(&ent);
	db_free(&raw);
	return rc;
}
