/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
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

#define MAX_RESPONSE (4u << 20)   /* a bound package is a few hundred kB; 4 MB is ample */

static void err(http_resp *r, const char *what, int rc)
{
	snprintf(r->error, sizeof(r->error), "%s (%d)", what, rc);
}

/* "https://host:port/path" into parts; default ports 443 / 80 */
static int split_url(const char *url, bool *tls, char *host, size_t hcap, char *port,
                     size_t pcap, const char **path)
{
	const char *h, *e, *c;
	size_t n;

	if (!strncmp(url, "https://", 8)) {
		*tls = true;
		h = url + 8;
	} else if (!strncmp(url, "http://", 7)) {
		*tls = false;
		h = url + 7;
	} else {
		return -1;
	}

	e = strchr(h, '/');
	*path = e ? e : "/";
	if (!e)
		e = h + strlen(h);

	c = memchr(h, ':', (size_t)(e - h));
	n = (size_t)((c ? c : e) - h);
	if (n == 0 || n >= hcap)
		return -1;
	memcpy(host, h, n);
	host[n] = '\0';

	if (c) {
		n = (size_t)(e - c - 1);
		if (n == 0 || n >= pcap)
			return -1;
		memcpy(port, c + 1, n);
		port[n] = '\0';
	} else {
		snprintf(port, pcap, "%s", *tls ? "443" : "80");
	}
	return 0;
}

static const uint8_t *find_crlf2(const uint8_t *p, size_t len)
{
	size_t i;

	for (i = 0; i + 3 < len; i++)
		if (p[i] == '\r' && p[i + 1] == '\n' && p[i + 2] == '\r' && p[i + 3] == '\n')
			return p + i;
	return NULL;
}

int http_parse_response(const uint8_t *p, size_t len, http_resp *r)
{
	const uint8_t *hend = find_crlf2(p, len), *b, *end = p + len;
	long clen = -1;
	bool chunked = false;
	char line[512];
	const uint8_t *q;

	if (!hend || len < 12 || memcmp(p, "HTTP/1.", 7))
		return -1;

	r->status = atoi((const char *)p + 9);

	/* headers: only the two that decide how the body is framed */
	for (q = p; q < hend; ) {
		const uint8_t *nl = memchr(q, '\n', (size_t)(hend - q));
		size_t n = (size_t)((nl ? nl : hend) - q);

		if (n >= sizeof(line))
			n = sizeof(line) - 1;
		memcpy(line, q, n);
		line[n] = '\0';
		if (!strncasecmp(line, "Content-Length:", 15))
			clen = atol(line + 15);
		else if (!strncasecmp(line, "Transfer-Encoding:", 18) && strstr(line + 18, "chunked"))
			chunked = true;
		q = nl ? nl + 1 : hend;
	}

	b = hend + 4;

	if (chunked) {
		while (b < end) {
			char *ep;
			unsigned long n = strtoul((const char *)b, &ep, 16);
			const uint8_t *data = memchr(b, '\n', (size_t)(end - b));

			if (!data)
				return -1;
			data++;
			if (n == 0)
				return 0;
			if ((size_t)(end - data) < n + 2)
				return -1;
			db_put(&r->body, data, n);
			b = data + n + 2;
		}
		return -1;   /* no terminating chunk */
	}

	if (clen >= 0) {
		if ((size_t)(end - b) < (size_t)clen)
			return -1;
		db_put(&r->body, b, (size_t)clen);
		return 0;
	}

	db_put(&r->body, b, (size_t)(end - b));   /* read to close */
	return 0;
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

int http_post(const char *url, const char *const *headers, const uint8_t *body, size_t len,
              const http_tls *t, http_resp *r)
{
	char host[256], port[8], hdr[2048];
	const char *path;
	bool tls;
	int rc = -1, hn, i;
	mbedtls_net_context net;
	mbedtls_ssl_context ssl;
	mbedtls_ssl_config conf;
	mbedtls_x509_crt ca;
	mbedtls_entropy_context ent;
	mbedtls_ctr_drbg_context drbg;
	dbuf raw;
	int timeout = (t && t->timeout_ms) ? t->timeout_ms : 30000;

	memset(r, 0, sizeof(*r));
	db_init(&r->body);
	db_init(&raw);

	if (split_url(url, &tls, host, sizeof(host), port, sizeof(port), &path) < 0) {
		err(r, "bad url", 0);
		return -1;
	}

	hn = snprintf(hdr, sizeof(hdr), "POST %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ipad\r\n"
	              "Content-Length: %zu\r\nConnection: close\r\n", path, host, len);
	for (i = 0; headers && headers[i]; i++)
		hn += snprintf(hdr + hn, sizeof(hdr) - (size_t)hn, "%s\r\n", headers[i]);
	hn += snprintf(hdr + hn, sizeof(hdr) - (size_t)hn, "\r\n");
	if (hn >= (int)sizeof(hdr)) {
		err(r, "headers too long", hn);
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

	if ((i = mbedtls_net_connect(&net, host, port, MBEDTLS_NET_PROTO_TCP)) != 0) {
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

		if ((i = mbedtls_ssl_setup(&ssl, &conf)) != 0 ||
		    (i = mbedtls_ssl_set_hostname(&ssl, host)) != 0) {   /* SNI + name check */
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
	}

#define SEND(buf, n) (tls ? mbedtls_ssl_write(&ssl, (buf), (n)) : mbedtls_net_send(&net, (buf), (n)))
#define RECV(buf, n) (tls ? mbedtls_ssl_read(&ssl, (buf), (n)) : mbedtls_net_recv_timeout(&net, (buf), (n), (uint32_t)timeout))
	{
		const uint8_t *parts[2] = { (const uint8_t *)hdr, body };
		size_t lens[2] = { (size_t)hn, len };
		int k;

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
		if (raw.len > MAX_RESPONSE) {
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
