/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The one HTTP exchange ESipa needs: POST a body, read the answer. HTTP/1.1
 * with `Connection: close`, over TLS (mbedTLS) or, for a lab eIM only, plain.
 *
 * Server trust, in the order the eIM configuration can express it (SGP.32
 * v1.3 EimConfigurationData.trustedPublicKeyDataTls):
 *   pin_spki  the server's leaf key must be exactly this SubjectPublicKeyInfo
 *   ca_der    a CA certificate the chain must end in
 *   ca_file   otherwise, the system bundle
 * insecure skips verification altogether and is meant for lab setups only.
 */
#ifndef IPAD_HTTP_H
#define IPAD_HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "der.h"

typedef struct {
	const char *ca_file;          /* default /etc/ssl/certs/ca-certificates.crt */
	const uint8_t *ca_der;
	size_t ca_der_len;
	const uint8_t *pin_spki;
	size_t pin_spki_len;
	bool insecure;
	int timeout_ms;               /* per read/connect, default 30000 */
} http_tls;

/* the most ipad reads from one answer: a bound package is a few hundred kB */
#define HTTP_MAX_BODY ((size_t)4 << 20)

typedef struct {
	int status;                   /* HTTP status, 0 when none was read */
	dbuf body;
	char error[160];              /* what failed, for the log */
} http_resp;

/* A URL taken apart: host is what is connected to (an IPv6 literal without
 * its brackets), sni the TLS server name and certificate name (empty for an
 * IP literal, trailing dot removed), host_hdr the Host field value. */
typedef struct {
	bool tls;
	bool ip;                      /* host is an IPv4 or IPv6 literal */
	char host[256];
	char port[6];
	char sni[256];
	char host_hdr[264];
	const char *path;             /* points into the URL */
} http_url;

/* http(s)://host[:port][/path] and http(s)://[v6][:port][/path]; -1 on
 * anything else (userinfo, a zone id, a control character or space) */
int http_split_url(const char *url, http_url *u);

/* url: http(s)://host[:port]/path. headers: "Name: value" lines, NULL-terminated.
 * Returns 0 when an HTTP answer was read (any status), -1 on a transport or
 * TLS failure (resp->error says which). resp->body must be freed by the caller. */
int http_post(const char *url, const char *const *headers, const uint8_t *body, size_t len,
              const http_tls *tls, http_resp *resp);

/* exposed for tests: parse a complete HTTP/1.1 response. resp must be zeroed
 * with its body initialised (db_init) first; -1 on anything malformed. */
int http_parse_response(const uint8_t *p, size_t len, http_resp *resp);

#endif
