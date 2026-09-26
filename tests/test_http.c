/* SPDX-License-Identifier: GPL-2.0-only
 * http.c against a local HTTPS stand-in (tests/tls_echo.py): the ESipa
 * headers arrive, bodies come back (Content-Length and chunked), and server
 * trust holds: the right CA or pin passes, a wrong pin or name does not.
 * The response parser on its own against malformed and hostile framing. */
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>
#include "check.h"
#include "http.h"

static size_t slurp(const char *name, uint8_t *buf, size_t cap)
{
	char p[512];
	FILE *f;
	size_t n;

	snprintf(p, sizeof(p), "%s/%s", FIXTURES, name);
	f = fopen(p, "rb");
	if (!f)
		return 0;
	n = fread(buf, 1, cap, f);
	fclose(f);
	return n;
}

static pid_t server_ex(int port, const char *certname, const char *host)
{
	int fd[2];
	pid_t pid;
	char ready[16] = { 0 };

	if (pipe(fd) < 0)
		return -1;
	pid = fork();
	if (pid == 0) {
		char p[16], cert[512], key[512];

		dup2(fd[1], 1);
		snprintf(p, sizeof(p), "%d", port);
		snprintf(cert, sizeof(cert), "%s/%s", FIXTURES, certname);
		snprintf(key, sizeof(key), "%s/server.key.pem", FIXTURES);
		execlp("python3", "python3", TESTS "/tls_echo.py", p, cert, key, host, (char *)NULL);
		_exit(127);
	}
	close(fd[1]);
	if (read(fd[0], ready, sizeof(ready) - 1) <= 0)
		return -1;
	close(fd[0]);
	return pid;
}

static pid_t server(int port)
{
	return server_ex(port, "server.cert.pem", "127.0.0.1");
}

/* An IP-literal URL against a certificate trusted as its own anchor, so
 * only the name decides: iPAddress SANs pass; a dNSName spelling the
 * address, a wildcard and a CN without SAN do not (RFC 9525 6.3). */
static void ip_names(int port)
{
	static const struct {
		const char *cert, *host, *url_host, *msg;
		bool ok;
	} C[] = {
		{ "ip-v4.cert.pem", "127.0.0.1", "127.0.0.1", "ip: iPAddress SAN 127.0.0.1 matches", true },
		{ "ip-v6.cert.pem", "::1", "[::1]", "ip: iPAddress SAN ::1 matches [::1]", true },
		{ "ip-v4.cert.pem", "::1", "[::1]", "ip: an iPAddress SAN of another address does not", false },
		{ "ip-dns.cert.pem", "127.0.0.1", "127.0.0.1", "ip: a dNSName spelling the address does not match", false },
		{ "ip-wild.cert.pem", "127.0.0.1", "127.0.0.1", "ip: a wildcard dNSName does not match", false },
		{ "ip-cn.cert.pem", "127.0.0.1", "127.0.0.1", "ip: a CN without SAN does not match", false },
	};
	const char *hdrs[] = { NULL };
	size_t i;

	for (i = 0; i < sizeof(C) / sizeof(C[0]); i++) {
		char url[128], ca[512];
		pid_t pid = server_ex(port + 1 + (int)i, C[i].cert, C[i].host);
		http_tls t;
		http_resp r;
		int rc;

		memset(&t, 0, sizeof(t));
		snprintf(ca, sizeof(ca), "%s/%s", FIXTURES, C[i].cert);
		t.ca_file = ca;
		snprintf(url, sizeof(url), "https://%s:%d/x", C[i].url_host, port + 1 + (int)i);
		rc = http_post(url, hdrs, (const uint8_t *)"x", 1, &t, &r);
		if (C[i].ok)
			OK(pid > 0 && rc == 0 && r.status == 200, C[i].msg);
		else
			OK(pid > 0 && rc < 0 && strstr(r.error, "this address"), C[i].msg);
		if (rc != 0 && C[i].ok)
			fprintf(stderr, "  error: %s\n", r.error);
		db_free(&r.body);
		if (pid > 0) {
			kill(pid, SIGTERM);
			waitpid(pid, NULL, 0);
		}
	}
}

/* one response through the parser; the body is compared when want is set */
struct pcase {
	const char *name, *in, *want;
	int rc, status;
};

static const struct pcase PARSE[] = {
	/* the chunk size of the R9 finding: ULONG_MAX + 2 wrapped to 1, the
	 * bound check passed and the copy ran off the heap */
	{ "chunk size 2^64-1 (overflow reproducer)",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nffffffffffffffff\r\nAB\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunk size 2^64-1 after a chunk (memcpy of SIZE_MAX under the old reader)",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nX\r\nffffffffffffffff\r\nAB\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunk size 2^64-2 (wraps to 0)",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffe\r\n\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunk size of 17 digits",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n00000000000000003\r\nabc\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunk size 2^32+3 (a 32-bit size_t would read 3)",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n100000003\r\nabc\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunk size larger than the data",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nabc\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "not a chunk size is an error, not the last chunk",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n", NULL, -1, 0 },
	{ "a negative chunk size",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nabc\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "no CRLF after the chunk data",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcX\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunk data ends at the buffer end",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc", NULL, -1, 0 },
	{ "no last chunk", "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n", NULL, -1, 0 },
	{ "last chunk without the empty line",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n", NULL, -1, 0 },
	{ "chunk extensions are ignored, trailers read past",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3 ;a=b;c\r\nabc\r\n2\r\nde\r\n0;x\r\nT: 1\r\n\r\n",
	  "abcde", 0, 200 },
	{ "something other than an extension after the size",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3x\r\nabc\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunked is case-insensitive",
	  "HTTP/1.1 200 OK\r\ntransfer-encoding:  Chunked \r\n\r\n1\r\na\r\n0\r\n\r\n", "a", 0, 200 },
	{ "chunked not the final coding",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n1\r\na\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "a coding ipad does not decode",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n1\r\na\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunked as a substring is not chunked",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: xchunkedx\r\n\r\n1\r\na\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "chunked twice",
	  "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "Transfer-Encoding with Content-Length",
	  "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "Transfer-Encoding in HTTP/1.0",
	  "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\na\r\n0\r\n\r\n", NULL, -1, 0 },
	{ "Content-Length", "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi and more", "hi", 0, 200 },
	{ "Content-Length list of equal values", "HTTP/1.1 200 OK\r\nContent-Length: 2, 2\r\n\r\nhi", "hi", 0, 200 },
	{ "Content-Length list of different values", "HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\nhi!", NULL, -1, 0 },
	{ "two different Content-Length fields",
	  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nhi!", NULL, -1, 0 },
	{ "negative Content-Length", "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\nhi", NULL, -1, 0 },
	{ "Content-Length not a number", "HTTP/1.1 200 OK\r\nContent-Length: 2x\r\n\r\nhi", NULL, -1, 0 },
	{ "empty Content-Length", "HTTP/1.1 200 OK\r\nContent-Length:\r\n\r\nhi", NULL, -1, 0 },
	{ "Content-Length beyond 64 bits",
	  "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551618\r\n\r\nhi", NULL, -1, 0 },
	{ "Content-Length longer than the body", "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nhi", NULL, -1, 0 },
	{ "read to close", "HTTP/1.1 200 OK\r\nX: y\r\n\r\nhi", "hi", 0, 200 },
	{ "status without a reason phrase", "HTTP/1.1 404\r\n\r\n", "", 0, 404 },
	{ "status of two digits", "HTTP/1.1 20 OK\r\n\r\n", NULL, -1, 0 },
	{ "status out of range", "HTTP/1.1 600 X\r\n\r\n", NULL, -1, 0 },
	{ "status with a sign", "HTTP/1.1 +20 OK\r\n\r\n", NULL, -1, 0 },
	{ "HTTP/2 status line", "HTTP/2 200 OK\r\n\r\n", NULL, -1, 0 },
	{ "no header end", "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n", NULL, -1, 0 },
	{ "1xx answers are skipped",
	  "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: x\r\n\r\n"
	  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", "hi", 0, 200 },
	{ "only a 1xx answer", "HTTP/1.1 100 Continue\r\n\r\n", NULL, -1, 0 },
	{ "101 Switching Protocols", "HTTP/1.1 101 Switching\r\n\r\nHTTP/1.1 200 OK\r\n\r\n", NULL, -1, 0 },
	{ "204 has no body", "HTTP/1.1 204 No Content\r\nContent-Length: 2\r\n\r\nhi", "", 0, 204 },
	{ "whitespace before the colon", "HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\nhi", NULL, -1, 0 },
	{ "obs-fold on Content-Length",
	  "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n 3\r\n\r\nhi!", NULL, -1, 0 },
	{ "obs-fold elsewhere", "HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 2\r\n\r\nhi", "hi", 0, 200 },
	{ "a field behind a bare LF",
	  "HTTP/1.1 200 OK\r\nX: a\nContent-Length: 1\r\n\r\nhi", NULL, -1, 0 },
	{ "a field line without a colon", "HTTP/1.1 200 OK\r\nbroken\r\n\r\nhi", NULL, -1, 0 },
};

static long retry_after(const char *in)
{
	http_resp r;
	long v = -2;

	memset(&r, 0, sizeof(r));
	db_init(&r.body);
	if (http_parse_response((const uint8_t *)in, strlen(in), &r) == 0)
		v = r.retry_after;
	db_free(&r.body);
	return v;
}

static void parse_cases(void)
{
	size_t i;

	for (i = 0; i < sizeof(PARSE) / sizeof(PARSE[0]); i++) {
		const struct pcase *c = &PARSE[i];
		/* a copy of just the bytes, so ASan sees any read past the end */
		size_t n = strlen(c->in);
		uint8_t *buf = malloc(n ? n : 1);
		http_resp r;
		int rc;

		memcpy(buf, c->in, n);
		memset(&r, 0, sizeof(r));
		db_init(&r.body);
		rc = http_parse_response(buf, n, &r);
		OK(rc == c->rc, c->name);
		if (rc == 0 && c->rc == 0) {
			OK(r.status == c->status, c->name);
			if (c->want && *c->want)
				EQ_HEX(r.body.d, r.body.len, c->want, strlen(c->want), c->name);
			else if (c->want)
				OK(r.body.len == 0, c->name);
		}
		db_free(&r.body);
		free(buf);
	}
	/* Retry-After: delay-seconds only, bounded at a day */
	OK(retry_after("HTTP/1.1 429 Too Many\r\nRetry-After: 120\r\n\r\n") == 120, "Retry-After: seconds");
	OK(retry_after("HTTP/1.1 429 Too Many\r\n\r\n") == -1, "Retry-After: absent");
	OK(retry_after("HTTP/1.1 103 Early Hints\r\nRetry-After: 5\r\n\r\nHTTP/1.1 429 Too Many\r\n\r\n") == -1,
	   "Retry-After: one on a 1xx is not the final answer's");
	OK(retry_after("HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 429 Too Many\r\nRetry-After: 7\r\n\r\n") == 7,
	   "Retry-After: the final answer's after a 1xx");
	OK(retry_after("HTTP/1.1 429 Too Many\r\nRetry-After: Fri, 31 Dec 2027 23:59:59 GMT\r\n\r\n") == -1,
	   "Retry-After: a date is not read");
	OK(retry_after("HTTP/1.1 429 Too Many\r\nRetry-After:\r\n\r\n") == -1, "Retry-After: empty");
	OK(retry_after("HTTP/1.1 429 Too Many\r\nRetry-After: -5\r\n\r\n") == -1, "Retry-After: negative");
	OK(retry_after("HTTP/1.1 429 Too Many\r\nRetry-After: 86401\r\n\r\n") == -1, "Retry-After: over a day");
	OK(retry_after("HTTP/1.1 429 Too Many\r\nRetry-After: 99999999999999999999999\r\n\r\n") == -1,
	   "Retry-After: no overflow");
}

struct ucase {
	const char *url;
	int rc;
	const char *host, *port, *sni, *host_hdr, *path;
};

static const struct ucase URLS[] = {
	{ "https://eim.example/gsma/rsp2/asn1", 0, "eim.example", "443", "eim.example", "eim.example", "/gsma/rsp2/asn1" },
	{ "https://eim.example", 0, "eim.example", "443", "eim.example", "eim.example", "/" },
	/* RFC 9110 7.2: the port in Host unless it is the default */
	{ "https://eim.example:8443/x", 0, "eim.example", "8443", "eim.example", "eim.example:8443", "/x" },
	{ "https://eim.example:443/x", 0, "eim.example", "443", "eim.example", "eim.example", "/x" },
	{ "http://eim.example:443/x", 0, "eim.example", "443", "eim.example", "eim.example:443", "/x" },
	/* RFC 6066 3: no trailing dot in SNI, no IP literal */
	{ "https://eim.example./x", 0, "eim.example.", "443", "eim.example", "eim.example.", "/x" },
	{ "https://192.0.2.1:8443/x", 0, "192.0.2.1", "8443", "", "192.0.2.1:8443", "/x" },
	{ "https://[2001:db8::1]/x", 0, "2001:db8::1", "443", "", "[2001:db8::1]", "/x" },
	{ "https://[2001:db8::1]:8443/x", 0, "2001:db8::1", "8443", "", "[2001:db8::1]:8443", "/x" },
	{ "https://[::ffff:192.0.2.1]/", 0, "::ffff:192.0.2.1", "443", "", "[::ffff:192.0.2.1]", "/" },
	/* four numbers are an address, anything else a name */
	{ "https://192.0.2.1.example/", 0, "192.0.2.1.example", "443", "192.0.2.1.example", "192.0.2.1.example", "/" },
	/* an address in another spelling would reach getaddrinfo as a name
	 * and come back as the address it spells to inet_aton */
	{ "https://127.1/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://2130706433/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://0x7f.1/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://0x7f000001/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://0177.0.0.1/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://010.0.0.1/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://127.0.0.1./", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://1.2.3.4.5/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://example.123/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://10.0.0.0/", 0, "10.0.0.0", "443", "", "10.0.0.0", "/" },
	{ "https://cafe/", 0, "cafe", "443", "cafe", "cafe", "/" },
	{ "https://0xcafe.example/", 0, "0xcafe.example", "443", "0xcafe.example", "0xcafe.example", "/" },
	/* brackets hold an IPv6 address and nothing else */
	{ "https://[cafe.de]/x", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://[1.2.3.4]/x", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://[:::::]/x", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://[::]/x", 0, "::", "443", "", "[::]", "/x" },
	/* a query needs a path before it, a fragment is never sent */
	{ "https://eim.example?q=1", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example/x#f", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example#f", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example/x?q=1", 0, "eim.example", "443", "eim.example", "eim.example", "/x?q=1" },
	{ "https://[2001:db8::1/x", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://[2001:db8::1]x/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://[fe80::1%25eth0]/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example:0/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example:65536/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example:/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example:44x/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://user@eim.example/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim.example\r\nX: y/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://eim example/", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https:///x", -1, NULL, NULL, NULL, NULL, NULL },
	{ "https://./x", -1, NULL, NULL, NULL, NULL, NULL },
	{ "ftp://eim.example/", -1, NULL, NULL, NULL, NULL, NULL },
};

static void url_cases(void)
{
	size_t i;

	for (i = 0; i < sizeof(URLS) / sizeof(URLS[0]); i++) {
		const struct ucase *c = &URLS[i];
		http_url u;
		int rc = http_split_url(c->url, &u);

		OK(rc == c->rc, c->url);
		if (rc == 0 && c->rc == 0)
			OK(!strcmp(u.host, c->host) && !strcmp(u.port, c->port) && !strcmp(u.sni, c->sni) &&
			   !strcmp(u.host_hdr, c->host_hdr) && !strcmp(u.path, c->path), c->url);
	}
}

/* a server that answers and keeps the connection open (tests/hold_open.py):
 * the answer ends where its framing says, not at the read timeout */
static void hold_open(void)
{
	int fd[2];
	pid_t pid = -1;
	char port[16] = { 0 }, url[128];
	static const char *const paths[] = { "cl", "chunked" };
	http_tls t;
	http_resp r;
	size_t i;

	if (pipe(fd) == 0 && (pid = fork()) == 0) {
		dup2(fd[1], 1);
		execlp("python3", "python3", TESTS "/hold_open.py", (char *)NULL);
		_exit(127);
	}
	close(fd[1]);
	OK(pid > 0 && read(fd[0], port, sizeof(port) - 1) > 0, "hold_open: server started");
	close(fd[0]);
	port[strcspn(port, "\n")] = 0;
	memset(&t, 0, sizeof(t));
	t.timeout_ms = 5000;
	for (i = 0; i < 2; i++) {
		struct timespec a, b;
		char msg[80];

		snprintf(url, sizeof(url), "http://127.0.0.1:%s/%s", port, paths[i]);
		clock_gettime(CLOCK_MONOTONIC, &a);
		snprintf(msg, sizeof(msg), "hold_open %s: read without waiting for the close", paths[i]);
		OK(http_post(url, NULL, (const uint8_t *)"x", 1, &t, &r) == 0 && r.status == 200 && r.body.len == 2 &&
		   !memcmp(r.body.d, "ok", 2), msg);
		clock_gettime(CLOCK_MONOTONIC, &b);
		snprintf(msg, sizeof(msg), "hold_open %s: well within the read timeout", paths[i]);
		OK(b.tv_sec - a.tv_sec < 2, msg);
		db_free(&r.body);
	}
	/* no framing: the close ends it, as before */
	snprintf(url, sizeof(url), "http://127.0.0.1:%s/close", port);
	OK(http_post(url, NULL, (const uint8_t *)"x", 1, &t, &r) == 0 && r.body.len == 2, "hold_open: read to close");
	db_free(&r.body);
	if (pid > 0) {
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}
}

int main(void)
{
	uint8_t ca[2048], pin[256], bad[256];
	size_t ca_len = slurp("server.cert.der", ca, sizeof(ca));
	size_t pin_len = slurp("server.spki.der", pin, sizeof(pin));
	size_t bad_len = slurp("prime256v1.spki.der", bad, sizeof(bad));
	int port = 20000 + (getpid() % 20000);
	pid_t pid = server(port);
	const char *hdrs[] = { "Content-Type: application/x-gsma-rsp-asn1",
	                       "X-Admin-Protocol: gsma/rsp/v1.3.0", NULL };
	const char want[] = "echo:application/x-gsma-rsp-asn1|gsma/rsp/v1.3.0|\xBF\x4F\x00";
	uint8_t body[] = { 0xBF, 0x4F, 0x00 };
	char url[128];
	http_resp r;
	http_tls t;

	parse_cases();
	url_cases();
	hold_open();

	OK(pid > 0, "server started");

	/* trusted through its CA (self-signed: the cert is its own CA) */
	memset(&t, 0, sizeof(t));
	t.ca_der = ca;
	t.ca_der_len = ca_len;
	snprintf(url, sizeof(url), "https://localhost:%d/gsma/rsp2/asn1", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) == 0 && r.status == 200, "ca: 200");
	EQ_HEX(r.body.d, r.body.len, want, sizeof(want) - 1, "ca: headers and body round trip");
	db_free(&r.body);

	/* chunked answer */
	snprintf(url, sizeof(url), "https://localhost:%d/chunked", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) == 0, "chunked: read");
	EQ_HEX(r.body.d, r.body.len, want, sizeof(want) - 1, "chunked: reassembled");
	db_free(&r.body);

	/* Host carries a port that is not the default (RFC 9110 7.2) */
	snprintf(url, sizeof(url), "https://localhost:%d/host", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) == 0, "host: read");
	{
		char h[64];

		snprintf(h, sizeof(h), "localhost:%d", port);
		EQ_HEX(r.body.d, r.body.len, h, strlen(h), "host: the port is in Host");
	}
	db_free(&r.body);

	/* a trailing dot is a name the certificate (localhost) still matches:
	 * it is removed from SNI and from the name checked */
	snprintf(url, sizeof(url), "https://localhost.:%d/gsma/rsp2/asn1", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) == 0 && r.status == 200, "name: a trailing dot is not part of it");
	db_free(&r.body);

	/* a request head that does not fit is refused, not overrun */
	{
		static char big[3000];
		const char *bh[] = { big, NULL };

		memset(big, 'a', sizeof(big) - 1);
		memcpy(big, "X-Big: ", 7);
		OK(http_post(url, bh, body, sizeof(body), &t, &r) < 0 && strstr(r.error, "too long"), "headers: too long is an error");
		db_free(&r.body);
	}

	/* pinned server key, no CA needed */
	memset(&t, 0, sizeof(t));
	t.pin_spki = pin;
	t.pin_spki_len = pin_len;
	snprintf(url, sizeof(url), "https://localhost:%d/gsma/rsp2/asn1", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) == 0 && r.status == 200, "pin: the right key passes");
	db_free(&r.body);

	t.pin_spki = bad;
	t.pin_spki_len = bad_len;
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) < 0, "pin: another key is refused");
	db_free(&r.body);

	/* the CA is right but the name is not: 127.0.0.1 is not in the SAN. An IP
	 * literal goes out without SNI (RFC 6066 3); its address is checked
	 * against the certificate after the handshake */
	memset(&t, 0, sizeof(t));
	t.ca_der = ca;
	t.ca_der_len = ca_len;
	snprintf(url, sizeof(url), "https://127.0.0.1:%d/gsma/rsp2/asn1", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) < 0 && strstr(r.error, "this address"),
	   "name: a certificate for another name is refused");
	db_free(&r.body);

	/* an unknown CA (the system bundle does not know this self-signed cert) */
	memset(&t, 0, sizeof(t));
	snprintf(url, sizeof(url), "https://localhost:%d/gsma/rsp2/asn1", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) < 0, "ca: an unknown issuer is refused");
	db_free(&r.body);

	if (pid > 0) {
		kill(pid, SIGTERM);
		waitpid(pid, NULL, 0);
	}
	ip_names(port);
	DONE("test_http");
}
