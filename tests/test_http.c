/* SPDX-License-Identifier: GPL-2.0-only
 * http.c against a local HTTPS stand-in (tests/tls_echo.py): the ESipa
 * headers arrive, bodies come back (Content-Length and chunked), and server
 * trust holds: the right CA or pin passes, a wrong pin or name does not. */
#include <stdlib.h>
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

static pid_t server(int port)
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
		snprintf(cert, sizeof(cert), "%s/server.cert.pem", FIXTURES);
		snprintf(key, sizeof(key), "%s/server.key.pem", FIXTURES);
		execlp("python3", "python3", TESTS "/tls_echo.py", p, cert, key, (char *)NULL);
		_exit(127);
	}
	close(fd[1]);
	if (read(fd[0], ready, sizeof(ready) - 1) <= 0)
		return -1;
	close(fd[0]);
	return pid;
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

	/* the CA is right but the name is not: 127.0.0.1 is not in the SAN */
	memset(&t, 0, sizeof(t));
	t.ca_der = ca;
	t.ca_der_len = ca_len;
	snprintf(url, sizeof(url), "https://127.0.0.1:%d/gsma/rsp2/asn1", port);
	OK(http_post(url, hdrs, body, sizeof(body), &t, &r) < 0, "name: a certificate for another name is refused");
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
	DONE("test_http");
}
