/* SPDX-License-Identifier: GPL-2.0-only
 * hostsim: wwand's side of ipad's stdio protocol (src/host.h), with the card
 * simulated (fake22: an SGP.22 consumer eUICC). Runs one or more ipad
 * commands in a row against the same card, so a provision, an export and a
 * poll see one card state:
 *
 *   hostsim [-o] [-a] [-E eid] [-P iccid[,iccid...]] -- ipad <args> [-- ipad <args> ...]
 *
 *   -E   the card's EID, 32 hex digits (default fake22's): several cards
 *        against one eIM, whose registrations outlive a test run
 *   -P   profiles on the card, the first enabled (default: two test ICCIDs)
 *   -o   answer profile_changed with online:false
 *   -a   refuse the download event
 *
 * What ipad says besides APDUs (events, result lines) goes to stdout, one
 * line each, prefixed "host: " for the events it answered.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "fake22.h"
#include "hex.h"

static fake22 fcard;
static simcard sim;
static int offline, refuse_download;

static const char *field(const char *s, const char *key, char *out, size_t cap)
{
	char k[40];
	const char *p, *e;

	snprintf(k, sizeof(k), "\"%s\":\"", key);
	out[0] = 0;
	if (!(p = strstr(s, k)))
		return NULL;
	p += strlen(k);
	if (!(e = strchr(p, '"')) || (size_t)(e - p) >= cap)
		return NULL;
	memcpy(out, p, (size_t)(e - p));
	out[e - p] = 0;
	return out;
}

static void apdu(const char *line, FILE *to)
{
	char func[40], param[2048];
	uint8_t bin[1024];
	int n, ch;
	dbuf r;

	field(line, "func", func, sizeof(func));
	field(line, "param", param, sizeof(param));
	n = param[0] ? hex_decode(param, bin, strlen(param) / 2) : 0;

	if (!strcmp(func, "logic_channel_open")) {
		ch = SIMCARD_OPS.open(&sim, bin, (size_t)(n > 0 ? n : 0));
		fprintf(to, "{\"type\":\"apdu\",\"payload\":{\"ecode\":%d,\"data\":\"\"}}\n", ch);
	} else if (!strcmp(func, "transmit")) {
		char *hx;

		db_init(&r);
		if (n <= 0 || SIMCARD_OPS.transmit(&sim, bin, (size_t)n, &r) < 0) {
			fprintf(to, "{\"type\":\"apdu\",\"payload\":{\"ecode\":-1,\"data\":\"\"}}\n");
		} else {
			hx = malloc(r.len * 2 + 1);
			hex_encode(r.d, r.len, hx);
			fprintf(to, "{\"type\":\"apdu\",\"payload\":{\"ecode\":0,\"data\":\"%s\"}}\n", hx);
			free(hx);
		}
		db_free(&r);
	} else {
		if (!strcmp(func, "logic_channel_close"))
			SIMCARD_OPS.close(&sim, sim.channel);
		fprintf(to, "{\"type\":\"apdu\",\"payload\":{\"ecode\":0,\"data\":\"\"}}\n");
	}
	fflush(to);
}

static void event(const char *line, FILE *to)
{
	char ev[40];

	field(line, "event", ev, sizeof(ev));
	printf("host: %s", line);
	if (!strcmp(ev, "profile_changed"))
		fprintf(to, "{\"type\":\"event\",\"payload\":{\"online\":%s}}\n", offline ? "false" : "true");
	else if (!strcmp(ev, "download"))
		fprintf(to, "{\"type\":\"event\",\"payload\":{\"ok\":%s}}\n", refuse_download ? "false" : "true");
	else
		fprintf(to, "{\"type\":\"event\",\"payload\":{}}\n");
	fflush(to);
}

static int run(char **argv)
{
	int in[2], out[2], st;
	pid_t pid;
	FILE *from, *to;
	char *line = NULL;
	size_t cap = 0;

	if (pipe(in) < 0 || pipe(out) < 0)
		return -1;
	if ((pid = fork()) == 0) {
		dup2(in[0], 0);
		dup2(out[1], 1);
		close(in[1]);
		close(out[0]);
		execv(argv[0], argv);
		perror(argv[0]);
		_exit(127);
	}
	close(in[0]);
	close(out[1]);
	to = fdopen(in[1], "w");
	from = fdopen(out[0], "r");
	while (getline(&line, &cap, from) > 0) {
		if (strstr(line, "\"type\":\"apdu\""))
			apdu(line, to);
		else if (strstr(line, "\"type\":\"event\""))
			event(line, to);
		else
			fputs(line, stdout);
		fflush(stdout);
	}
	free(line);
	fclose(to);
	fclose(from);
	waitpid(pid, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 128;
}

int main(int argc, char **argv)
{
	int i, rc = 0, opt;
	const char *profiles = "98001032547698103214,98001032547698103224", *eid = NULL;

	while ((opt = getopt(argc, argv, "oaE:P:")) != -1) {
		switch (opt) {
		case 'o': offline = 1; break;
		case 'a': refuse_download = 1; break;
		case 'E': eid = optarg; break;
		case 'P': profiles = optarg; break;
		default: return 2;
		}
	}

	fake22_init(&fcard);
	if (eid && (strlen(eid) != 32 || hex_decode(eid, fcard.eid, 16) != 16)) {
		fprintf(stderr, "hostsim: -E wants 32 hex digits\n");
		return 2;
	}
	{
		char buf[512], *tok, *save = NULL;
		int first = 1;

		snprintf(buf, sizeof(buf), "%s", profiles);
		for (tok = strtok_r(buf, ",", &save); tok; tok = strtok_r(NULL, ",", &save), first = 0)
			fake22_add(&fcard, tok, first);
	}
	simcard_init(&sim, 1, fake22_handler, &fcard);

	/* the commands: ipad argv's separated by "--" */
	for (i = optind; i < argc; ) {
		int j = i;

		if (!strcmp(argv[i], "--")) {
			i++;
			continue;
		}
		while (j < argc && strcmp(argv[j], "--"))
			j++;
		{
			char *av[64];
			int k, n = 0;

			for (k = i; k < j && n < 63; k++)
				av[n++] = argv[k];
			av[n] = NULL;
			int g0 = fcard.geteids, i0 = fcard.infos, d0 = fcard.infos_default;

			rc = run(av);
			printf("exit: %d\n", rc);
			/* what the run asked of the card, for tests/test_cli.sh */
			printf("card: geteid %d, profiles %d, default list %d\n", fcard.geteids - g0,
			       fcard.infos - i0, fcard.infos_default - d0);
			fflush(stdout);
		}
		i = j;
	}
	simcard_free(&sim);
	fake22_free(&fcard);
	return rc;
}
