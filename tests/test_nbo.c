/* SPDX-License-Identifier: GPL-2.0-only
 * The notification backoff on its own (nbo.h): delays, the file, the
 * fingerprints. How ipa.c applies it is in test_ipa. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "check.h"
#include "nbo.h"

int main(void)
{
	static const int64_t want[] = { 7200, 14400, 28800, 57600, 86400, 86400 };
	static const uint8_t cfg1[] = { 0xBF, 0x55, 0x02, 0xA0, 0x00 }, cfg2[] = { 0xBF, 0x55, 0x03, 0xA0, 0x01, 0x00 };
	static const uint8_t md38[] = { 0xBF, 0x2F, 0x03, 0x80, 0x01, 0x26 }, md38b[] = { 0xBF, 0x2F, 0x04, 0x80, 0x01, 0x26, 0x0C };
	char path[] = "/tmp/ipad-test-nbo-XXXXXX";
	const int64_t t0 = 1790000000, only61[] = { 61 };
	int64_t t = t0;
	uint8_t e1[8], e2[8], f38[8], f38b[8], f61[8];
	size_t i;
	bool ok = true;
	nbo b;
	FILE *f;

	close(mkstemp(path));
	unlink(path);
	nbo_fp(cfg1, sizeof(cfg1), e1);
	nbo_fp(cfg2, sizeof(cfg2), e2);
	nbo_fp(md38, sizeof(md38), f38);
	nbo_fp(md38b, sizeof(md38b), f38b);
	memset(f61, 0x61, sizeof(f61));

	nbo_load(&b, path);
	nbo_eims(&b, e1);
	OK(b.n == 0 && access(path, F_OK) != 0, "nbo: no file, no record, nothing written");
	OK(nbo_due(&b, 38, f38, t0), "nbo: a notification never refused is due");
	OK(nbo_refused(&b, 38, f38, t0) == NBO_FIRST, "nbo: an hour after the first refusal");
	OK(!nbo_due(&b, 38, f38, t0 + NBO_FIRST - 1) && nbo_due(&b, 38, f38, t0 + NBO_FIRST),
	   "nbo: held for the hour, due after it");
	OK(nbo_due(&b, 61, f61, t0), "nbo: per notification");
	for (i = 0; i < sizeof(want) / sizeof(want[0]); i++) {
		t += NBO_CAP;
		ok = ok && nbo_refused(&b, 38, f38, t) == want[i];
	}
	OK(ok, "nbo: doubling, capped at a day");

	/* a reused seqNumber is another notification: not held, and its
	 * refusal starts from the first delay */
	OK(nbo_due(&b, 38, f38b, t), "nbo: the same seqNumber with other metadata is due");
	OK(nbo_refused(&b, 38, f38b, t) == NBO_FIRST && b.n == 1, "nbo: its refusal starts afresh, one record");
	OK(nbo_due(&b, 38, f38, t), "nbo: the old notification's record is gone with it");
	t += NBO_CAP;
	nbo_refused(&b, 38, f38, t);
	nbo_refused(&b, 38, f38, t);   /* back at two hours, to see it survive the file */

	nbo_load(&b, path);
	nbo_eims(&b, e1);
	OK(b.n == 1 && !nbo_due(&b, 38, f38, t + 2 * NBO_FIRST - 1) && nbo_due(&b, 38, f38, t + 2 * NBO_FIRST),
	   "nbo: kept in the file across a restart");
	OK(nbo_due(&b, 38, f38, t0), "nbo: a clock gone back does not hold it longer than the cap");

	nbo_refused(&b, 61, f61, t);
	nbo_keep(&b, only61, 1);
	OK(nbo_due(&b, 38, f38, t) && !nbo_due(&b, 61, f61, t), "nbo: the record of one no longer on the card is dropped");

	/* another eIM configuration: every record forgotten, in the file too */
	nbo_eims(&b, e2);
	OK(nbo_due(&b, 61, f61, t) && access(path, F_OK) != 0, "nbo: forgotten once the eIM configurations changed");
	nbo_refused(&b, 61, f61, t);
	nbo_load(&b, path);
	nbo_eims(&b, e2);
	OK(!nbo_due(&b, 61, f61, t), "nbo: under the new configurations, recorded again");
	nbo_load(&b, path);
	nbo_eims(&b, e1);
	OK(nbo_due(&b, 61, f61, t), "nbo: a file of other configurations holds nothing");

	/* a damaged file is no record, and no reason to fail */
	f = fopen(path, "w");
	fprintf(f, "ipad-nbo/1 zz\n61 1 1 0000000000000000\n");
	fclose(f);
	nbo_load(&b, path);
	OK(b.n == 0, "nbo: a damaged header, no record");
	f = fopen(path, "w");
	fprintf(f, "ipad-nbo/1 0000000000000000\n61 x 1 0000000000000000\n62 %lld 3600 6161616161616161\n",
	        (long long)(t + 10));
	fclose(f);
	nbo_load(&b, path);
	OK(b.n == 1 && b.r[0].seq == 62, "nbo: a damaged line skipped, the next read");

	/* no path: kept for the run only */
	unlink(path);
	nbo_load(&b, NULL);
	nbo_refused(&b, 61, f61, t);
	OK(!nbo_due(&b, 61, f61, t) && access(path, F_OK) != 0, "nbo: without a path in memory only");

	/* full: the oldest record goes */
	nbo_load(&b, NULL);
	for (i = 0; i < NBO_MAX + 1; i++)
		nbo_refused(&b, (int64_t)i, f61, t);
	OK(b.n == NBO_MAX && nbo_due(&b, 0, f61, t) && !nbo_due(&b, NBO_MAX, f61, t), "nbo: full, the oldest goes");

	/* the file is 0600 whatever the umask, and a link planted at the
	 * temporary name is not followed */
	{
		char tmp[64], target[64];
		struct stat st;
		mode_t old = umask(0);

		unlink(path);
		nbo_load(&b, path);
		nbo_eims(&b, e1);
		nbo_refused(&b, 61, f61, t);
		OK(stat(path, &st) == 0 && (st.st_mode & 07777) == 0600, "nbo: the file is 0600 under umask 0");

		/* a temporary a crash left with a wider mode keeps it under
		 * O_TRUNC unless the writer sets it */
		snprintf(tmp, sizeof(tmp), "%s.tmp", path);
		f = fopen(tmp, "w");
		fclose(f);
		chmod(tmp, 0666);
		nbo_refused(&b, 61, f61, t);
		OK(stat(path, &st) == 0 && (st.st_mode & 07777) == 0600, "nbo: 0600 over a stale temporary of 0666");

		snprintf(target, sizeof(target), "%s.target", path);
		unlink(target);
		OK(symlink(target, tmp) == 0, "nbo: a link at the temporary name");
		nbo_refused(&b, 38, f38, t);
		OK(access(target, F_OK) != 0, "nbo: the link is not followed");
		unlink(tmp);
		unlink(target);
		umask(old);
	}

	unlink(path);
	DONE("test_nbo");
}
