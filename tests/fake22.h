/* SPDX-License-Identifier: GPL-2.0-only
 * A simulated SGP.22 consumer eUICC for the tests (behind simcard): profiles
 * with state, ES10c enable/disable/delete, GetEUICCData, GetProfilesInfo,
 * GetRAT, SetDefaultDpAddress, an empty notification list. It knows no
 * SGP.32 function, as a real SGP.22 card does not. */
#ifndef IPAD_FAKE22_H
#define IPAD_FAKE22_H
#include "simcard.h"

typedef struct {
	uint8_t eid[16];
	/* fallback_allowed: the profile's fallbackAllowed ('9F67', SGP.32 4.4),
	 * 0 absent, 1 TRUE, 2 FALSE; GetProfilesInfo reports it only when a tag
	 * list asks for it, as SGP.22 5.7.15 has no (*) on it */
	struct { uint8_t iccid[10]; int enabled; int present; int fallback_allowed; } p[16];
	int np;
	int enables, disables, deletes;   /* observed calls */
	/* a card that refuses: nonzero answers EnableProfile / DisableProfile /
	 * DeleteProfile with that result code and changes nothing */
	int refuse_enable, refuse_disable, refuse_delete;
	/* called before the card carries out an enable, disable or delete */
	void (*before_change)(void *arg);
	void *before_arg;
	/* a card that answers a GetProfilesInfo tag list naming an SGP.32 tag
	 * (9F26, 9F67, 9F7B) with an error status word, as one that does not
	 * know them may; other unknown tags are just not returned */
	int refuse_taglist;
	/* the tag list of the last GetProfilesInfo, and whether it had one */
	uint8_t last_taglist[32];
	size_t last_taglist_len;
	int last_had_taglist;
	int last_refresh;                 /* refreshFlag of the last enable/disable */
	char dp[64];

	/* pending notifications, as RetrieveNotificationsList hands them out */
	dbuf notes[8];
	int64_t note_seq[8];
	int nnotes;
	int64_t next_seq;

	/* download: the BPP segments seen ("BF36 A0 A1 88 A3 86 ..."), the
	 * sessions cancelled, and what the last segment installs */
	char segs[256];
	int cancels, cancel_reason;
	char install_iccid[21];   /* the profile a completed load adds */

	/* a real DER certificate, stands in for CERT.EUICC / CERT.EUM */
	const uint8_t *cert;
	size_t cert_len;
} fake22;

void fake22_init(fake22 *f);
int fake22_add(fake22 *f, const char *iccid_hex, int enabled);
uint16_t fake22_handler(simcard *s, const uint8_t *req, size_t len, dbuf *resp);
int fake22_enabled(const fake22 *f);
void fake22_free(fake22 *f);
/* an eIM test vector (tests/vectors.h) by type and label, decoded; 0 or -1 */
int fake22_vector(const char *type, const char *label, dbuf *out);
/* a PIR (BF37) for a finished install, stored as a notification; the seq */
int64_t fake22_add_pir(fake22 *f, const char *iccid_hex);
/* an OtherSignedNotification (30) for e.g. an enable */
int64_t fake22_add_other(fake22 *f);   /* index of the enabled profile, -1 none */
#endif
