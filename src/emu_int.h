/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * Internals of the emulation, shared by emu.c (the ES10 functions) and
 * emu_state.c (the state and the eIM configuration records).
 */
#ifndef IPAD_EMU_INT_H
#define IPAD_EMU_INT_H

#include <stdbool.h>
#include "emu.h"
#include "der.h"

#define EMU_MAX_EIMS 8
#define EMU_MAX_EPRS 16

/* what a card refused once and is not asked again (state: quirks [9]) */
#define EMU_Q_NO_9F67 1        /* GetProfilesInfo with 5C { 5A 9F70 9F67 } */
#define EMU_Q_NO_IOT_TAGS 2    /* a listProfileInfo tag list with 9F7B / 9F67 */

typedef struct {
	dbuf cfg;              /* EimConfigurationData, universal SEQUENCE form */
	char id[129];
	int64_t counter;       /* replay counter (section 5.9.1) */
	bool has_token;
	int64_t token;         /* associationToken */
	crypto_key *pub;       /* eimPublicKey / eimCertificate key, NULL if none */
} emu_eim;

struct emu {
	card *card;
	emu_config cfg;
	char *state_path;                /* our copy: cfg.state_path need not outlive emu_open */
	uint8_t eid[16];

	emu_eim eims[EMU_MAX_EIMS];
	int neims;

	int64_t seq;                     /* last sequence number used */
	dbuf eprs[EMU_MAX_EPRS];         /* stored signed EPRs, BF51 ... */
	int64_t epr_seq[EMU_MAX_EPRS];
	int neprs;

	/* Profile Rollback (sections 3.3.2, 5.9.16): granted by an enable with
	 * rollbackFlag that the card carried out, reset by the next eUICC
	 * Package */
	bool rb_granted;
	uint8_t rb_iccid[10];            /* the profile to go back to */
	char rb_eim[129];
	int64_t rb_counter;
	uint8_t rb_txid[16];
	size_t rb_txid_len;
	int64_t rb_epr_seq;              /* the EPR a successful rollback discards (3.3.2 NOTE1) */

	/* Fallback (sections 3.4.6, 3.4.7, 5.9.20, 5.9.21) */
	bool fb_set;
	uint8_t fb_iccid[10];
	/* the profile ExecuteFallbackMechanism disabled, to return to; an eIM
	 * enable clears it (3.4.1 step 3). Whether the Fallback Profile is
	 * enabled is not kept: the card says (emu.c fallback_prof) */
	bool fb_prev_set;
	uint8_t fb_prev[10];

	/* Immediate Profile Enabling (sections 3.4.4, 3.4.5, 5.9.15) */
	bool ie_flag;
	dbuf ie_oid, ie_addr;
	bool ie_ctx;                     /* a download just completed */
	uint8_t ie_iccid[10];

	int64_t token_ctr;               /* associationToken generation */

	int quirks;                      /* EMU_Q_* */
};

/* state file */
int emu_state_load(emu *e);
int emu_state_save(const emu *e);

/* eIM configuration records */
int emu_eim_from_cfg(emu_eim *m, const uint8_t *cfg, size_t len);   /* cfg: 30 ... */
void emu_eim_free(emu_eim *m);
emu_eim *emu_eim_find(emu *e, const char *id);

/* the associationToken data object for signing: 84 <token> or 84 01 00 */
void emu_assoc_do(const emu_eim *m, dbuf *b);

#endif
