/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The IPA procedures of SGP.32 v1.3 over ESipa (HTTPS, ASN.1 binding):
 * eIM Package retrieval (3.1.1.1) and execution (3.3.1), Profile Rollback
 * (3.3.2), IPA/eUICC data (2.11.1.2), direct and indirect Profile download
 * (3.2.3.1, 3.2.3.2, cancel 3.2.3.3) and Notification delivery (3.7).
 *
 * Everything card-side goes through euicc_es10, so the procedures are the
 * same for an IoT eUICC and for the SGP.22 emulation. What only the device
 * can do, resetting the SIM after a profile change and waiting for the
 * connection, running a direct download through lpac, applying connectivity
 * parameters, is asked of the host through ipa_host.
 */
#ifndef IPAD_IPA_H
#define IPAD_IPA_H

#include <stdbool.h>
#include "euicc.h"
#include "http.h"
#include "connectivity.h"

typedef struct {
	/* The enabled profile changed (enable/disable/rollback/fallback): the
	 * host makes the modem see it (SIM reset) and waits for the data
	 * connection. iccid is the now-enabled profile, "" when none. Returns
	 * true once the device is online again. NULL: assumed online. */
	bool (*profile_changed)(void *ud, const char *iccid);
	/* Direct download (3.2.3.1) through the host's ES9+ client, with the
	 * Profile Installation Result left on the card (no auto notify): ipad
	 * reports it. cc may be NULL. 0 on success. NULL: direct download is
	 * not offered in the IPA capabilities. */
	int (*download)(void *ud, const char *activation_code, const char *cc);
	/* GetConnectivityParameters of the enabled profile (5.9.24): p NULL when
	 * the card has none; emulated says why (an SGP.22 card never has any). */
	void (*connectivity)(void *ud, const char *iccid, const conn_params *p, bool emulated);
	void (*log)(void *ud, int level, const char *msg);   /* syslog levels */
	void *ud;
} ipa_host;

/* Test seam: one ESipa exchange. status 200 with a body, 204 without. */
typedef int (*ipa_transport)(void *ud, const uint8_t *req, size_t len, int *status, dbuf *resp);

typedef struct {
	euicc *eu;
	const char *eim_id;        /* which configured eIM; NULL: the first with an FQDN */
	const char *eim_url;       /* override for https://<eimFqdn>/gsma/rsp2/asn1 */
	http_tls tls;              /* ca_file etc.; the pin/CA from the eIM config win */
	uint8_t tac[4];            /* DeviceInfo (SGP.22 4.2) */
	uint8_t imei[8];
	bool has_imei;
	int max_packages;          /* per poll, default 16 */
	int state_change_cause;    /* next poll notifies a state change; -1 none */
	uint8_t rplmn[3];
	bool has_rplmn;
	ipa_host host;
	ipa_transport transport;   /* NULL: HTTPS */
	void *transport_ud;
} ipa_config;

typedef struct ipa ipa;

/* Reads the EID and the eIM configuration; NULL when no eIM is configured
 * (provision one first) or the card does not answer. */
ipa *ipa_open(const ipa_config *cfg);
void ipa_close(ipa *a);

typedef struct {
	int packages, acknowledged, downloads, notifications;
	bool profile_changed;
	bool rolled_back;
} ipa_summary;

/* Retrieves and executes eIM Packages until the eIM has none left, then
 * delivers pending Notifications. 0 when the eIM was reached. */
int ipa_poll(ipa *a, ipa_summary *sum);

/* 3.7 on its own: every pending Notification over ESipa.HandleNotification,
 * removed from the card once the eIM took it. Returns how many went out. */
int ipa_deliver_notifications(ipa *a);

/* Hands the enabled profile's connectivity parameters to the host. */
int ipa_connectivity(ipa *a);

/* AddInitialEim (5.9.17) from an EimConfigurationData (30 ...), a whole
 * AddInitialEimRequest (BF57 ...) or a GetEimConfigurationDataResponse
 * (BF55 ..., another IPA's export) */
int ipa_add_initial_eim(euicc *eu, const uint8_t *cfg, size_t len, char *err, size_t errlen);

/* IpaCapabilities (4.1) under `tag` (A8 in IpaEuiccData, 30 on its own) */
void ipa_put_capabilities(dbuf *b, uint32_t tag, bool direct);

const uint8_t *ipa_eid(const ipa *a);
const char *ipa_url(const ipa *a);
const char *ipa_eim_id(const ipa *a);   /* the configured eIM this IPA talks to */
const http_tls *ipa_tls(const ipa *a);   /* with the eIM's pin/CA applied */

/* The ICCID of the enabled profile as a string, "" when none; -1 on error */
int ipa_enabled_iccid(euicc *eu, char out[21]);

#endif
