/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The host link over stdin/stdout, one JSON object per line.
 *
 * APDUs use lpac's stdio driver protocol (lpac v2.3.0 driver/apdu/stdio.c),
 * so wwand's esim_bridge relays them over the modem's channel exactly as it
 * does for lpac:
 *   out {"type":"apdu","payload":{"func":"transmit","param":"<hex>"}}
 *   in  {"type":"apdu","payload":{"ecode":0,"data":"<hex incl. SW>"}}
 * with func connect / logic_channel_open (param AID, ecode = channel) /
 * transmit / logic_channel_close / disconnect.
 *
 * Steps only the host can take go out as events, and ipad waits for the one
 * answer line (esim_bridge session_run on_event):
 *   {"type":"event","payload":{"event":"profile_changed","iccid":"..."}}
 *       -> {"online":true|false}
 *   {"type":"event","payload":{"event":"download","activation_code":"..."}}
 *       -> {"ok":true} | {"ok":false,"error":"..."}
 *   {"type":"event","payload":{"event":"connectivity","iccid":"...",
 *       "emulated":bool,"source":"card"|"none","apn":"...","username":"...",
 *       "password":"...","pdp_type":"ipv4"|...}}   -> {}
 *   {"type":"event","payload":{"event":"info","eid":"...","backend":
 *       "iot"|"emulated","key_fingerprint":"<sha256 of the SPKI>"}}  -> {}
 *       at the start of every run that reached the card, so the host can
 *       show what it manages without a session of its own
 */
#ifndef IPAD_HOST_H
#define IPAD_HOST_H

#include <stdio.h>
#include "card.h"
#include "ipa.h"

typedef struct {
	FILE *in, *out;
	char *line;          /* getline buffer */
	size_t cap;
	int channel;
} host_link;

extern const card_ops HOST_CARD_OPS;

void host_init(host_link *h, FILE *in, FILE *out);
void host_free(host_link *h);

/* the ipa_host callbacks over this link; log goes to syslog (and stderr
 * when verbose) */
void host_ipa_hooks(host_link *h, ipa_host *hooks, int verbose);

/* the info event; fp NULL for an IoT eUICC (it has no device key) */
void host_event_info(host_link *h, const char *eid, const char *backend, const char *fp);

/* JSON string body with the escapes RFC 8259 requires */
void host_json_str(FILE *f, const char *s);

#endif
