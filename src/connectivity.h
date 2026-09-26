/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The Connectivity Parameters of the enabled Profile (ES10b.GetConnectivity-
 * Parameters, SGP.32 v1.3 section 5.9.24) as a data connection configuration.
 *
 * httpParams carries the Table 3 coding of section 2.4.4 directly: ETSI
 * COMPREHENSION-TLVs, CR bit clear, in the order Bearer description, Network
 * Access Name, User Login, User Password. Every coding below was checked
 * against the ETSI texts in spec/ on 2026-09-26:
 *   tags          TS 101 220 V19.0.0: '35' bearer, '47' NAN, '0D' text string
 *                 (the CR-set forms 'B5', 'C7', '8D' are accepted as well)
 *   NAN           TS 31.111 V19.4.0 8.61 -> TS 23.003: an APN, i.e. labels
 *                 each preceded by its length octet
 *   text string   TS 102 223 V18.3.0 8.15: first octet is the data coding
 *                 scheme ('04' 8-bit, '00' 7-bit packed, '08' UCS2)
 *   PDP type      TS 31.111 8.52.2 (bearer '02', byte 9: '02' IP, '07' Non-IP),
 *                 8.52.3/8.52.5 (bearers '09'/'0B', last byte: TS 24.008
 *                 V19.5.0 10.5.6.4, '21' IPv4 '57' IPv6 '8D' IPv4v6),
 *                 8.52.6 (bearer '0C', byte 4: TS 24.501 V19.7.0 9.11.4.11,
 *                 1 IPv4 2 IPv6 3 IPv4v6, other values read as IPv4v6)
 */
#ifndef IPAD_CONNECTIVITY_H
#define IPAD_CONNECTIVITY_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	char apn[101];         /* TS 23.003: at most 100 octets */
	char username[128];
	char password[128];
	const char *pdp_type;  /* "ipv4" | "ipv6" | "ipv4v6" | "non-ip" | NULL (not stated) */
	int bearer;            /* bearer type octet, -1 when absent */
} conn_params;

/* 0 on success (fields not present stay empty/NULL), -1 on malformed data */
int conn_parse(const uint8_t *p, size_t len, conn_params *out);

#endif
