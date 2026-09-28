/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 *
 * The eUICC as the IPA sees it: one ES10 exchange at a time, command data
 * object in, response data object out (SGP.32 v1.3 section 5.9, SGP.22 v2.7
 * section 5.7). Two implementations behind the same call:
 *
 *   iot  an SGP.32 IoT eUICC. Every function goes to the card; the card
 *        verifies the eIM, signs its results and keeps its own state.
 *   emu  an SGP.22 consumer eUICC behind a virtual SGP.32 ISD-R (emu.c). The
 *        SGP.32-only functions are answered here, with the eIM trust, the
 *        replay counter and the result signatures kept by the IPA; the rest
 *        goes to the card unchanged.
 *
 * Because the call is the same, everything above it (ipa.c) is written once.
 * It asks which one it drives only for what an IoT eUICC has no place for:
 * the notification backoff, kept in the emulation's state (emu.h).
 */
#ifndef IPAD_EUICC_H
#define IPAD_EUICC_H

#include "card.h"
#include "der.h"

typedef enum { EUICC_IOT, EUICC_EMU } euicc_kind;

typedef struct euicc {
	euicc_kind kind;
	card *card;
	struct emu *emu;   /* EUICC_EMU only */
} euicc;

/* One ES10 function. 0 when the eUICC answered (the answer may itself carry
 * an error code), -1 when there was no answer (transport, or a status word
 * other than 9000; e->card->sw holds it). */
int euicc_es10(euicc *e, const uint8_t *req, size_t len, dbuf *resp);

/* Which one this card is: an IoT eUICC answers ES10b.GetEimConfigurationData
 * (BF55); an SGP.22 card does not know the function. */
euicc_kind euicc_probe(card *c);

#endif
