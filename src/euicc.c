/* SPDX-License-Identifier: GPL-2.0-only
 * Copyright (C) 2026 André Valentin <avalentin@marcant.net>
 */
#include "euicc.h"
#include "emu.h"

int euicc_es10(euicc *e, const uint8_t *req, size_t len, dbuf *resp)
{
	if (e->kind == EUICC_EMU)
		return emu_es10(e->emu, req, len, resp);
	return card_es10(e->card, req, len, resp);
}

euicc_kind euicc_probe(card *c)
{
	/* GetEimConfigurationData (SGP.32 5.9.18) with no search criteria: an IoT
	 * eUICC answers with BF55 (an empty list when no eIM is configured yet);
	 * an SGP.22 card refuses the unknown function with a status word, or
	 * answers something that is not BF55 */
	static const uint8_t req[] = { 0xBF, 0x55, 0x00 };
	dbuf resp;
	der_tlv t;
	euicc_kind k = EUICC_EMU;

	db_init(&resp);
	if (card_es10(c, req, sizeof(req), &resp) == 0 && der_parse(resp.d, resp.len, &t) == 0 &&
	    t.tag == 0xBF55)
		k = EUICC_IOT;
	db_free(&resp);
	return k;
}
