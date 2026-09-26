/* SPDX-License-Identifier: GPL-2.0-only
 * connectivity.c: httpParams (SGP.32 v1.3 2.4.4 Table 3) built per the ETSI
 * codings cited in connectivity.h, and read back to a connection config.
 * The JSON string writer the parameters reach the host through. */
#define _POSIX_C_SOURCE 200809L   /* open_memstream */
#include <stdlib.h>
#include "check.h"
#include "connectivity.h"
#include "hex.h"
#include "host.h"

/* host_json_str into a string */
static char *json(const char *in)
{
	char *out = NULL;
	size_t n = 0;
	FILE *f = open_memstream(&out, &n);

	host_json_str(f, in);
	fclose(f);
	return out;
}

#define JSON_EQ(in, want, msg) do { char *_j = json(in); OK(_j && !strcmp(_j, want), msg); free(_j); } while (0)

static int parse_hex(const char *h, conn_params *o)
{
	uint8_t b[512];
	int n = hex_decode(h, b, sizeof(b));

	return n < 0 ? -2 : conn_parse(b, (size_t)n, o);
}

#define STR_EQ(a, b, msg) OK(strcmp((a), (b)) == 0, msg)

int main(void)
{
	conn_params c;

	/* GPRS bearer '02' with PDP type '02' (IP) in byte 9; NAN internet.telekom
	 * as labels; login/password as 8-bit text strings */
	OK(parse_hex("3507" "02" "030403041F" "02"
	             "4711" "08696E7465726E6574" "0774656C656B6F6D"
	             "0D05" "0475736572"
	             "0D05" "0470617373", &c) == 0, "gprs: parses");
	STR_EQ(c.apn, "internet.telekom", "nan: labels joined with dots");
	STR_EQ(c.username, "user", "login: first text string");
	STR_EQ(c.password, "pass", "password: second text string");
	OK(c.pdp_type && strcmp(c.pdp_type, "ipv4") == 0, "gprs: PDP '02' is IPv4");
	OK(c.bearer == 2, "gprs: bearer type kept");

	/* E-UTRAN '0B', non-GBR (X=2: QCI 9), PDP_type 8D = IPv4v6 (TS 24.008) */
	OK(parse_hex("3503" "0B" "09" "8D", &c) == 0 && c.pdp_type &&
	   strcmp(c.pdp_type, "ipv4v6") == 0, "e-utran: 8D is IPv4v6");
	OK(parse_hex("3503" "0B" "09" "57", &c) == 0 && c.pdp_type &&
	   strcmp(c.pdp_type, "ipv6") == 0, "e-utran: 57 is IPv6");

	/* NG-RAN '0C', PDU session type 2 = IPv6; 4 (Unstructured) is no IP type */
	OK(parse_hex("3502" "0C" "02", &c) == 0 && c.pdp_type && strcmp(c.pdp_type, "ipv6") == 0,
	   "nr: PDU session type 2 is IPv6");
	OK(parse_hex("3502" "0C" "04", &c) == 0 && c.pdp_type == NULL, "nr: Unstructured states no IP type");

	/* the 'A1' wrapper of Table 2, and CR-set tags (B5/C7/8D) */
	OK(parse_hex("A10C" "C707" "06696F742D3031" "8D01" "04", &c) == 0, "wrapper + CR tags: parses");
	STR_EQ(c.apn, "iot-01", "cr tags: NAN read");
	STR_EQ(c.username, "", "cr tags: an empty login is empty");

	/* 7-bit packed "hello" (TS 23.038) and UCS2 "ab" */
	OK(parse_hex("0D06" "00E8329BFD06" "0D05" "0800610062", &c) == 0, "dcs: parses");
	STR_EQ(c.username, "hello", "dcs 00: 7-bit packed unpacked");
	STR_EQ(c.password, "ab", "dcs 08: UCS2");

	/* nothing at all: all fields empty, no PDP type */
	OK(parse_hex("", &c) == 0 && c.apn[0] == 0 && c.pdp_type == NULL && c.bearer == -1,
	   "empty: nothing stated");

	/* refused: a label running past the NAN, a character no APN has, a TLV
	 * longer than the data */
	OK(parse_hex("4705" "0961626364", &c) < 0, "malformed: label overruns the NAN");
	OK(parse_hex("4705" "04612F6263", &c) < 0, "malformed: '/' is not an APN character");
	OK(parse_hex("4709" "0461626364", &c) < 0, "malformed: TLV longer than the data");

	/* a profile's credentials are 8-bit text in any coding: what is not
	 * UTF-8 must not end up in the host's JSON line */
	JSON_EQ("internet", "\"internet\"", "json: ASCII as is");
	JSON_EQ("a\"b\\c\n\x7f", "\"a\\\"b\\\\c\\u000a\\u007f\"", "json: quote, backslash, controls escaped");
	JSON_EQ("gr\xc3\xbc\xc3\x9f \xe2\x82\xac \xf0\x9f\x93\xb6", "\"gr\xc3\xbc\xc3\x9f \xe2\x82\xac \xf0\x9f\x93\xb6\"",
	        "json: well-formed UTF-8 as is");
	JSON_EQ("p\xe4ss", "\"p\\ufffdss\"", "json: a Latin-1 byte becomes U+FFFD");
	JSON_EQ("\xc0\xaf", "\"\\ufffd\\ufffd\"", "json: an overlong form is refused");
	JSON_EQ("\xed\xa0\x80", "\"\\ufffd\\ufffd\\ufffd\"", "json: a surrogate is refused");
	JSON_EQ("\xf4\x90\x80\x80", "\"\\ufffd\\ufffd\\ufffd\\ufffd\"", "json: above U+10FFFF is refused");
	JSON_EQ("x\xe2\x82", "\"x\\ufffd\\ufffd\"", "json: a sequence cut at the end");

	/* the connectivity event: credentials that are not UTF-8 are not
	 * sent mangled, the event is not sent at all */
	{
		static char answer[] = "{\"type\":\"event\",\"payload\":{}}\n";
		conn_params p;
		host_link h;
		ipa_host hooks;
		char *out = NULL;
		size_t n = 0;
		FILE *in = fmemopen(answer, sizeof(answer) - 1, "r"), *o = open_memstream(&out, &n);

		host_init(&h, in, o);
		memset(&hooks, 0, sizeof(hooks));
		host_ipa_hooks(&h, &hooks, 0);
		memset(&p, 0, sizeof(p));
		snprintf(p.apn, sizeof(p.apn), "internet");
		snprintf(p.username, sizeof(p.username), "user");
		snprintf(p.password, sizeof(p.password), "p\xe4ss");   /* Latin-1 */
		hooks.connectivity(hooks.ud, "8949000000000000001", &p, false);
		fflush(o);
		OK(n == 0, "event: Latin-1 password -> no event");
		OK(strstr(h.last_error, "not UTF-8") && !strstr(h.last_error, "p\xe4ss") && !strstr(h.last_error, "user"),
		   "event: the error says why, without the credentials");
		snprintf(p.password, sizeof(p.password), "p\xc3\xa4ss");   /* the same in UTF-8 */
		hooks.connectivity(hooks.ud, "8949000000000000001", &p, false);
		fflush(o);
		OK(n > 0 && strstr(out, "\"password\":\"p\xc3\xa4ss\""), "event: UTF-8 credentials sent as they are");
		snprintf(p.apn, sizeof(p.apn), "inter\xffnet");
		n = 0;
		fseek(o, 0, SEEK_SET);
		hooks.connectivity(hooks.ud, "8949000000000000001", &p, false);
		fflush(o);
		OK(n == 0, "event: an APN that is not UTF-8 -> no event");
		fclose(o);
		fclose(in);
		free(out);
		host_free(&h);
	}

	DONE("test_connectivity");
}
