/* SPDX-License-Identifier: GPL-2.0-only
 * The eIM's provisioning bundle (D-69): the flat-object reader, the expiry
 * date, the bind answers and the bind URL. */
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "bundle.h"
#include "check.h"

/* base64 of 30 03 80 01 41 (a DER SEQUENCE) and of 5 arbitrary bytes */
#define CFG64 "MAOAAUE="
#define KEY64 "AQIDBAU="

static int parse(const char *s, bundle *b, char *err)
{
	return bundle_parse((const uint8_t *)s, strlen(s), b, err, 200);
}

int main(void)
{
	bundle b;
	char err[200];
	time_t t;
	char url[200];

	/* --- the file as the eIM writes it ------------------------------------ */
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"6f1c2a\","
	         "\"eim_configuration\":\"" CFG64 "\",\"device_key\":\"" KEY64 "\","
	         "\"counter\":7,\"expires_at\":\"2027-03-25T12:00:00Z\"}\n", &b, err) == 0, "parse: the eIM's bundle");
	OK(!strcmp(b.issuance_id, "6f1c2a"), "parse: issuance id");
	OK(b.counter == 7, "parse: the start counter");
	EQ_HEX(b.eim_config.d, b.eim_config.len, "\x30\x03\x80\x01\x41", 5, "parse: the configuration, decoded");
	EQ_HEX(b.device_key.d, b.device_key.len, "\x01\x02\x03\x04\x05", 5, "parse: the key, decoded");
	bundle_free(&b);

	/* --- what is refused, not guessed at ------------------------------------ */
	OK(parse("{\"format\":\"eim-euicc-import/1\",\"issuance_id\":\"x\",\"eim_configuration\":\"" CFG64
	         "\",\"device_key\":\"" KEY64 "\",\"counter\":0,\"expires_at\":\"2027-01-01T00:00:00Z\"}", &b, err) < 0,
	   "refused: another format");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"x\",\"eim_configuration\":\"" CFG64
	         "\",\"counter\":0,\"expires_at\":\"2027-01-01T00:00:00Z\"}", &b, err) < 0,
	   "refused: no device key");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"x\\\"y\",\"eim_configuration\":\"" CFG64
	         "\",\"device_key\":\"" KEY64 "\",\"counter\":0,\"expires_at\":\"2027-01-01T00:00:00Z\"}", &b, err) < 0,
	   "refused: an escape (D-69 writes none)");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"x\",\"eim_configuration\":\"AQID\","
	         "\"device_key\":\"" KEY64 "\",\"counter\":0,\"expires_at\":\"2027-01-01T00:00:00Z\"}", &b, err) < 0,
	   "refused: a configuration that is not DER");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"nested\":{\"a\":1}}", &b, err) < 0, "refused: nesting");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"x\",\"eim_configuration\":\"@@@@\","
	         "\"device_key\":\"" KEY64 "\",\"counter\":0,\"expires_at\":\"2027-01-01T00:00:00Z\"}", &b, err) < 0,
	   "refused: not base64");

#define GOOD_TAIL "\"eim_configuration\":\"" CFG64 "\",\"device_key\":\"" KEY64 "\",\"expires_at\":\"2027-01-01T00:00:00Z\""
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0," GOOD_TAIL "}", &b, err) == 0,
	   "parse: the variant used below is good");
	bundle_free(&b);
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0," GOOD_TAIL
	         ",\"device_key\":\"" KEY64 "\"}", &b, err) < 0, "refused: a field twice (a second key would be appended)");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0,\"counter\":1,"
	         GOOD_TAIL "}", &b, err) < 0, "refused: the counter twice");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":-1," GOOD_TAIL "}", &b, err) < 0,
	   "refused: a negative counter");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":99999999999999999999,"
	         GOOD_TAIL "}", &b, err) < 0, "refused: a counter past 64 bits");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":-," GOOD_TAIL "}", &b, err) < 0,
	   "refused: a lone minus");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab/../1\",\"counter\":0," GOOD_TAIL "}", &b, err) < 0,
	   "refused: an issuance id that is not a UUID");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0," GOOD_TAIL "}{}", &b, err) < 0,
	   "refused: data after the object");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0," GOOD_TAIL ",}", &b, err) < 0,
	   "refused: a trailing comma");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0,\"x\":true," GOOD_TAIL "}", &b, err) < 0,
	   "refused: a boolean");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0,\"x\":[1]," GOOD_TAIL "}", &b, err) < 0,
	   "refused: an array");
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0,\"note\":\"later\",\"n\":2,"
	         GOOD_TAIL "}", &b, err) == 0, "parse: unknown string and integer fields are ignored");
	bundle_free(&b);
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0," GOOD_TAIL, &b, err) < 0,
	   "refused: truncated");
	OK(parse("{}", &b, err) < 0, "refused: empty object");
	{
		char *big = calloc(1, BUNDLE_MAX + 2);

		memset(big, ' ', BUNDLE_MAX + 1);
		big[0] = '{';
		OK(big && bundle_parse((const uint8_t *)big, BUNDLE_MAX + 1, &b, err, sizeof(err)) < 0 &&
		   strstr(err, "too large"), "refused: larger than a bundle can be");
		free(big);
	}
	OK(parse("{\"format\":\"eim-ipad-provision/1\",\"issuance_id\":\"ab-1\",\"counter\":0,"
	         "\"eim_configuration\":\"" CFG64 "\",\"device_key\":\"SECRETKEY@\",\"expires_at\":\"2027-01-01T00:00:00Z\"}",
	         &b, err) < 0 && !strstr(err, "SECRET"), "refused: the error never quotes the key");

	/* --- bundle or DER ---------------------------------------------------------- */
	OK(bundle_is((const uint8_t *)" \n{\"format\"", 11), "is: a JSON object, leading whitespace allowed");
	OK(!bundle_is((const uint8_t *)"\x30\x03", 2), "is: DER is not a bundle");

	/* --- expiry ------------------------------------------------------------------ */
	OK(rfc3339_time("2027-03-25T12:00:00Z", &t) == 0 && t == 1805976000, "time: Z");
	OK(rfc3339_time("2027-03-25T14:00:00.123+02:00", &t) == 0 && t == 1805976000, "time: offset and fraction");
	OK(rfc3339_time("2027-03-25 12:00", &t) < 0, "time: not RFC 3339");

	/* --- the bind answers (D-69) ------------------------------------------------- */
	OK(bind_outcome_of(204) == BIND_DONE, "bind: 204 bound");
	OK(bind_outcome_of(409) == BIND_DONE, "bind: 409 already registered counts as bound");
	OK(bind_outcome_of(403) == BIND_REFUSED, "bind: 403 stops polling");
	OK(bind_outcome_of(429) == BIND_RETRY && bind_outcome_of(503) == BIND_RETRY && bind_outcome_of(0) == BIND_RETRY,
	   "bind: rate limit, server error, no answer: retried");
	OK(bind_outcome_of(400) == BIND_BAD && bind_outcome_of(413) == BIND_BAD, "bind: a malformed request is an error");

	/* --- the bind URL: the ESipa host, our path ------------------------------------ */
	OK(bind_url("https://eim.lab.example:8443/gsma/rsp2/asn1", url, sizeof(url)) == 0 &&
	   !strcmp(url, "https://eim.lab.example:8443/ipad/v1/bind"), "url: same host and port");
	OK(bind_url("https://eim.example", url, sizeof(url)) == 0 && !strcmp(url, "https://eim.example/ipad/v1/bind"),
	   "url: without a path");
	OK(bind_url("eim.example", url, sizeof(url)) < 0, "url: no scheme is no URL");

	DONE("test_bundle");
}
