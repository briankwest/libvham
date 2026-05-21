/* test/test_fixtures.h — placeholder test data, NOT real credentials.
 *
 * These values are fixture strings used to exercise wire encoders and
 * state machines offline. They never authenticate against a real
 * server. Live tools/scripts read VHAM_USER / VHAM_PASS / VHAM_SERVER
 * from the environment (see ../.env.example).
 *
 * The values can still be overridden at test-build time via env vars,
 * which is useful when you want to use the same dispatch numbers
 * across offline and live tests:
 *
 *   VHAM_TEST_USER_A   primary fixture dispatch number
 *   VHAM_TEST_USER_B   secondary fixture dispatch number
 *   VHAM_TEST_GROUP    fixture group number
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_TEST_FIXTURES_H
#define VHAM_TEST_FIXTURES_H

#include <stdlib.h>
#include <string.h>

static inline const char *tf_get(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return (v && *v) ? v : fallback;
}

/* Placeholder fixture dispatch numbers. Format mirrors the real
 * 12-digit "V1NNNNNNNNNN" pattern so length-sensitive tests behave
 * the same against fixture and real values. */
#define TF_USER_A_DEFAULT  "USER_A0000001"
#define TF_USER_B_DEFAULT  "USER_B0000002"
#define TF_GROUP_DEFAULT   "GROUP0001"

#define TEST_USER_A   tf_get("VHAM_TEST_USER_A",  TF_USER_A_DEFAULT)
#define TEST_USER_B   tf_get("VHAM_TEST_USER_B",  TF_USER_B_DEFAULT)
#define TEST_GROUP    tf_get("VHAM_TEST_GROUP",   TF_GROUP_DEFAULT)

/* Names that appear literally inside recorded wire-capture byte arrays
 * (and inside hand-crafted frames where char-tokens already pin a
 * specific length). These can't be parameterized without rebuilding
 * the captured bytes; collected here so test code doesn't have to
 * sprinkle the literals around. */
/* 12-char dispatch numbers — same length as the originals so IE-length
 * fields in captured byte arrays remain correct. */
#define CAPTURED_NUM_A       "V00000000001"
#define CAPTURED_NUM_B       "V00000000002"
#define CAPTURED_NUM_NOTIFY  CAPTURED_NUM_B

#endif /* VHAM_TEST_FIXTURES_H */
