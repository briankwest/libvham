/* libvham/include/vham/causes.h — cause / status code dictionary.
 *
 * Mirrors `GetCauseStr @ 0x263164` from libsvcapi. Codes are emitted
 * by the server in IE 0x02 (OAM_RSP status) and IE 0x40 (CC_REL
 * cause). Names are translated from the binary's Chinese strings.
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef VHAM_CAUSES_H
#define VHAM_CAUSES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t    code;
    const char *name_en;
    const char *name_cn;        /* original Chinese name from binary */
} vham_cause_t;

/* Look up a cause code. Returns NULL if the code is unknown. */
const vham_cause_t *vham_cause_lookup(uint16_t code);

/* Convenience: returns the English name, or "unknown" if the code
 * is not in our table. */
const char *vham_cause_name(uint16_t code);

#ifdef __cplusplus
}
#endif

#endif /* VHAM_CAUSES_H */
