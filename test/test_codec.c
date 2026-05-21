/* Unit tests for vham codec primitives. */
#include "test_fixtures.h"
#include "vham/codec.h"
#include "vham/regreq.h"
#include "vham/regrsp.h"
#include "vham/cc.h"
#include "vham/sdp.h"
#include "vham/rtp.h"
#include "vham/g711.h"
#include "vham/dtmf.h"
#include "vham/voice.h"
#include "vham/composites.h"
#include "vham/passthrough.h"
#include "vham/oam.h"
#include "vham/causes.h"
#include "vham/codec_audio.h"
#include "vham/jitter.h"
#include "vham/rtcp.h"
#include "vham/retx.h"
#include "vham/segment.h"
#include "vham/im.h"
#include "vham/gps.h"
#include "vham/tokenstore.h"
#include "vham/h264.h"
#include "vham/srtp.h"
#include <stdlib.h>
#include <unistd.h>
#include "mock_server.h"
#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* RFC 1321 test vectors for sanity. */
#include "../src/md5_internal.h"
static void test_md5(void) {
    uint8_t out[16];
    char hex[33];
    /* MD5("") */
    vham_md5("", 0, out);
    vham_md5_hex(out, hex);
    assert(strcmp(hex, "d41d8cd98f00b204e9800998ecf8427e") == 0);
    /* MD5("abc") */
    vham_md5("abc", 3, out);
    vham_md5_hex(out, hex);
    assert(strcmp(hex, "900150983cd24fb0d6963f7d28e17f72") == 0);
    /* Constant for the REGISTER:0.0.0.0 hash that the protocol uses */
    vham_md5("REGISTER:0.0.0.0", 16, out);
    vham_md5_hex(out, hex);
    printf("MD5('REGISTER:0.0.0.0') = %s\n", hex);
}

/* Confirm BE encoding of u16/u32. */
static void test_pack_be(void) {
    uint8_t buf[16];
    vham_buf_t b;

    vham_buf_init(&b, buf, sizeof buf);
    assert(vham_pack_u16(&b, 0x0001) == 0);  /* class=1 */
    assert(buf[0] == 0x00 && buf[1] == 0x01);

    vham_buf_init(&b, buf, sizeof buf);
    assert(vham_pack_u32(&b, 0x00000098) == 0);
    assert(buf[0] == 0x00 && buf[1] == 0x00 && buf[2] == 0x00 && buf[3] == 0x98);

    vham_buf_init(&b, buf, sizeof buf);
    assert(vham_pack_intel_u16(&b, 0x1234) == 0);
    assert(buf[0] == 0x34 && buf[1] == 0x12);
}

/* Confirm TLV layout: tag(BE) len(BE) value */
static void test_tlv_layout(void) {
    uint8_t buf[64];
    vham_buf_t b;

    vham_buf_init(&b, buf, sizeof buf);
    assert(vham_pack_tlv_u32(&b, 1, 0x0037, 0x00000098) == 0);
    assert(b.off == 8);
    /* tag */
    assert(buf[0] == 0x00 && buf[1] == 0x37);
    /* len */
    assert(buf[2] == 0x00 && buf[3] == 0x04);
    /* value */
    assert(buf[4] == 0x00 && buf[5] == 0x00 && buf[6] == 0x00 && buf[7] == 0x98);

    /* presence=0 should emit nothing */
    vham_buf_init(&b, buf, sizeof buf);
    assert(vham_pack_tlv_u32(&b, 0, 0x0037, 0x99) == 0);
    assert(b.off == 0);

    /* String TLV: length includes NUL */
    vham_buf_init(&b, buf, sizeof buf);
    assert(vham_pack_tlv_str(&b, 1, 0x0009, "abc") == 0);
    assert(buf[0] == 0x00 && buf[1] == 0x09);
    assert(buf[2] == 0x00 && buf[3] == 0x04);     /* 3 chars + NUL */
    assert(buf[4] == 'a' && buf[5] == 'b' && buf[6] == 'c' && buf[7] == 0x00);
}

/* Smoke-test the REGREQ builder (initial, no auth). */
static void test_regreq_initial(void) {
    uint8_t buf[1500];

    vham_regreq_t r = {
        .seq_no       = 1,
        .reg_type     = VHAM_REGTYPE_USER,
        .username     = "200001",
        .self_num     = "200001",
        .server_ipv4  = 0xc0a80101,    /* 192.168.1.1 */
        .server_port  = 10000,
        .feature_mask = 0x00000098,
    };
    int n = vham_build_regreq(&r, buf, sizeof buf);
    assert(n > 32);
    printf("REGREQ length = %d bytes\n", n);

    /* TAP header */
    assert(buf[0]  == 0x01 && buf[1]  == 0x00);     /* version */
    assert(buf[2]  == 0x00 && buf[3]  == 0x00);     /* reserved */
    assert(buf[4]  == 0x00 && buf[5]  == 0x00 &&    /* seq */
           buf[6]  == 0x00 && buf[7]  == 0x01);
    assert(buf[8]  == 0x00 && buf[9]  == 0x01);     /* class */
    assert(buf[10] == 0x00 && buf[11] == 0x10);     /* cmd = MM_REGREQ */
    /* body_len at [12..15] == n - 16 */
    uint32_t body_len = ((uint32_t)buf[12] << 24) | ((uint32_t)buf[13] << 16) |
                        ((uint32_t)buf[14] << 8)  |  (uint32_t)buf[15];
    assert(body_len == (uint32_t)(n - 16));

    /* SRVMSG header at offset 16 */
    assert(buf[16] == 0x04 && buf[17] == 0x04);    /* Dst=MM, Src=MM */
    assert(buf[18] == 0x00 && buf[19] == 0x10);    /* wMsgId */
    for (int i = 20; i < 28; ++i) assert(buf[i] == 0xff);   /* FsmIds */
    uint32_t srv_body_len = ((uint32_t)buf[28] << 24) |
                            ((uint32_t)buf[29] << 16) |
                            ((uint32_t)buf[30] <<  8) |
                             (uint32_t)buf[31];
    assert(srv_body_len == (uint32_t)(n - 32));

    /* First IE should be 0x001d (RegType) with value 0x01 */
    assert(buf[32] == 0x00 && buf[33] == 0x1d);
    assert(buf[34] == 0x00 && buf[35] == 0x01);
    assert(buf[36] == 0x01);                       /* RegType = 1 */
}

/* End-to-end auth check: known fixed inputs → known fixed output. */
static void test_auth_known(void) {
    /* From a hypothetical challenge:
     *   username = "200001"
     *   realm    = "ids"
     *   password = "secret"
     *   nonce    = "deadbeef"
     *   method   = "REGISTER"
     *   uri      = "0.0.0.0"
     * Compute by hand to derive expected:
     *   HA1 = md5("200001:ids:secret")
     *   HA2 = md5("REGISTER:0.0.0.0")
     *   resp = md5(HA1_hex ":deadbeef:" HA2_hex)
     */
    char out[33];
    int rc = vham_auth_md5("200001", "ids", "secret",
                           "REGISTER", "MD5", "deadbeef",
                           NULL, NULL, "0.0.0.0", NULL, out);
    assert(rc == 0);
    /* Recompute the expected value locally to keep this self-checking. */
    uint8_t  bin[16]; char ha1[33], ha2[33], expect[33];
    vham_md5_ctx_t c;
    vham_md5_init(&c);
    vham_md5_update(&c, "200001:ids:secret", 17);
    vham_md5_final(&c, bin); vham_md5_hex(bin, ha1);
    vham_md5("REGISTER:0.0.0.0", 16, bin); vham_md5_hex(bin, ha2);
    vham_md5_init(&c);
    vham_md5_update(&c, ha1, 32);
    vham_md5_update(&c, ":deadbeef:", 10);
    vham_md5_update(&c, ha2, 32);
    vham_md5_final(&c, bin); vham_md5_hex(bin, expect);
    if (strcmp(out, expect) != 0) {
        fprintf(stderr, "auth: got %s want %s\n", out, expect);
        assert(0);
    }
    printf("auth resp = %s\n", out);
}

/* Round-trip: encode a REGREQ, parse it back, verify every IE. */
static void test_regreq_roundtrip(void) {
    uint8_t buf[1500];
    vham_regreq_t r = {
        .seq_no       = 7,
        .reg_type     = VHAM_REGTYPE_USER,
        .username     = "200001",
        .self_num     = "200002",
        .server_ipv4  = 0xc0a80101,
        .server_port  = 10000,
        .feature_mask = 0x12345678,
    };
    int n = vham_build_regreq(&r, buf, sizeof buf);
    assert(n > 32);

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    int rc = vham_parse_packet(buf, (size_t)n, &th, &sh, &rd);
    assert(rc == 0);

    assert(th.ver_hi == 0x01 && th.ver_lo == 0x00);
    assert(th.class_id == 0x0001);
    assert(th.cmd      == VHAM_MM_REGREQ);
    assert(th.seq_no   == 7);

    assert(sh.ucDst == VHAM_MOD_MM && sh.ucSrc == VHAM_MOD_MM);
    assert(sh.wMsgId == VHAM_MM_REGREQ);
    assert(sh.dwDstFsmId == 0xffffffff && sh.dwSrcFsmId == 0xffffffff);

    /* Walk IEs */
    int saw_regtype = 0, saw_feat = 0, saw_addr = 0, saw_user = 0, saw_self = 0;
    vham_ie_t ie;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_REG_TYPE: {
            uint8_t v;
            assert(vham_ie_get_u8(&ie, &v) == 0);
            assert(v == VHAM_REGTYPE_USER);
            saw_regtype = 1;
            break;
        }
        case VHAM_IE_FEATURE_MASK: {
            uint32_t v;
            assert(vham_ie_get_u32(&ie, &v) == 0);
            assert(v == 0x12345678);
            saw_feat = 1;
            break;
        }
        case VHAM_IE_SERVER_ADDR: {
            vham_ipaddr_t a;
            assert(vham_ie_get_ipaddr(&ie, &a) == 0);
            assert(a.ipv4 == 0xc0a80101);
            assert(a.port == 10000);
            assert(a.family == 0x00);  /* see encode_pipaddr — wire is 0x00 */
            saw_addr = 1;
            break;
        }
        case VHAM_IE_IDENTITY_NUM: {
            const char *s = vham_ie_get_str(&ie);
            assert(s && strcmp(s, "200001") == 0);
            saw_user = 1;
            break;
        }
        case VHAM_IE_SELF_NUM: {
            const char *s = vham_ie_get_str(&ie);
            assert(s && strcmp(s, "200002") == 0);
            saw_self = 1;
            break;
        }
        default:
            /* Unknown IE — just skip */
            break;
        }
    }
    assert(rc == 0);                 /* clean end */
    assert(saw_regtype && saw_feat && saw_addr && saw_user && saw_self);
}

/* Hand-craft a REGRSP-with-challenge datagram, parse it, verify we
 * can extract realm / nonce / algorithm and that the sub-opcode
 * 0x1e == 0x53 is recognised. Then run the auth digest against it. */
static void test_regrsp_challenge_parse(void) {
    uint8_t out[1500];
    vham_buf_t b;
    vham_buf_init(&b, out, sizeof out);

    /* TAP header */
    assert(vham_pack_u8(&b, 0x01) == 0);
    assert(vham_pack_u8(&b, 0x00) == 0);
    assert(vham_pack_u16(&b, 0)    == 0);
    assert(vham_pack_u32(&b, 42)   == 0);
    assert(vham_pack_u16(&b, 1)    == 0);
    assert(vham_pack_u16(&b, VHAM_MM_REGRSP) == 0);
    size_t tap_len_off = b.off;
    assert(vham_pack_u32(&b, 0) == 0);
    size_t body_start = b.off;

    /* SRVMSG header */
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_MM, .ucSrc = VHAM_MOD_MM,
        .wMsgId = VHAM_MM_REGRSP,
        .dwDstFsmId = 0xffffffff, .dwSrcFsmId = 0xffffffff,
    };
    size_t srvmsg_len_off;
    assert(vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off) == 0);
    size_t srvmsg_body_start = b.off;

    /* IEs */
    assert(vham_pack_tlv_u16(&b, 1, VHAM_IE_SUB_OPCODE, 0x53)         == 0);
    assert(vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_ALGORITHM, "MD5")    == 0);
    assert(vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_NONCE, "deadbeef")   == 0);
    assert(vham_pack_tlv_str(&b, 1, VHAM_IE_AUTH_REALM, "ids")        == 0);

    assert(vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body_start) == 0);
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    b.buf[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    b.buf[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    b.buf[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    b.buf[tap_len_off + 3] = (uint8_t)(tap_body);

    /* --- parse --- */
    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t shp;
    vham_reader_t     rd;
    assert(vham_parse_packet(out, b.off, &th, &shp, &rd) == 0);
    assert(th.cmd == VHAM_MM_REGRSP);
    assert(shp.wMsgId == VHAM_MM_REGRSP);

    const char *algo = NULL, *nonce = NULL, *realm = NULL;
    uint16_t sub_opcode = 0;
    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_SUB_OPCODE:
            assert(vham_ie_get_u16(&ie, &sub_opcode) == 0);
            break;
        case VHAM_IE_AUTH_ALGORITHM: algo  = vham_ie_get_str(&ie); break;
        case VHAM_IE_AUTH_NONCE:     nonce = vham_ie_get_str(&ie); break;
        case VHAM_IE_AUTH_REALM:     realm = vham_ie_get_str(&ie); break;
        }
    }
    assert(rc == 0);
    assert(sub_opcode == 0x53);
    assert(algo  && strcmp(algo,  "MD5")      == 0);
    assert(nonce && strcmp(nonce, "deadbeef") == 0);
    assert(realm && strcmp(realm, "ids")      == 0);

    /* Now run the auth digest with what we parsed. */
    char resp[33];
    assert(vham_auth_md5("200001", realm, "secret",
                         "REGISTER", algo, nonce,
                         NULL, NULL, "0.0.0.0", NULL, resp) == 0);
    assert(strlen(resp) == 32);
    printf("challenge resp = %s\n", resp);
}

/* Malformed-input tests — make sure we don't crash or run off the end */
static void test_decoder_robustness(void) {
    /* Too short */
    vham_tap_hdr_t th; vham_srvmsg_hdr_t sh; vham_reader_t rd;
    assert(vham_parse_packet("", 0, &th, &sh, &rd) == -1);
    uint8_t tiny[31] = {0};
    assert(vham_parse_packet(tiny, sizeof tiny, &th, &sh, &rd) == -1);

    /* Plausible 32-byte packet but body_len mismatch */
    uint8_t bad[32] = {
        0x01, 0x00, 0x00, 0x00,                /* version */
        0x00, 0x00, 0x00, 0x01,                /* seq */
        0x00, 0x01,                            /* class */
        0x00, 0x10,                            /* cmd */
        0x00, 0x00, 0x00, 0x99,                /* body_len = 0x99 (wrong) */
        0x04, 0x04, 0x00, 0x10,                /* SRVMSG hdr */
        0xff,0xff,0xff,0xff, 0xff,0xff,0xff,0xff,
        0x00, 0x00, 0x00, 0x00,                /* dwMsgLen = 0 */
    };
    assert(vham_parse_packet(bad, sizeof bad, &th, &sh, &rd) == -1);

    /* Truncated TLV inside an otherwise-valid frame */
    uint8_t trunc[16 + 16 + 3];
    memset(trunc, 0, sizeof trunc);
    trunc[0] = 0x01;                           /* ver_hi */
    /* TAP body_len = 16 (SRVMSG hdr) + 3 (truncated TLV) = 19 */
    trunc[12] = 0; trunc[13] = 0; trunc[14] = 0; trunc[15] = 19;
    trunc[10] = 0; trunc[11] = 0x10;           /* cmd */
    /* class = 1 */ trunc[8] = 0; trunc[9] = 1;
    /* SRVMSG */
    trunc[16] = 0x04; trunc[17] = 0x04;
    trunc[18] = 0; trunc[19] = 0x10;           /* wMsgId */
    memset(trunc + 20, 0xff, 8);               /* FsmIds */
    /* dwMsgLen = 3 (the truncated TLV) */
    trunc[28] = 0; trunc[29] = 0; trunc[30] = 0; trunc[31] = 3;
    /* Only 3 bytes of "TLV" (need 4 for header alone) */
    assert(vham_parse_packet(trunc, sizeof trunc, &th, &sh, &rd) == 0);
    vham_ie_t ie;
    assert(vham_next_ie(&rd, &ie) == -1);      /* truncated header */
}

/* End-to-end: client and mock server exchange buffers in-process.
 * Asserts a full 4-message registration handshake and final OK state. */
static void test_registration_loopback(void) {
    /* shared credentials */
    const char *user  = "200001";
    const char *pass  = "secret";
    const char *realm = "ids";
    const char *nonce = "deadbeef1234";

    mock_srv_t srv;
    mock_srv_init(&srv, user, pass, realm, nonce);

    vham_reg_client_t cli;
    assert(vham_reg_client_init(&cli, user, pass,
                                0xc0a80101, 10000) == 0);

    uint8_t cli_buf[1500];
    uint8_t srv_buf[1500];

    /* --- step 1: client → server (initial REGREQ) --- */
    int n = vham_reg_client_emit(&cli, cli_buf, sizeof cli_buf);
    assert(n > 0);
    assert(cli.state == VHAM_REG_SENT_INITIAL);

    /* --- step 2: server → client (REGRSP with challenge) --- */
    int m = mock_srv_handle(&srv, cli_buf, (size_t)n,
                            srv_buf, sizeof srv_buf);
    assert(m > 0);
    assert(srv.saw_initial_regreq == 1 && srv.saw_auth_regreq == 0);

    vham_reg_state_t st = vham_reg_client_recv(&cli, srv_buf, (size_t)m);
    assert(st == VHAM_REG_SENT_INITIAL);
    assert(cli.last_response_hex[0] != 0);
    printf("client computed response = %s\n", cli.last_response_hex);

    /* --- step 3: client → server (REGREQ with auth) --- */
    n = vham_reg_client_emit(&cli, cli_buf, sizeof cli_buf);
    assert(n > 0);
    assert(cli.state == VHAM_REG_SENT_AUTH);

    /* --- step 4: server → client (REGRSP success) --- */
    m = mock_srv_handle(&srv, cli_buf, (size_t)n,
                        srv_buf, sizeof srv_buf);
    assert(m > 0);
    assert(srv.saw_auth_regreq == 1);
    assert(srv.regreqs_received == 2);

    st = vham_reg_client_recv(&cli, srv_buf, (size_t)m);
    assert(st == VHAM_REG_OK);
    printf("registration OK after %d REGREQs\n", srv.regreqs_received);
}

/* Same flow but with the wrong password — server should reject. */
static void test_registration_bad_password(void) {
    mock_srv_t srv;
    mock_srv_init(&srv, "200001", "correct", "ids", "n0nc3");

    vham_reg_client_t cli;
    vham_reg_client_init(&cli, "200001", "WRONG",
                         0xc0a80101, 10000);

    uint8_t a[1500], b[1500];
    int n = vham_reg_client_emit(&cli, a, sizeof a);
    int m = mock_srv_handle(&srv, a, (size_t)n, b, sizeof b);
    assert(m > 0);
    vham_reg_state_t st = vham_reg_client_recv(&cli, b, (size_t)m);
    assert(st == VHAM_REG_SENT_INITIAL);  /* challenge accepted */

    n = vham_reg_client_emit(&cli, a, sizeof a);
    m = mock_srv_handle(&srv, a, (size_t)n, b, sizeof b);
    assert(m > 0);
    st = vham_reg_client_recv(&cli, b, (size_t)m);
    assert(st == VHAM_REG_FAILED);
    printf("bad password → state FAILED as expected\n");
}

/* CC_SETUP round-trip + frame layout check */
static void test_cc_setup_roundtrip(void) {
    uint8_t buf[1500];
    vham_cc_setup_t s = {
        .seq_no          = 1,
        .leg_id          = 42,
        .called_num      = "146520",     /* a real channel */
        .calling_num     = TEST_USER_A,
        .service_type    = VHAM_CALL_HALF_DUPLEX,
        .channel_subcode = "01",          /* exercise IE 0x45 */
    };
    int n = vham_build_cc_setup(&s, buf, sizeof buf);
    assert(n > 32);

    /* TAP header asserts */
    assert(buf[0] == 0x01 && buf[1] == 0x00);
    assert(buf[2] == 0x00 && buf[3] == 0x00);            /* flags=0 */
    assert(buf[8] == 0x00 && buf[9] == 0x03);            /* class = CC */
    assert(buf[10] == 0x00 && buf[11] == 0x50);          /* cmd = CC_SETUP */

    /* SRVMSG header */
    assert(buf[16] == 0x04 && buf[17] == 0x04);           /* Dst/Src=MM */
    assert(buf[18] == 0x00 && buf[19] == 0x50);           /* wMsgId */
    for (int i = 20; i < 24; ++i) assert(buf[i] == 0xff); /* DstFsmId */
    /* SrcFsmId = leg_id */
    assert(buf[24] == 0x00 && buf[25] == 0x00 &&
           buf[26] == 0x00 && buf[27] == 0x2a);

    /* Walk IEs and verify */
    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    assert(vham_parse_packet(buf, (size_t)n, &th, &sh, &rd) == 0);
    assert(th.cmd      == VHAM_CC_SETUP);
    assert(th.class_id == VHAM_TAP_CLASS_CC);
    assert(sh.wMsgId   == VHAM_CC_SETUP);
    assert(sh.dwSrcFsmId == 42);

    int saw_called = 0, saw_calling = 0, saw_service = 0, saw_subcode = 0;
    vham_ie_t ie;
    int rc;
    while ((rc = vham_next_ie(&rd, &ie)) == 1) {
        switch (ie.tag) {
        case VHAM_IE_CC_CALLED_NUM: {
            const char *s2 = vham_ie_get_str(&ie);
            assert(s2 && strcmp(s2, "146520") == 0);
            saw_called = 1;
            break;
        }
        case VHAM_IE_CC_CALLING_NUM: {
            const char *s2 = vham_ie_get_str(&ie);
            assert(s2 && strcmp(s2, TEST_USER_A) == 0);
            saw_calling = 1;
            break;
        }
        case VHAM_IE_CC_SERVICE: {
            uint32_t v;
            assert(vham_ie_get_u32(&ie, &v) == 0);
            assert(v == VHAM_CALL_HALF_DUPLEX);
            saw_service = 1;
            break;
        }
        case VHAM_IE_CC_SUBCODE: {
            const char *s2 = vham_ie_get_str(&ie);
            assert(s2 && strcmp(s2, "01") == 0);
            saw_subcode = 1;
            break;
        }
        }
    }
    assert(rc == 0);
    assert(saw_called && saw_calling && saw_service && saw_subcode);
}

/* TAP-ACK builder + parser sanity */
static void test_tap_ack(void) {
    uint8_t ack[16];
    int n = vham_build_tap_ack(0x12345678, VHAM_TAP_CLASS_MM,
                               VHAM_MM_REGREQ, ack, sizeof ack);
    assert(n == 16);
    /* ver */
    assert(ack[0] == 0x01 && ack[1] == 0x00);
    /* flags = ACK */
    assert(ack[2] == 0x00 && ack[3] == 0x01);
    /* seq */
    assert(ack[4] == 0x12 && ack[5] == 0x34 &&
           ack[6] == 0x56 && ack[7] == 0x78);
    /* class */
    assert(ack[8] == 0x00 && ack[9] == 0x01);
    /* cmd */
    assert(ack[10] == 0x00 && ack[11] == 0x10);
    /* body_len = 0 */
    for (int i = 12; i < 16; ++i) assert(ack[i] == 0x00);
}

/* SDP round-trip with a minimal audio-only block (one PCMU codec) */
static void test_sdp_audio_roundtrip(void) {
    vham_sdp_t s;
    memset(&s, 0, sizeof s);
    s.origin_ipv4 = 0xc0a80105;  /* 192.168.1.5 */
    s.origin_port = 20000;
    s.media_count = 1;

    vham_sdp_media_t *m = &s.media[0];
    m->ipv4         = 0xc0a80105;
    m->port         = 20002;
    m->family       = 0;
    m->transport    = VHAM_SDP_TX_RTP_UDP;
    m->flags        = 0;
    m->media_type   = VHAM_SDP_MEDIA_AUDIO;
    m->bandwidth_or_flags = 0;
    m->codec_count  = 1;

    vham_sdp_codec_t *c = &m->codecs[0];
    c->payload_type   = 0;             /* PCMU */
    c->encoding_param = 1;             /* mono */
    c->clock_rate     = 8000;
    snprintf(c->name, sizeof c->name, "PCMU");
    c->num_params     = 0;
    snprintf(c->param_a, sizeof c->param_a, "");
    snprintf(c->param_b, sizeof c->param_b, "");

    uint8_t out[2048];
    int n = vham_build_sdp_body(&s, out, sizeof out);
    assert(n > 0);

    /* Spot check header bytes */
    assert(out[0] == 0x05 && out[1] == 0x01 &&
           out[2] == 0xa8 && out[3] == 0xc0);    /* LE 192.168.1.5 */
    assert(out[4] == 0x20 && out[5] == 0x4e);    /* LE port 20000 */
    assert(out[8] == 0x01);                       /* media_count */

    vham_sdp_t s2;
    assert(vham_parse_sdp_body(out, (size_t)n, &s2) == 0);
    assert(!s2.is_type1);
    assert(s2.media_count == 1);
    assert(s2.origin_ipv4 == 0xc0a80105);
    assert(s2.origin_port == 20000);
    assert(s2.media[0].ipv4 == 0xc0a80105);
    assert(s2.media[0].port == 20002);
    assert(s2.media[0].media_type == VHAM_SDP_MEDIA_AUDIO);
    assert(s2.media[0].codec_count == 1);
    assert(s2.media[0].codecs[0].payload_type == 0);
    assert(s2.media[0].codecs[0].clock_rate   == 8000);
    assert(strcmp(s2.media[0].codecs[0].name, "PCMU") == 0);
}

/* SDP round-trip with audio + video (mixed) */
static void test_sdp_audio_video_roundtrip(void) {
    vham_sdp_t s;
    memset(&s, 0, sizeof s);
    s.origin_ipv4 = 0xc0a80101;
    s.origin_port = 20000;
    s.media_count = 2;

    /* audio */
    vham_sdp_media_t *a = &s.media[0];
    a->ipv4         = 0xc0a80101;
    a->port         = 20002;
    a->transport    = VHAM_SDP_TX_RTP_UDP;
    a->media_type   = VHAM_SDP_MEDIA_AUDIO;
    a->codec_count  = 2;
    a->codecs[0].payload_type = 0;
    a->codecs[0].encoding_param = 1;
    a->codecs[0].clock_rate = 8000;
    strcpy(a->codecs[0].name, "PCMU");
    a->codecs[1].payload_type = 106;
    a->codecs[1].encoding_param = 1;
    a->codecs[1].clock_rate = 48000;
    strcpy(a->codecs[1].name, "Opus");

    /* video */
    vham_sdp_media_t *v = &s.media[1];
    v->ipv4         = 0xc0a80101;
    v->port         = 20004;
    v->transport    = VHAM_SDP_TX_RTP_UDP;
    v->media_type   = VHAM_SDP_MEDIA_VIDEO;
    v->codec_count  = 1;
    v->codecs[0].payload_type = 98;
    v->codecs[0].encoding_param = 0;
    v->codecs[0].clock_rate = 90000;
    strcpy(v->codecs[0].name, "H264");
    v->codecs[0].video_width   = 320;
    v->codecs[0].video_height  = 240;
    v->codecs[0].video_bitrate = 300000;
    v->codecs[0].video_fps     = 25;
    v->codecs[0].video_gop     = 15;

    uint8_t out[2048];
    int n = vham_build_sdp_body(&s, out, sizeof out);
    assert(n > 0);

    vham_sdp_t s2;
    assert(vham_parse_sdp_body(out, (size_t)n, &s2) == 0);
    assert(s2.media_count == 2);
    assert(s2.media[0].codec_count == 2);
    assert(s2.media[0].codecs[1].payload_type == 106);
    assert(s2.media[0].codecs[1].clock_rate == 48000);
    assert(strcmp(s2.media[0].codecs[1].name, "Opus") == 0);

    assert(s2.media[1].media_type == VHAM_SDP_MEDIA_VIDEO);
    assert(s2.media[1].codecs[0].video_width   == 320);
    assert(s2.media[1].codecs[0].video_height  == 240);
    assert(s2.media[1].codecs[0].video_bitrate == 300000);
    assert(s2.media[1].codecs[0].video_fps     == 25);
    assert(s2.media[1].codecs[0].video_gop     == 15);
}

/* SDP type-1 (WebRTC variant) round-trip */
static void test_sdp_type1_roundtrip(void) {
    vham_sdp_t s;
    memset(&s, 0, sizeof s);
    s.origin_ipv4 = 0xc0a80101;
    s.origin_port = 20000;
    s.is_type1 = 1;
    s.type1_bytes[0] = 1;
    snprintf(s.type1_ice_ufrag,   sizeof s.type1_ice_ufrag,   "user1");
    snprintf(s.type1_ice_pwd,     sizeof s.type1_ice_pwd,     "pass1");
    snprintf(s.type1_setup,       sizeof s.type1_setup,       "passive");
    snprintf(s.type1_fingerprint, sizeof s.type1_fingerprint, "sha-256 AA:BB:CC");
    snprintf(s.type1_sdp_text,    sizeof s.type1_sdp_text,
             "v=0\r\nm=audio 9 RTP/AVP 0\r\n");

    uint8_t out[8192];
    int n = vham_build_sdp_body(&s, out, sizeof out);
    assert(n > 0);

    vham_sdp_t s2;
    assert(vham_parse_sdp_body(out, (size_t)n, &s2) == 0);
    assert(s2.is_type1);
    assert(strcmp(s2.type1_ice_ufrag,  "user1") == 0);
    assert(strcmp(s2.type1_setup,      "passive") == 0);
    assert(strstr(s2.type1_sdp_text,   "m=audio") != NULL);
}

/* SDP malformed-input tests */
static void test_sdp_robustness(void) {
    vham_sdp_t s;
    /* Empty buffer */
    assert(vham_parse_sdp_body("", 0, &s) == -1);
    /* Header only, no media_count */
    uint8_t buf[8] = {0};
    assert(vham_parse_sdp_body(buf, 8, &s) == -1);
    /* media_count too big */
    uint8_t buf2[9] = {0};
    buf2[8] = 99;
    assert(vham_parse_sdp_body(buf2, 9, &s) == -1);
    /* Codec name larger than its max — fill rest with non-NUL so the
     * string never terminates within the buffer. */
    uint8_t buf3[256];
    memset(buf3, 0xFF, sizeof buf3);
    /* origin header (8B zero) */
    for (int i = 0; i < 8; ++i) buf3[i] = 0;
    buf3[8] = 1;                       /* media_count = 1 */
    /* media: addr(8) + packed + media_type + reserved + bw(4) + codec_count */
    for (int i = 9; i <= 9+7; ++i) buf3[i] = 0;    /* media addr */
    buf3[9+8]  = 0;                    /* packed */
    buf3[9+9]  = 0;                    /* media_type=audio */
    buf3[9+10] = 0;                    /* reserved */
    for (int i = 0; i < 4; ++i) buf3[9+11+i] = 0;  /* bw */
    buf3[9+15] = 1;                    /* codec_count = 1 */
    /* codec header starts at byte 9+16 = 25:
     *   pt(1) channels(1) clock(4) name(...) — name region is all 0xFF
     *   so rd_str runs past the codec name max and fails. */
    buf3[25] = 0; buf3[26] = 0;        /* pt, channels */
    for (int i = 0; i < 4; ++i) buf3[27+i] = 0;   /* clock */
    /* bytes 31..255 are 0xFF — no NUL in codec name region → fail */
    assert(vham_parse_sdp_body(buf3, sizeof buf3, &s) == -1);
}

/* ---------------- RTP / G.711 / DTMF / voice tests ---------------- */

static void test_rtp_basic_roundtrip(void) {
    uint8_t pl[160];
    for (int i = 0; i < 160; ++i) pl[i] = (uint8_t)(i ^ 0xA5);

    vham_rtp_pkt_t in = {
        .payload_type = VHAM_RTP_PT_PCMU,
        .marker       = 1,
        .sequence     = 0xCAFE,
        .timestamp    = 0xDEADBEEF,
        .ssrc         = 0x12345678,
        .payload      = pl,
        .payload_len  = sizeof pl,
    };
    uint8_t buf[300];
    int n = vham_rtp_build(&in, buf, sizeof buf);
    assert(n == 12 + 160);

    /* Header byte 0: V=2 P=0 X=0 CC=0 → 10 000 000 = 0x80 */
    assert(buf[0] == 0x80);
    /* Header byte 1: M=1 PT=0 → 0x80 */
    assert(buf[1] == 0x80);
    assert(buf[2] == 0xCA && buf[3] == 0xFE);
    assert(buf[4] == 0xDE && buf[5] == 0xAD &&
           buf[6] == 0xBE && buf[7] == 0xEF);
    assert(buf[8] == 0x12 && buf[9] == 0x34 &&
           buf[10]== 0x56 && buf[11]== 0x78);

    vham_rtp_pkt_t out;
    assert(vham_rtp_parse(buf, (size_t)n, &out) == 0);
    assert(out.version == 2);
    assert(out.marker == 1);
    assert(out.payload_type == 0);
    assert(out.sequence == 0xCAFE);
    assert(out.timestamp == 0xDEADBEEF);
    assert(out.ssrc == 0x12345678);
    assert(out.payload_len == sizeof pl);
    assert(memcmp(out.payload, pl, sizeof pl) == 0);
}

static void test_rtp_csrc_and_extension(void) {
    uint8_t ext_payload[12] = { 1,2,3,4,5,6,7,8,9,10,11,12 };
    uint8_t media[40];
    for (size_t i = 0; i < sizeof media; ++i) media[i] = (uint8_t)i;

    vham_rtp_pkt_t in = {
        .payload_type   = 96,
        .sequence       = 100,
        .timestamp      = 1000,
        .ssrc           = 0xAABBCCDD,
        .csrc_count     = 2,
        .csrc           = { 0x11111111, 0x22222222 },
        .have_extension = 1,
        .extension      = 1,
        .ext_profile    = 0xBEDE,
        .ext_word_count = 3,
        .ext_data       = ext_payload,
        .payload        = media,
        .payload_len    = sizeof media,
    };
    uint8_t buf[300];
    int n = vham_rtp_build(&in, buf, sizeof buf);
    assert(n == 12 + 8 /*csrcs*/ + 4 + 12 /*ext*/ + 40);

    vham_rtp_pkt_t out;
    assert(vham_rtp_parse(buf, (size_t)n, &out) == 0);
    assert(out.csrc_count == 2);
    assert(out.csrc[0] == 0x11111111 && out.csrc[1] == 0x22222222);
    assert(out.have_extension);
    assert(out.ext_profile == 0xBEDE);
    assert(out.ext_word_count == 3);
    assert(memcmp(out.ext_data, ext_payload, 12) == 0);
    assert(out.payload_len == sizeof media);
    assert(memcmp(out.payload, media, sizeof media) == 0);
}

static void test_rtp_padding(void) {
    uint8_t media[16];
    for (int i = 0; i < 16; ++i) media[i] = (uint8_t)i;
    vham_rtp_pkt_t in = {
        .payload_type = 0,
        .padding      = 1,
        .padding_len  = 4,
        .payload      = media,
        .payload_len  = sizeof media,
    };
    uint8_t buf[200];
    int n = vham_rtp_build(&in, buf, sizeof buf);
    assert(n == 12 + 16 + 4);
    assert(buf[0] == (0x80 | 0x20));   /* V=2 P=1 */
    assert(buf[n - 1] == 4);            /* trailing length */

    vham_rtp_pkt_t out;
    assert(vham_rtp_parse(buf, (size_t)n, &out) == 0);
    assert(out.padding == 1);
    assert(out.padding_len == 4);
    assert(out.payload_len == 16);
    assert(memcmp(out.payload, media, 16) == 0);
}

static void test_rtp_robustness(void) {
    vham_rtp_pkt_t out;
    /* Too short */
    uint8_t tiny[5] = { 0x80, 0, 0, 0, 0 };
    assert(vham_rtp_parse(tiny, sizeof tiny, &out) == -1);
    /* Wrong version */
    uint8_t badver[12] = { 0xC0, 0,0,0,0,0,0,0,0,0,0,0 };
    assert(vham_rtp_parse(badver, sizeof badver, &out) == -1);
    /* CSRC count claims too many */
    uint8_t toomany[12] = { 0x8F, 0,0,0,0,0,0,0,0,0,0,0 }; /* CC=15 */
    assert(vham_rtp_parse(toomany, sizeof toomany, &out) == -1);
}

/* G.711 µ-law round-trip across the full 16-bit input range.
 * Per ITU-T G.711 the SQNR after encode/decode is bounded; we only
 * assert that monotonic input maps to monotonic output and that a
 * handful of canonical values round-trip exactly. */
static void test_g711_ulaw(void) {
    /* Silence */
    assert(vham_g711_linear_to_ulaw(0) == 0xff);
    assert(vham_g711_ulaw_to_linear(0xff) == 0);

    /* +Full scale and -full scale */
    uint8_t pos = vham_g711_linear_to_ulaw(32635);
    uint8_t neg = vham_g711_linear_to_ulaw(-32635);
    assert(pos == 0x80);
    assert(neg == 0x00);

    /* Sign symmetry */
    for (int v = 1; v < 30000; v += 137) {
        uint8_t a = vham_g711_linear_to_ulaw((int16_t)v);
        uint8_t b = vham_g711_linear_to_ulaw((int16_t)-v);
        /* µ-law sign bit is bit 7 (after the final XOR with 0xff):
         * positive → bit cleared, negative → bit set. So a has bit
         * 7 high (after XOR) and b has it low. */
        assert((a & 0x80) != (b & 0x80));
    }

    /* Round-trip preserves the *quantized* sample. The standard
     * permits some error; assert it's within the maximum step size
     * for each segment. */
    int max_err = 0;
    for (int v = -32000; v <= 32000; v += 31) {
        uint8_t c = vham_g711_linear_to_ulaw((int16_t)v);
        int16_t d = vham_g711_ulaw_to_linear(c);
        int err = (int)d - v;
        if (err < 0) err = -err;
        if (err > max_err) max_err = err;
    }
    /* G.711 µ-law step size at full scale is ~512. Allow a margin. */
    assert(max_err < 600);
}

static void test_g711_alaw(void) {
    /* Sign symmetry across the buffer encoder */
    int16_t pcm[8] = { 0, 1, -1, 100, -100, 10000, -10000, 32000 };
    uint8_t enc[8];
    int16_t dec[8];
    vham_g711_encode_alaw(pcm, 8, enc);
    vham_g711_decode_alaw(enc, 8, dec);
    /* The sign of decoded matches input */
    for (int i = 0; i < 8; ++i) {
        if (pcm[i] > 0) assert(dec[i] >= 0);
        if (pcm[i] < 0) assert(dec[i] <= 0);
    }
    /* Quantization error bounded */
    int max_err = 0;
    for (int v = -32000; v <= 32000; v += 31) {
        uint8_t c = vham_g711_linear_to_alaw((int16_t)v);
        int16_t d = vham_g711_alaw_to_linear(c);
        int err = (int)d - v;
        if (err < 0) err = -err;
        if (err > max_err) max_err = err;
    }
    assert(max_err < 600);
}

static void test_dtmf(void) {
    vham_dtmf_event_t in = {
        .event    = VHAM_DTMF_5,
        .end      = 1,
        .reserved = 0,
        .volume   = 10,
        .duration = 1600,
    };
    uint8_t b[4];
    assert(vham_dtmf_build(&in, b, sizeof b) == 4);
    /* byte 0 = event = 5 */
    assert(b[0] == 5);
    /* byte 1 = E(1)<<7 | R<<6 | volume = 0x80 | 10 = 0x8a */
    assert(b[1] == 0x8a);
    /* bytes 2-3 = BE duration 1600 = 0x0640 */
    assert(b[2] == 0x06 && b[3] == 0x40);

    vham_dtmf_event_t out;
    assert(vham_dtmf_parse(b, 4, &out) == 0);
    assert(out.event == 5 && out.end == 1 && out.volume == 10
        && out.duration == 1600);

    assert(vham_dtmf_from_char('0') == 0);
    assert(vham_dtmf_from_char('9') == 9);
    assert(vham_dtmf_from_char('*') == VHAM_DTMF_STAR);
    assert(vham_dtmf_from_char('#') == VHAM_DTMF_POUND);
    assert(vham_dtmf_from_char('A') == VHAM_DTMF_A);
    assert(vham_dtmf_from_char('z') == -1);
}

/* End-to-end voice TX → RX round-trip: encode PCM via voice_tx,
 * shove the produced RTP bytes through voice_rx, get PCM back out. */
static void test_voice_pcm_roundtrip(void) {
    vham_voice_tx_t tx;
    vham_voice_tx_init(&tx, VHAM_RTP_PT_PCMU, 0xABCDEF01);

    vham_voice_rx_t rx;
    vham_voice_rx_init(&rx);

    /* Generate a 440 Hz tone for 5 frames (100ms) */
    int16_t pcm_in[VHAM_VOICE_SAMPLES];
    uint8_t pkt[1500];
    vham_voice_frame_t frame;

    for (int f = 0; f < 5; ++f) {
        for (size_t i = 0; i < VHAM_VOICE_SAMPLES; ++i) {
            /* simple triangle wave so we don't depend on libm */
            int t = (f * VHAM_VOICE_SAMPLES + (int)i) % 200;
            pcm_in[i] = (int16_t)((t < 100 ? t : 200 - t) * 200);
        }
        int n = vham_voice_tx_pcm_frame(&tx, pcm_in, VHAM_VOICE_SAMPLES,
                                        f == 0, pkt, sizeof pkt);
        assert(n == 12 + (int)VHAM_VOICE_SAMPLES);

        int rc = vham_voice_rx_feed(&rx, pkt, (size_t)n, &frame);
        assert(rc == 0);
        assert(frame.kind == VHAM_VOICE_FRAME_AUDIO);
        assert(frame.payload_type == VHAM_RTP_PT_PCMU);
        assert(frame.pcm_samples == VHAM_VOICE_SAMPLES);
        assert(frame.marker == (f == 0 ? 1 : 0));
        /* Lossy round-trip — just spot-check error bound */
        int max_err = 0;
        for (size_t i = 0; i < VHAM_VOICE_SAMPLES; ++i) {
            int err = (int)frame.pcm[i] - (int)pcm_in[i];
            if (err < 0) err = -err;
            if (err > max_err) max_err = err;
        }
        assert(max_err < 600);
    }
    assert(rx.pkt_count == 5);
    assert(rx.lost_count == 0);
    assert(rx.drop_count == 0);
}

/* Drop one packet in the middle, verify rx counts the loss. */
static void test_voice_loss_detection(void) {
    vham_voice_tx_t tx;
    vham_voice_tx_init(&tx, VHAM_RTP_PT_PCMU, 0x11223344);
    vham_voice_rx_t rx;
    vham_voice_rx_init(&rx);

    int16_t pcm[VHAM_VOICE_SAMPLES] = { 0 };
    uint8_t pkt[1500];
    vham_voice_frame_t frame;
    for (int f = 0; f < 10; ++f) {
        int n = vham_voice_tx_pcm_frame(&tx, pcm, VHAM_VOICE_SAMPLES, 0,
                                        pkt, sizeof pkt);
        assert(n > 0);
        if (f == 4) continue;        /* drop this packet */
        (void)vham_voice_rx_feed(&rx, pkt, (size_t)n, &frame);
    }
    assert(rx.pkt_count == 9);
    assert(rx.lost_count == 1);
}

/* DTMF over RTP: send via voice_tx_dtmf, parse via voice_rx_feed. */
static void test_voice_dtmf_roundtrip(void) {
    vham_voice_tx_t tx;
    vham_voice_tx_init(&tx, VHAM_RTP_PT_PCMU, 0xDEAFBEEF);

    vham_voice_rx_t rx;
    vham_voice_rx_init(&rx);

    uint8_t pkt[64];
    int n = vham_voice_tx_dtmf(&tx, VHAM_DTMF_7, 10, VHAM_VOICE_SAMPLES,
                               0, pkt, sizeof pkt);
    assert(n == 12 + 4);

    vham_voice_frame_t frame;
    assert(vham_voice_rx_feed(&rx, pkt, (size_t)n, &frame) == 0);
    assert(frame.kind == VHAM_VOICE_FRAME_DTMF);
    assert(frame.dtmf.event == VHAM_DTMF_7);
    assert(frame.dtmf.duration == VHAM_VOICE_SAMPLES);
    assert(rx.dtmf_count == 1);
}

/* Verify the MM-notification parser recognizes the exact 60-byte
 * frame we captured from the live server (sub_opcode=0x21 = call
 * incoming). Bytes are reproduced verbatim from our trace. */
static void test_mm_notify_call_incoming(void) {
    const uint8_t frame[] = {
        /* TAP header */
        0x01,0x00, 0x00,0x00, 0xc0,0x6b,0x26,0x6a,
        0x00,0x01, 0x00,0x11, 0x00,0x00,0x00,0x2c,
        /* SRVMSG header: Dst=MM(4) Src=CC(5) wMsgId=0x11 FsmIds=-1 dwMsgLen=0x1c */
        0x04,0x05, 0x00,0x11, 0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff, 0x00,0x00,0x00,0x1c,
        /* IE 0x1d (RegType=3) */
        0x00,0x1d, 0x00,0x01, 0x03,
        /* IE 0x1e (sub_opcode=0x0021) */
        0x00,0x1e, 0x00,0x02, 0x00,0x21,
        /* IE 0x27 (callee's num "V00000000002\0") */
        0x00,0x27, 0x00,0x0d,
        'V','0','0','0','0','0','0','0','0','0','0','2',0x00,
    };
    vham_mm_notify_t note;
    int rc = vham_parse_mm_notify(frame, sizeof frame, &note);
    assert(rc == 0);
    assert(note.have_notify);
    assert(note.sub_opcode == 0x0021);
    assert(note.notify_status == 0x03);
    /* The recorded frame literally contains this number in its bytes,
     * so the parsed value isn't parameterizable like other tests. */
    assert(strcmp(note.echoed_num, CAPTURED_NUM_NOTIFY) == 0);
}

/* Verify OrgList (IE 0x5c, Tap variant) parser against the exact
 * 150-byte body we captured from a live REGRSP. */
static void test_orglist_parse(void) {
    const uint8_t body[] = {
        0x00,0x01,
        '2','0','2','2','0','6','0','9','1','2','2','8','1','7','5','2',0x00,
        'H','A','M',0x00,
        0x00,                                /* Desc = "" */
        0x00,0x00,0x23,0x28,                 /* UserNum = 9000 */
        0x00,0x00,0x00,0x00,                 /* DsNum = 0 */
        'H','A','M',0x00,                    /* DS0Num = "HAM" */
        0x00,                                /* DS0Pwd = "" */
        /* DSName = "领朋智慧通信平台" (UTF-8) */
        0xe9,0xa2,0x86,0xe6,0x9c,0x8b,0xe6,0x99,0xba,
        0xe6,0x85,0xa7,0xe9,0x80,0x9a,0xe4,0xbf,0xa1,
        0xe5,0xb9,0xb3,0xe5,0x8f,0xb0,0x00,
        0x00,                                /* DsIcon = "" */
        /* AppName = same Chinese string */
        0xe9,0xa2,0x86,0xe6,0x9c,0x8b,0xe6,0x99,0xba,
        0xe6,0x85,0xa7,0xe9,0x80,0x9a,0xe4,0xbf,0xa1,
        0xe5,0xb9,0xb3,0xe5,0x8f,0xb0,0x00,
        /* AppIcon = "/upload/system_icon/...-logo.png" */
        '/','u','p','l','o','a','d','/','s','y','s','t','e','m','_',
        'i','c','o','n','/',
        '6','6','a','5','b','1','3','0','8','e','9','3','4','e','7','5',
        '9','1','0','a','d','b','1','f','7','3','b','b','f','b','2','6',
        '-','l','o','g','o','.','p','n','g',0x00,
    };
    vham_orglist_t ol;
    int rc = vham_parse_orglist(body, sizeof body, &ol);
    assert(rc == 0);
    assert(ol.count == 1);
    assert(strcmp(ol.entries[0].num,     "2022060912281752") == 0);
    assert(strcmp(ol.entries[0].name,    "HAM") == 0);
    assert(strcmp(ol.entries[0].desc,    "") == 0);
    assert(ol.entries[0].user_num == 9000);
    assert(ol.entries[0].ds_num   == 0);
    assert(strcmp(ol.entries[0].ds0_num, "HAM") == 0);
    assert(strcmp(ol.entries[0].ds0_pwd, "") == 0);
    assert(strstr(ol.entries[0].app_icon, "logo.png") != NULL);
}

/* UsrGInfo round-trip with a hand-built 2-entry body. */
static void test_user_ginfo_parse(void) {
    /* Build by hand: count=2, then 2 group entries. */
    uint8_t body[256];
    size_t i = 0;
    /* count */
    body[i++] = 0x00; body[i++] = 0x02;

    /* Entry 0: dispatcher's "HAM" group */
    body[i++] = 0x05;                          /* prio */
    body[i++] = 0x01;                          /* type */
    body[i++] = 0x02;                          /* ut_type */
    body[i++] = 0x00;                          /* attr */
    memcpy(body + i, "146520",  7); i += 7;    /* num */
    memcpy(body + i, "VHF-CALL",9); i += 9;    /* name */
    memcpy(body + i, "",        1); i += 1;    /* ag_num empty */
    body[i++] = 0x01;                          /* chan_num */
    body[i++] = 0x02;                          /* status */
    body[i++] = 0x00;                          /* fg_count */
    memcpy(body + i, "",        1); i += 1;    /* fg_num empty */

    /* Entry 1: another group */
    body[i++] = 0x04;
    body[i++] = 0x01;
    body[i++] = 0x02;
    body[i++] = 0x10;
    memcpy(body + i, "446000",   7); i += 7;
    memcpy(body + i, "UHF-CALL", 9); i += 9;
    memcpy(body + i, "146520",   7); i += 7;
    body[i++] = 0x02;
    body[i++] = 0x01;
    body[i++] = 0x01;
    memcpy(body + i, "9001",     5); i += 5;

    vham_user_ginfo_t info;
    int rc = vham_parse_user_ginfo(body, i, &info);
    assert(rc == 0);
    assert(info.count == 2);
    assert(info.entries[0].prio == 5);
    assert(strcmp(info.entries[0].num,  "146520")   == 0);
    assert(strcmp(info.entries[0].name, "VHF-CALL") == 0);
    assert(info.entries[0].chan_num == 1);
    assert(info.entries[1].prio == 4);
    assert(strcmp(info.entries[1].ag_num, "146520") == 0);
    assert(info.entries[1].fg_count == 1);
    assert(strcmp(info.entries[1].fg_num, "9001")   == 0);
}

/* Hand-build a CC_CONN with an embedded answer SDP, feed it to the
 * CC state machine, verify remote_sdp gets populated. */
static void test_cc_conn_answer_sdp(void) {
    /* Step 1: build a valid SDP body (loopback caller, port 30000). */
    vham_sdp_t s = {
        .origin_ipv4 = (10u<<24)|(0u<<16)|(0u<<8)|7u,
        .origin_port = 0,
        .media_count = 1,
        .media = {
            {
                .media_type = VHAM_SDP_MEDIA_AUDIO,
                .transport  = VHAM_SDP_TX_RTP_UDP,
                .ipv4 = (10u<<24)|(0u<<16)|(0u<<8)|7u,
                .port = 30000,
                .codec_count = 1,
                .codecs = {
                    { .payload_type = 0, .encoding_param = 1,
                      .clock_rate = 8000, .name = "PCMU" }
                }
            }
        }
    };
    uint8_t sdp_body[1024];
    int sdp_n = vham_build_sdp_body(&s, sdp_body, sizeof sdp_body);
    assert(sdp_n > 0);

    /* Step 2: synthesize a CC_CONN frame containing IE 0x19 = SDP. */
    uint8_t frame[2048];
    vham_buf_t b;
    vham_buf_init(&b, frame, sizeof frame);
    /* TAP header */
    vham_pack_u8 (&b, 0x01);
    vham_pack_u8 (&b, 0x00);
    vham_pack_u16(&b, 0x0000);                       /* CMD */
    vham_pack_u32(&b, 0x12345678);                   /* seq */
    vham_pack_u16(&b, VHAM_TAP_CLASS_CC);
    vham_pack_u16(&b, VHAM_CC_CONN);
    size_t tap_len_off = b.off;
    vham_pack_u32(&b, 0);
    size_t body_start = b.off;
    /* SRVMSG header */
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_CC, .ucSrc = VHAM_MOD_CC,
        .wMsgId = VHAM_CC_CONN, .dwDstFsmId = 1,
        .dwSrcFsmId = 99,                            /* server-side leg */
    };
    size_t srvmsg_len_off;
    vham_pack_srvmsg_header(&b, &sh, &srvmsg_len_off);
    size_t srvmsg_body = b.off;
    /* IE 0x19 SDP body */
    vham_pack_tlv_fix(&b, 1, VHAM_IE_CC_SDP_A, sdp_body, (size_t)sdp_n);
    vham_patch_srvmsg_len(&b, srvmsg_len_off, srvmsg_body);
    /* Patch TAP length */
    uint32_t tap_body = (uint32_t)(b.off - body_start);
    frame[tap_len_off    ] = (uint8_t)(tap_body >> 24);
    frame[tap_len_off + 1] = (uint8_t)(tap_body >> 16);
    frame[tap_len_off + 2] = (uint8_t)(tap_body >> 8);
    frame[tap_len_off + 3] = (uint8_t)(tap_body);

    /* Step 3: feed into the CC state machine, verify extraction. */
    vham_cc_call_t call;
    vham_cc_call_init(&call, TEST_USER_A, TEST_USER_B, 1);
    call.state = VHAM_CALL_SETUP_SENT;               /* in-flight call */
    vham_call_state_t st = vham_cc_call_recv(&call, frame, b.off);
    assert(st == VHAM_CALL_CONNECTED);
    assert(call.have_remote_sdp);
    assert(call.remote_sdp.media_count == 1);
    assert(call.remote_sdp.media[0].port == 30000);
    assert(call.remote_sdp.media[0].ipv4 == ((10u<<24)|7u));
    assert(call.remote_sdp.media[0].codec_count == 1);
    assert(call.remote_sdp.media[0].codecs[0].payload_type == 0);
    assert(strcmp(call.remote_sdp.media[0].codecs[0].name, "PCMU") == 0);
    assert(call.have_remote_leg);
    assert(call.remote_leg_id == 99);
}

/* MM_QUIT shape. */
static void test_mm_quit(void) {
    uint8_t buf[128];
    int n = vham_build_mm_quit(1, TEST_USER_A, buf, sizeof buf);
    assert(n > 0);
    /* TAP class=1 (MM), cmd=0x18 (MM_QUIT per GetSrvMsgStr table) */
    assert(buf[8]  == 0x00 && buf[9]  == 0x01);
    assert(buf[10] == 0x00 && buf[11] == 0x18);
}

/* Codec table: AMR/iLBC stubs are registered but encode/decode fail. */
static void test_codec_stubs(void) {
    vham_codec_init();
    vham_audio_codec_t *amr = vham_codec_by_pt(96);
    assert(amr && strcmp(amr->name, "AMR") == 0);
    int16_t pcm[160] = {0};  uint8_t out[160];
    int n = amr->encode(amr, pcm, 160, out, sizeof out);
    /* Without VHAM_WITH_AMR, the stub returns -1. With the real
     * libopencore-amrnb backend, the encoder succeeds. Accept both. */
#ifdef VHAM_WITH_AMR
    assert(n > 0);
#else
    assert(n == -1);
#endif
    (void)n;
    assert(vham_codec_by_pt(102) != NULL);   /* iLBC */
    assert(vham_codec_by_pt(97)  != NULL);   /* AMR-WB */
}

/* Token persistence: save then load returns identical record. */
static void test_token_store(void) {
    /* Use a temp dir so we don't touch the developer's real config. */
    char tmpdir[] = "/tmp/vham-test-XXXXXX";
    char *d = mkdtemp(tmpdir);
    assert(d != NULL);
    setenv("XDG_CONFIG_HOME", d, 1);

    vham_token_t in = { 0 };
    strcpy(in.user,   "TEST_USER");
    strcpy(in.token,  "abcd1234efgh");
    strcpy(in.yaoyun, "feat-A");
    in.last_reg_unix = 1747776000ULL;
    assert(vham_token_save(&in) == 0);

    vham_token_t out;
    assert(vham_token_load("TEST_USER", &out) == 0);
    assert(strcmp(out.user,   "TEST_USER")    == 0);
    assert(strcmp(out.token,  "abcd1234efgh") == 0);
    assert(strcmp(out.yaoyun, "feat-A")       == 0);
    assert(out.last_reg_unix == 1747776000ULL);

    assert(vham_token_clear("TEST_USER") == 0);
    assert(vham_token_load("TEST_USER", &out) == -1);
}

/* DTLS-SRTP stub returns -1 / NULL when VHAM_WITH_DTLS isn't set. */
static void test_srtp_stub(void) {
    /* Default build: unavailable. If VHAM_WITH_DTLS is on we'd expect
     * 1 here — the call should still not crash. */
    int avail = vham_srtp_available();
    (void)avail;
    vham_srtp_session_t *s = vham_srtp_open("cert", "key", 0);
    if (!avail) assert(s == NULL);
    vham_srtp_close(s);   /* must be safe on NULL */
}

/* H.264 round-trip: large NAL fragments via FU-A, reassemble. */
static void test_h264_fua_roundtrip(void) {
    /* Build a 4500-byte synthetic NAL (type=5 = IDR slice). */
    uint8_t nal[4500];
    nal[0] = 0x65;                           /* F=0 NRI=11 type=5 */
    for (size_t i = 1; i < sizeof nal; ++i) nal[i] = (uint8_t)(i & 0xff);

    vham_h264_slice_t slices[8];
    int n = vham_h264_fragment(nal, sizeof nal, 1400, slices, 8);
    assert(n > 1);
    /* First slice has start bit, last has end + marker. */
    assert((slices[0].data[1] & 0x80) != 0);
    assert((slices[n-1].data[1] & 0x40) != 0);
    assert(slices[n-1].marker == 1);

    vham_h264_rx_t rx;
    vham_h264_rx_init(&rx);
    uint8_t out[8192];
    int got = 0;
    for (int i = 0; i < n; ++i) {
        int rc = vham_h264_rx_feed(&rx, slices[i].data, slices[i].length,
                                   out, sizeof out);
        if (rc > 0) got = rc;
    }
    assert(got == (int)sizeof nal);
    assert(memcmp(out, nal, sizeof nal) == 0);
}

/* Small NAL fits in a single packet — no fragmentation. */
static void test_h264_small_single(void) {
    uint8_t nal[] = { 0x67, 0x42, 0x00, 0x0a, 0x96, 0x35 };  /* SPS, short */
    vham_h264_slice_t s[2];
    int n = vham_h264_fragment(nal, sizeof nal, 1400, s, 2);
    assert(n == 1);
    assert(s[0].length == sizeof nal);
    assert(s[0].marker == 1);

    vham_h264_rx_t rx;
    vham_h264_rx_init(&rx);
    uint8_t out[64];
    int rc = vham_h264_rx_feed(&rx, s[0].data, s[0].length, out, sizeof out);
    assert(rc == (int)sizeof nal);
    assert(memcmp(out, nal, sizeof nal) == 0);
}

/* GPS report builds with expected header bytes. */
static void test_gps_report(void) {
    vham_gps_report_t g = {
        .latitude = 37.7749f, .longitude = -122.4194f,
        .speed_kph = 5.0f, .heading_deg = 90.0f,
        .altitude_m = 20, .accuracy_m = 5,
        .satellites = 8, .fix_quality = 1,
        .timestamp = 1747776000, .batt_pct = 78,
    };
    uint8_t buf[256];
    int n = vham_build_gps_report(1, TEST_USER_A, &g, buf, sizeof buf);
    assert(n > 0);
    /* TAP class=MM(1), cmd=0x92 */
    assert(buf[8]  == 0x00 && buf[9]  == 0x01);
    assert(buf[10] == 0x00 && buf[11] == 0x92);
}

/* IM round-trip via PASSTHROUGH carrier. */
static void test_im_roundtrip(void) {
    vham_im_t in = {
        .code = 1, .type = 0, .ut_sn = 99,
        .sn   = "msg-abc",
        .time = "2026-05-21T10:00:00Z",
        .from = TEST_USER_A,
        .to   = TEST_USER_B,
        .ori_to = TEST_USER_B,
        .text = "hello world",
        .file_name = "",
        .source_file_name = "",
    };
    uint8_t buf[2048];
    int n = vham_build_im(7, &in, buf, sizeof buf);
    assert(n > 0);

    vham_im_t out;
    char scratch[2048];
    int rc = vham_parse_im(buf, (size_t)n, &out, scratch, sizeof scratch);
    assert(rc == 0);
    assert(out.code == 1);
    assert(out.ut_sn == 99);
    assert(strcmp(out.sn,   "msg-abc")            == 0);
    assert(strcmp(out.from, TEST_USER_A)        == 0);
    assert(strcmp(out.to,   TEST_USER_B)        == 0);
    assert(strcmp(out.text, "hello world")         == 0);
}

/* RFC 4571: frame + unframe round-trip. */
static void test_rfc4571(void) {
    uint8_t rtp[200];
    for (size_t i = 0; i < sizeof rtp; ++i) rtp[i] = (uint8_t)i;
    uint8_t framed[256];
    int n = vham_rtp_tcp_frame(rtp, sizeof rtp, framed, sizeof framed);
    assert(n == (int)(sizeof rtp + 2));
    assert(framed[0] == 0x00 && framed[1] == 0xc8);

    const uint8_t *body = NULL;
    size_t blen = 0;
    int consumed = vham_rtp_tcp_unframe(framed, (size_t)n, &body, &blen);
    assert(consumed == n);
    assert(blen == sizeof rtp);
    assert(memcmp(body, rtp, sizeof rtp) == 0);

    /* Partial input → returns 0 (need more bytes) */
    assert(vham_rtp_tcp_unframe(framed, 1, &body, &blen) == 0);
    /* Header says 200 but we only have 50 — still 0 */
    assert(vham_rtp_tcp_unframe(framed, 50, &body, &blen) == 0);
}

/* Segment reassembly: feed 3 fragments of a 3500-byte body. */
static void test_segment_reassemble(void) {
    vham_seg_t s;
    vham_seg_init(&s);
    /* Build a known body */
    uint8_t whole[3500];
    for (size_t i = 0; i < sizeof whole; ++i) whole[i] = (uint8_t)(i & 0xff);

    const uint8_t *out_buf = NULL;
    size_t out_len = 0;
    /* Out-of-order fragments */
    assert(vham_seg_feed(&s, 4, 99, 3500, 1384, whole + 1384, 1384,
                         &out_buf, &out_len) == 0);
    assert(vham_seg_feed(&s, 4, 99, 3500, 2768, whole + 2768,
                         3500 - 2768, &out_buf, &out_len) == 0);
    int rc = vham_seg_feed(&s, 4, 99, 3500, 0, whole, 1384,
                           &out_buf, &out_len);
    assert(rc == 1);
    assert(out_len == 3500);
    assert(memcmp(out_buf, whole, sizeof whole) == 0);
    vham_seg_release(&s, 4, 99);
}

/* TAP retransmit tracker. */
static void test_retx(void) {
    vham_retx_t r;
    vham_retx_init(&r);
    uint8_t buf[] = { 1, 2, 3, 4 };

    assert(vham_retx_track(&r, 1, 100, buf, 4, 1000) == 0);
    assert(vham_retx_track(&r, 1, 101, buf, 4, 1000) == 0);

    /* Nothing due yet at t=1100 with 200ms retry. */
    assert(vham_retx_next_due(&r, 1100, 200) == NULL);

    /* At t=1250, both are due. */
    vham_retx_pkt_t *p = vham_retx_next_due(&r, 1250, 200);
    assert(p && (p->seq == 100 || p->seq == 101));
    vham_retx_mark_resent(&r, p, 1250);

    /* ACK one — it should clear. */
    assert(vham_retx_ack(&r, 1, 100) == 1);
    /* Acking unknown returns 0. */
    assert(vham_retx_ack(&r, 1, 999) == 0);

    /* Drain by exceeding max retries. */
    for (int t = 0; t < 10; ++t) {
        p = vham_retx_next_due(&r, (uint64_t)(2000 + 200*t), 200);
        if (!p) break;
        vham_retx_mark_resent(&r, p, (uint64_t)(2000 + 200*t));
    }
    assert(r.gave_up >= 1);
}

/* RTCP SR encode + parse round-trip. */
static void test_rtcp_sr_roundtrip(void) {
    vham_rtcp_rr_block_t blocks[1] = {{
        .ssrc = 0x77777777,
        .fraction_lost = 5,
        .cumulative_lost = 42,
        .highest_seq = 100,
        .jitter = 200,
        .lsr = 0xdeadbeef,
        .dlsr = 0x12345,
    }};
    uint8_t buf[256];
    int n = vham_rtcp_build_sr(0xaaaaaaaa, 0x1122334455667788ULL,
                               0xc0ffee, 1000, 80000,
                               blocks, 1, "alice@example",
                               buf, sizeof buf);
    assert(n > 0);
    vham_rtcp_pkt_t pkt;
    int consumed = vham_rtcp_parse(buf, (size_t)n, &pkt);
    assert(consumed > 0);
    assert(pkt.pt == VHAM_RTCP_PT_SR);
    assert(pkt.ssrc == 0xaaaaaaaa);
    assert(pkt.ntp_ts == 0x1122334455667788ULL);
    assert(pkt.rtp_ts == 0xc0ffee);
    assert(pkt.packets == 1000);
    assert(pkt.octets == 80000);
    assert(pkt.block_count == 1);
    assert(pkt.blocks[0].ssrc == 0x77777777);
    assert(pkt.blocks[0].fraction_lost == 5);
    assert(pkt.blocks[0].cumulative_lost == 42);
    /* The SDES packet follows in the compound */
    vham_rtcp_pkt_t sdes;
    int c2 = vham_rtcp_parse(buf + consumed, (size_t)(n - consumed), &sdes);
    assert(c2 > 0);
    assert(sdes.pt == VHAM_RTCP_PT_SDES);
}

/* RTCP RR (no sender info) round-trip. */
static void test_rtcp_rr_roundtrip(void) {
    uint8_t buf[128];
    int n = vham_rtcp_build_rr(0x11111111, NULL, 0, "bob", buf, sizeof buf);
    assert(n > 0);
    vham_rtcp_pkt_t pkt;
    int consumed = vham_rtcp_parse(buf, (size_t)n, &pkt);
    assert(consumed > 0);
    assert(pkt.pt == VHAM_RTCP_PT_RR);
    assert(pkt.ssrc == 0x11111111);
    assert(pkt.block_count == 0);
}

/* Mic-grant gating: TX emits when held, suppresses when not held. */
static void test_voice_mic_gate(void) {
    vham_voice_tx_t tx;
    vham_voice_tx_init(&tx, 0, 0x12345);
    int16_t pcm[160] = {0};
    uint8_t buf[256];

    /* Held by default → frame is emitted */
    int n1 = vham_voice_tx_pcm_frame(&tx, pcm, 160, 0, buf, sizeof buf);
    assert(n1 > 0);
    uint64_t after_held = tx.frame_index;

    /* Release mic → next frame is suppressed (no bytes, no advance) */
    vham_voice_tx_set_mic(&tx, 0);
    int n2 = vham_voice_tx_pcm_frame(&tx, pcm, 160, 0, buf, sizeof buf);
    assert(n2 == 0);
    assert(tx.frame_index == after_held);

    /* Reclaim → emits again */
    vham_voice_tx_set_mic(&tx, 1);
    int n3 = vham_voice_tx_pcm_frame(&tx, pcm, 160, 0, buf, sizeof buf);
    assert(n3 > 0);
}

#ifdef VHAM_WITH_AMR
/* AMR-NB round-trip via the codec dispatch table. */
static void test_codec_amrnb(void) {
    vham_audio_codec_t *c = vham_codec_by_pt(96);
    assert(c && c->frame_samples == 160 && c->clock_rate == 8000);
    int16_t pcm[160], pcm_out[160] = {0};
    for (int i = 0; i < 160; ++i)
        pcm[i] = (int16_t)(10000 * sin(2.0*M_PI*440.0*i/8000.0));
    uint8_t enc[64];
    int n = c->encode(c, pcm, 160, enc, sizeof enc);
    assert(n > 0);
    int dn = c->decode(c, enc, (size_t)n, pcm_out, 160);
    assert(dn == 160);
    int max_abs = 0;
    for (int i = 0; i < 160; ++i)
        if (pcm_out[i] > max_abs) max_abs = pcm_out[i];
    assert(max_abs > 500);
}

/* AMR-WB round-trip. */
static void test_codec_amrwb(void) {
    vham_audio_codec_t *c = vham_codec_by_pt(97);
    assert(c && c->frame_samples == 320 && c->clock_rate == 16000);
    int16_t pcm[320], pcm_out[320] = {0};
    for (int i = 0; i < 320; ++i)
        pcm[i] = (int16_t)(10000 * sin(2.0*M_PI*440.0*i/16000.0));
    uint8_t enc[128];
    int n = c->encode(c, pcm, 320, enc, sizeof enc);
    assert(n > 0);
    int dn = c->decode(c, enc, (size_t)n, pcm_out, 320);
    assert(dn == 320);
}
#endif

#ifdef VHAM_WITH_ILBC
/* iLBC round-trip. */
static void test_codec_ilbc(void) {
    vham_audio_codec_t *c = vham_codec_by_pt(102);
    assert(c && c->frame_samples == 160 && c->clock_rate == 8000);
    int16_t pcm[160], pcm_out[160] = {0};
    for (int i = 0; i < 160; ++i)
        pcm[i] = (int16_t)(10000 * sin(2.0*M_PI*440.0*i/8000.0));
    uint8_t enc[64];
    int n = c->encode(c, pcm, 160, enc, sizeof enc);
    assert(n == 38);                   /* fixed-size 20ms iLBC frame */
    int dn = c->decode(c, enc, (size_t)n, pcm_out, 160);
    assert(dn == 160);
}
#endif

#ifdef VHAM_WITH_DTLS
/* DTLS-SRTP smoke: confirm the module reports as available. A full
 * handshake test would need a peer instance and self-signed cert
 * material; this just exercises the init path. */
static void test_dtls_available(void) {
    assert(vham_srtp_available() == 1);
}
#endif

#ifdef VHAM_WITH_OPUS
/* Opus encode → decode round-trip via the codec dispatch table.
 * Output PCM should approximate the input — Opus is lossy so we
 * just check it's the right length and not silence. */
static void test_codec_opus(void) {
    vham_audio_codec_t *o = vham_codec_by_pt(106);
    assert(o);
    assert(strcmp(o->name, "opus") == 0);
    assert(o->clock_rate == 48000);
    assert(o->frame_samples == 960);

    /* Synthesize a 440 Hz tone at 48 kHz (one 20 ms frame). */
    int16_t pcm[960], pcm_out[960];
    for (int i = 0; i < 960; ++i)
        pcm[i] = (int16_t)(10000 * sin(2.0 * M_PI * 440.0 * i / 48000.0));

    uint8_t enc[1500];
    int en = o->encode(o, pcm, 960, enc, sizeof enc);
    assert(en > 0 && en < (int)sizeof enc);

    int dn = o->decode(o, enc, (size_t)en, pcm_out, 960);
    assert(dn == 960);

    /* Sanity-check the decoded output isn't all zeros. */
    int max_abs = 0;
    for (int i = 0; i < 960; ++i)
        if (pcm_out[i] > max_abs) max_abs = pcm_out[i];
    assert(max_abs > 1000);
}
#endif

/* Codec table lookup. */
static void test_codec_table(void) {
    vham_codec_init();
    vham_audio_codec_t *u = vham_codec_by_pt(0);
    vham_audio_codec_t *a = vham_codec_by_pt(8);
    assert(u && strcmp(u->name, "PCMU") == 0);
    assert(a && strcmp(a->name, "PCMA") == 0);
    /* Opus only present when built with VHAM_WITH_OPUS — accept either. */
    vham_audio_codec_t *o = vham_codec_by_pt(106);
    (void)o;
    /* Unknown PT returns NULL. */
    assert(vham_codec_by_pt(99) == NULL);

    /* Encode/decode round-trip via the table. */
    int16_t pcm[160], pcm_out[160];
    for (int i = 0; i < 160; ++i) pcm[i] = (int16_t)(i * 50);
    uint8_t enc[160];
    assert(u->encode(u, pcm, 160, enc, sizeof enc) == 160);
    assert(u->decode(u, enc, 160, pcm_out, 160)    == 160);
}

/* Jitter buffer reorders + delivers in timestamp order. */
static void test_jitter_reorder(void) {
    vham_jitter_t jb;
    vham_jitter_init(&jb, 8000, 40);
    /* Push 5 packets out of order; ts = 0, 160, 320, 480, 640 */
    uint8_t pl[160] = {0};
    pl[0] = 2; vham_jitter_push(&jb, 102, 320, pl, 160);  /* third */
    pl[0] = 0; vham_jitter_push(&jb, 100,   0, pl, 160);  /* first */
    pl[0] = 4; vham_jitter_push(&jb, 104, 640, pl, 160);
    pl[0] = 1; vham_jitter_push(&jb, 101, 160, pl, 160);
    pl[0] = 3; vham_jitter_push(&jb, 103, 480, pl, 160);

    /* All should pop out in order with payload[0] = 0..4 */
    vham_jitter_pkt_t out;
    for (uint8_t expected = 0; expected < 5; ++expected) {
        assert(vham_jitter_pop(&jb, &out) == 1);
        assert(out.payload[0] == expected);
    }
    /* No more available */
    assert(vham_jitter_pop(&jb, &out) == 0);
    assert(jb.delivered == 5);
    assert(jb.dropped_late == 0);
}

/* Late packets are dropped. */
static void test_jitter_late_drop(void) {
    vham_jitter_t jb;
    vham_jitter_init(&jb, 8000, 40);
    uint8_t pl[160] = {0};
    /* Get past warm-up */
    vham_jitter_push(&jb, 100, 0,   pl, 160);
    vham_jitter_push(&jb, 101, 160, pl, 160);
    vham_jitter_push(&jb, 102, 320, pl, 160);
    vham_jitter_pkt_t out;
    vham_jitter_pop(&jb, &out);                            /* base_ts = 160 */
    vham_jitter_pop(&jb, &out);                            /* base_ts = 320 */
    /* This is now late: */
    int rc = vham_jitter_push(&jb, 99, 0, pl, 160);
    assert(rc == -1);
    assert(jb.dropped_late == 1);
}

/* MM_STATUSNOTIFY (0x91) parser smoke test. */
static void test_status_notify_parse(void) {
    /* Synthesize a STATUSNOTIFY frame. */
    uint8_t frame[128];
    vham_buf_t b;
    vham_buf_init(&b, frame, sizeof frame);
    vham_pack_u8(&b, 0x01); vham_pack_u8(&b, 0x00);
    vham_pack_u16(&b, VHAM_TAP_FLAG_NORMAL);
    vham_pack_u32(&b, 0x12345);
    vham_pack_u16(&b, VHAM_TAP_CLASS_MM);
    vham_pack_u16(&b, 0x0091);
    size_t tap_len = b.off; vham_pack_u32(&b, 0);
    size_t body = b.off;
    vham_srvmsg_hdr_t sh = {
        .ucDst = VHAM_MOD_MM, .ucSrc = VHAM_MOD_MM,
        .wMsgId = 0x0091, .dwDstFsmId = 0xffffffff,
        .dwSrcFsmId = 0xffffffff,
    };
    size_t srv_len_off;
    vham_pack_srvmsg_header(&b, &sh, &srv_len_off);
    size_t srv_body = b.off;
    vham_pack_tlv_str(&b, 1, VHAM_IE_IDENTITY_NUM, TEST_USER_B);
    vham_pack_tlv_u32(&b, 1, VHAM_IE_COUNTER, 42);
    vham_pack_tlv_u8 (&b, 1, VHAM_IE_REG_TYPE, 2);
    vham_pack_tlv_str(&b, 1, 0x006c, TEST_USER_A);
    vham_patch_srvmsg_len(&b, srv_len_off, srv_body);
    uint32_t tap_body = (uint32_t)(b.off - body);
    frame[tap_len    ] = (uint8_t)(tap_body >> 24);
    frame[tap_len + 1] = (uint8_t)(tap_body >> 16);
    frame[tap_len + 2] = (uint8_t)(tap_body >> 8);
    frame[tap_len + 3] = (uint8_t)(tap_body);

    vham_status_notify_t n;
    assert(vham_parse_status_notify(frame, b.off, &n) == 0);
    assert(n.have_subject && strcmp(n.subject_num, TEST_USER_B) == 0);
    assert(n.have_counter && n.counter == 42);
    assert(n.have_status  && n.status == 2);
    assert(n.have_peer    && strcmp(n.peer_num, TEST_USER_A) == 0);
}

/* Cause code dictionary spot-checks. */
static void test_cause_dictionary(void) {
    /* The one we hit live. */
    assert(strcmp(vham_cause_name(0x002b), "no such group") == 0);
    /* Other well-known codes. */
    assert(strcmp(vham_cause_name(0x0000), "ok") == 0);
    assert(strcmp(vham_cause_name(0x0011), "user not found") == 0);
    assert(strcmp(vham_cause_name(0x0019), "auth required") == 0);
    /* Unknown returns "unknown" instead of NULL. */
    assert(strcmp(vham_cause_name(0xffff), "unknown") == 0);
    /* Lookup also exposes the Chinese name. */
    const vham_cause_t *c = vham_cause_lookup(0x002b);
    assert(c && c->name_cn && strlen(c->name_cn) > 0);
}

/* OAM_RSP parser against the exact bytes captured from the live
 * server in response to our GQueryU. */
static void test_oam_rsp_parse(void) {
    const uint8_t frame[] = {
        /* TAP */
        0x01,0x00, 0x00,0x00,  0xc0,0x6b,0x26,0x6a,
        0x00,0x04, 0x00,0x71,  0x00,0x00,0x00,0x50,
        /* SRVMSG: Dst=MM Src=API wMsg=0x71 FsmIds=-1 len=0x40 */
        0x04,0x03, 0x00,0x71,  0xff,0xff,0xff,0xff,
        0xff,0xff,0xff,0xff,   0x00,0x00,0x00,0x40,
        /* IE 0x02 status = 0x002b */
        0x00,0x02, 0x00,0x02,  0x00,0x2b,
        /* IE 0x1b op = 0xc (GQueryU) */
        0x00,0x1b, 0x00,0x04,  0x00,0x00,0x00,0x0c,
        /* IE 0x21 count = 0 */
        0x00,0x21, 0x00,0x04,  0x00,0x00,0x00,0x00,
        /* IE 0x40 target num (CAPTURED_NUM_A literal) */
        0x00,0x40, 0x00,0x0d,
        'V','0','0','0','0','0','0','0','0','0','0','1',0x00,
        /* IE 0x44 session_id = 0x1e8d */
        0x00,0x44, 0x00,0x04,  0x00,0x00,0x1e,0x8d,
        /* IE 0x5d sender = CAPTURED_NUM_A */
        0x00,0x5d, 0x00,0x0d,
        'V','0','0','0','0','0','0','0','0','0','0','1',0x00,
    };
    vham_oam_rsp_t r;
    int rc = vham_parse_oam_rsp(frame, sizeof frame, &r);
    assert(rc == 0);
    assert(r.have_status && r.status == 0x002b);
    assert(r.have_op && r.op_code == 0xc);
    assert(r.have_count && r.count == 0);
    assert(strcmp(r.target_num, CAPTURED_NUM_A) == 0);
    assert(strcmp(r.echoed_num, CAPTURED_NUM_A) == 0);
    assert(r.have_session_id && r.session_id == 0x1e8d);
    assert(!r.have_ginfo);
}

/* OAM frames build cleanly and have the expected wire shape. */
static void test_oam_frames(void) {
    uint8_t buf[512];
    int n;

    n = vham_build_oam_gqueryu(1, TEST_USER_A, TEST_USER_A, 100,
                               NULL, buf, sizeof buf);
    assert(n > 0);
    /* TAP class=4, cmd=0x70 */
    assert(buf[8]  == 0x00 && buf[9]  == 0x04);
    assert(buf[10] == 0x00 && buf[11] == 0x70);

    n = vham_build_oam_gaddu(2, TEST_USER_A, "146520", 100,
                             buf, sizeof buf);
    assert(n > 0);

    n = vham_build_oam_gdelu(3, TEST_USER_A, "146520", 100,
                             buf, sizeof buf);
    assert(n > 0);

    n = vham_build_oam_gmodify(4, TEST_USER_A, "146520",
                               "Test Group", 5, 100, buf, sizeof buf);
    assert(n > 0);

    n = vham_build_oam_gmodifyu(5, TEST_USER_A, "146520",
                                TEST_USER_B, NULL, 100, buf, sizeof buf);
    assert(n > 0);
}

/* CallExt (IE 0x50). */
static void test_callext(void) {
    uint8_t body[] = { 0x01, 0x02, 'X', 0, 'Y', 'Z', 0 };
    vham_callext_t c;
    assert(vham_parse_callext(body, sizeof body, &c) == 0);
    assert(c.a == 1 && c.b == 2);
    assert(strcmp(c.str_a, "X") == 0);
    assert(strcmp(c.str_b, "YZ") == 0);
}

/* CallStreamCtrl (IE 0x55). */
static void test_call_streamctrl(void) {
    uint8_t body[] = { 's','1', 0, 0x05, 0x07 };
    vham_call_streamctrl_t s;
    assert(vham_parse_call_streamctrl(body, sizeof body, &s) == 0);
    assert(strcmp(s.stream_id, "s1") == 0);
    assert(s.flag_a == 5 && s.flag_b == 7);
}

/* CommQuery (IE 0x4f/0x79). */
static void test_commquery(void) {
    uint8_t body[] = {
        0x10,
        0x00,0x00,0x00,0x42,
        0x00,0x00,0x00,0x99,
        'K', 0,
        'V', 0,
    };
    vham_commquery_t q;
    assert(vham_parse_commquery(body, sizeof body, &q) == 0);
    assert(q.type == 0x10);
    assert(q.param1 == 0x42);
    assert(q.param2 == 0x99);
    assert(strcmp(q.key, "K") == 0);
    assert(strcmp(q.val, "V") == 0);
}

/* FsmPair (IE 0x73): count + N (u32,u32). */
static void test_fsmpair(void) {
    uint8_t body[] = {
        0x00,0x00,0x00,0x02,            /* count = 2 */
        0x00,0x00,0x00,0x10, 0x00,0x00,0x00,0x11,
        0x00,0x00,0x00,0x20, 0x00,0x00,0x00,0x21,
    };
    vham_fsmpair_list_t l;
    assert(vham_parse_fsmpair(body, sizeof body, &l) == 0);
    assert(l.count == 2);
    assert(l.pairs[0].a == 0x10 && l.pairs[0].b == 0x11);
    assert(l.pairs[1].a == 0x20 && l.pairs[1].b == 0x21);
}

/* VerInfo (IE 0x06). */
static void test_verinfo(void) {
    uint8_t body[] = { 0x03, 0x07 };
    vham_verinfo_t v;
    assert(vham_parse_verinfo(body, sizeof body, &v) == 0);
    assert(v.major == 3 && v.minor == 7);
}

/* UsrPos (IE 0x05/0x29/0x92). */
static void test_usrpos(void) {
    uint8_t body[] = {
        0x01,
        0x02,0x3a,0x35,0xa1,                /* lat */
        0xf8,0xa4,0x53,0xa0,                /* lon */
        0x00, 0x0a,                          /* altitude */
    };
    vham_usrpos_t p;
    assert(vham_parse_usrpos(body, sizeof body, &p) == 0);
    assert(p.type == 1);
    assert(p.altitude == 10);
}

/* Info (IE 0x15) with text. */
static void test_info(void) {
    uint8_t body[] = {
        0x00, 0x00, 0x00, 0x42,             /* code = 0x42 */
        'h','e','l','l','o', 0x00,
    };
    vham_info_t info;
    assert(vham_parse_info(body, sizeof body, &info) == 0);
    assert(info.code == 0x42);
    assert(info.have_text);
    assert(strcmp(info.text, "hello") == 0);

    /* Length-4 (no text) form. */
    assert(vham_parse_info(body, 4, &info) == 0);
    assert(info.code == 0x42);
    assert(!info.have_text);
}

/* PlayInfo (IE 0x03). */
static void test_playinfo(void) {
    uint8_t body[16] = {
        0,0,0,1, 0,0,0,2, 0,0,0,3, 0,0,0,4,
    };
    vham_playinfo_t p;
    assert(vham_parse_playinfo(body, sizeof body, &p) == 0);
    assert(p.a == 1 && p.b == 2 && p.c == 3 && p.d == 4);
}

/* ResReport (IE 0x72). */
static void test_resreport(void) {
    uint8_t body[8] = { 0,0,0,0xaa, 0,0,0,0xbb };
    vham_resreport_t r;
    assert(vham_parse_resreport(body, sizeof body, &r) == 0);
    assert(r.a == 0xaa && r.b == 0xbb);
}

/* GMemberExtInfo (IE 0x71). */
static void test_gmember_extinfo(void) {
    uint8_t body[] = {
        0x00, 0x02,                          /* count = 2 */
        'A','1', 0,                          /* num */
        'p','r','i','m','a','r','y', 0,      /* info */
        'B','2', 0,
        's','e','c','o','n','d', 0,
    };
    vham_gmember_extinfo_t e;
    assert(vham_parse_gmember_extinfo(body, sizeof body, &e) == 0);
    assert(e.count == 2);
    assert(strcmp(e.entries[0].num,  "A1") == 0);
    assert(strcmp(e.entries[0].info, "primary") == 0);
    assert(strcmp(e.entries[1].num,  "B2") == 0);
    assert(strcmp(e.entries[1].info, "second") == 0);
}

/* WatchLeg (IE 0x33). */
static void test_watchleg(void) {
    uint8_t body[] = { 0x00,0x00,0x12,0x34, 0x07 };
    vham_watchleg_t w;
    assert(vham_parse_watchleg(body, sizeof body, &w) == 0);
    assert(w.leg_id == 0x1234);
    assert(w.flag   == 0x07);
}

/* LegExt (IE 0x75) — 22-byte minimum body. */
static void test_legext(void) {
    uint8_t body[22] = {
        0xaa, 0xbb,
        0,0,0,0,0,0,0,0x55,
        0,0,0,0,0,0,0,0x77,
        0x00, 0x00, 0x12, 0x34,
    };
    vham_legext_t e;
    assert(vham_parse_legext(body, sizeof body, &e) == 0);
    assert(e.a == 0xaa && e.b == 0xbb);
    assert(e.value == 0x1234);
}

/* GpsRec (IE 0x4e) — subject + 2 entries. */
static void test_gpsrec(void) {
    uint8_t body[2 + 1 + 1 + 2 * (4*4 + 2 + 5)];
    size_t i = 0;
    body[i++] = 'A';  body[i++] = 0;     /* subject = "A" */
    body[i++] = 0x02;                    /* type */
    body[i++] = 0x02;                    /* count = 2 */
    for (int k = 0; k < 2; ++k) {
        uint32_t base = 1000 + k;
        body[i++] = (uint8_t)(base >> 24); body[i++] = (uint8_t)(base >> 16);
        body[i++] = (uint8_t)(base >> 8);  body[i++] = (uint8_t)base;
        body[i++] = 0; body[i++] = 0; body[i++] = 0; body[i++] = 0;  /* lon */
        body[i++] = 0; body[i++] = 0; body[i++] = 0; body[i++] = 0;  /* speed */
        body[i++] = 0; body[i++] = 0; body[i++] = 0; body[i++] = 0;  /* hdg */
        body[i++] = 0x00; body[i++] = 0x0a;  /* alt */
        body[i++] = 1; body[i++] = 2; body[i++] = 3; body[i++] = 4; body[i++] = 5;
    }
    vham_gpsrec_t r;
    assert(vham_parse_gpsrec(body, i, &r) == 0);
    assert(strcmp(r.subject, "A") == 0);
    assert(r.type == 2);
    assert(r.count == 2);
    assert(r.entries[0].lat_e6 == 1000);
    assert(r.entries[1].lat_e6 == 1001);
    assert(r.entries[0].altitude == 0x000a);
    assert(r.entries[0].flags[4] == 5);
}

/* CamInfo (IE 0x2e) — full descriptor. */
static void test_caminfo(void) {
    uint8_t body[400]; size_t i = 0;
    body[i++] = 0x07;                       /* type */
    memcpy(body + i, "cam-1",   6); i += 6;
    memcpy(body + i, "front",   6); i += 6;
    body[i++] = 0x1f; body[i++] = 0x90;     /* port = 8080 */
    memcpy(body + i, "rtsp://a/1", 11); i += 11;
    memcpy(body + i, "rtsp://b/1", 11); i += 11;
    body[i++] = 0x01;                       /* status_a */
    body[i++] = 0x02;                       /* status_b */
    memcpy(body + i, "extra",   6); i += 6;

    vham_caminfo_t c;
    assert(vham_parse_caminfo(body, i, &c) == 0);
    assert(c.type == 0x07);
    assert(strcmp(c.name, "cam-1") == 0);
    assert(strcmp(c.desc, "front") == 0);
    assert(c.port == 8080);
    assert(strcmp(c.url_a, "rtsp://a/1") == 0);
    assert(strcmp(c.url_b, "rtsp://b/1") == 0);
    assert(c.status_a == 1 && c.status_b == 2);
    assert(strcmp(c.extra, "extra") == 0);
}

/* MM_PASSTHROUGH end-to-end: build, parse, verify all IEs round-trip. */
static void test_passthrough_roundtrip(void) {
    uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02 };
    vham_passthrough_event_t ev = {
        .code = 0x10,
        .type = 0xc0ffee,
        .ut_sn = 0x12345678,
        .sn   = "20260520-001",
        .time = "2026-05-20T14:30:00Z",
        .data = payload,
        .data_len = sizeof payload,
    };
    uint8_t buf[512];
    int n = vham_build_passthrough(0x55aa, TEST_USER_A,
                                   TEST_USER_B, &ev,
                                   "hello", buf, sizeof buf);
    assert(n > 0);

    vham_passthrough_t pt;
    int rc = vham_parse_passthrough(buf, (size_t)n, &pt);
    assert(rc == 0);
    assert(pt.have_dst);
    assert(strcmp(pt.dst_num, TEST_USER_B) == 0);
    assert(pt.have_src);
    assert(strcmp(pt.src_num, TEST_USER_A) == 0);
    assert(pt.have_event);
    assert(pt.code == 0x10);
    assert(pt.type == 0xc0ffee);
    assert(pt.ut_sn == 0x12345678);
    assert(strcmp(pt.sn,   "20260520-001") == 0);
    assert(strcmp(pt.time, "2026-05-20T14:30:00Z") == 0);
    assert(pt.data_len == sizeof payload);
    assert(memcmp(pt.data, payload, sizeof payload) == 0);
    assert(pt.have_display);
    assert(strcmp(pt.display, "hello") == 0);
}

/* YaoYun extractor finds the integer value inside the JSON blob. */
static void test_yaoyun_extract(void) {
    /* Build a PASSTHROUGH carrying YaoYun=7 in its data payload. */
    const char *yy_json = "{\"YaoYun\":\"7\"}";
    vham_passthrough_event_t ev = {
        .code = 0xff, .type = 0, .ut_sn = 0,
        .sn = "y", .time = "",
        .data = (const uint8_t *)yy_json,
        .data_len = (uint16_t)strlen(yy_json),
    };
    uint8_t buf[512];
    int n = vham_build_passthrough(1, "srv", "me", &ev, NULL,
                                   buf, sizeof buf);
    assert(n > 0);
    vham_passthrough_t pt;
    assert(vham_parse_passthrough(buf, (size_t)n, &pt) == 0);
    assert(vham_passthrough_yaoyun_value(&pt) == 7);

    /* When absent, returns -1. */
    const char *plain = "{\"Code\":1}";
    ev.data = (const uint8_t *)plain;
    ev.data_len = (uint16_t)strlen(plain);
    n = vham_build_passthrough(2, "srv", "me", &ev, NULL, buf, sizeof buf);
    assert(vham_parse_passthrough(buf, (size_t)n, &pt) == 0);
    assert(vham_passthrough_yaoyun_value(&pt) == -1);
}

/* YaoYun ack frame builds and re-parses cleanly. */
static void test_yaoyun_ack(void) {
    uint8_t buf[512];
    int n = vham_build_yaoyun_ack(99, TEST_USER_A, "server",
                                  "FeatureProbe", 42, buf, sizeof buf);
    assert(n > 0);
    vham_passthrough_t pt;
    assert(vham_parse_passthrough(buf, (size_t)n, &pt) == 0);
    assert(pt.have_dst && strcmp(pt.dst_num, "server") == 0);
    assert(vham_passthrough_yaoyun_value(&pt) == 42);
}

/* PASSTHROUGH with no src and no display (the minimal frame). */
static void test_passthrough_minimal(void) {
    vham_passthrough_event_t ev = {
        .code = 1, .type = 0, .ut_sn = 0,
        .sn = "", .time = "",
        .data = NULL, .data_len = 0,
    };
    uint8_t buf[256];
    int n = vham_build_passthrough(1, NULL, TEST_USER_B, &ev,
                                   NULL, buf, sizeof buf);
    assert(n > 0);

    vham_passthrough_t pt;
    assert(vham_parse_passthrough(buf, (size_t)n, &pt) == 0);
    assert(pt.have_dst && !pt.have_src && !pt.have_display);
    assert(pt.have_event && pt.code == 1);
    assert(pt.data_len == 0);
}

/* CC_REL with cause code round-trip — verifies cause IE 0x40
 * gets encoded as a decimal string and re-parses to the same int. */
static void test_cc_release_with_cause(void) {
    vham_cc_call_t call;
    vham_cc_call_init(&call, TEST_USER_A, "146520", 5);
    call.have_remote_leg = 1;
    call.remote_leg_id   = 99;
    call.state           = VHAM_CALL_ACTIVE;

    uint8_t buf[256];
    int n = vham_cc_call_release(&call, 0x10, buf, sizeof buf);  /* normal */
    assert(n > 0);
    assert(call.state == VHAM_CALL_RELEASING);

    /* Round-trip via the recv state machine */
    vham_cc_call_t peer;
    vham_cc_call_init(&peer, "146520", TEST_USER_A, 99);
    peer.state = VHAM_CALL_ACTIVE;
    vham_call_state_t st = vham_cc_call_recv(&peer, buf, (size_t)n);
    assert(st == VHAM_CALL_RELEASING);
    assert(peer.last_cause == 0x10);
}

/* CC_CONN outbound (callee answer with SDP) — verify it carries the
 * answer SDP correctly so the caller can extract it. */
static void test_cc_answer_outbound(void) {
    /* Build callee's answer SDP. */
    vham_sdp_t s = {
        .origin_ipv4 = (192u<<24)|(168u<<16)|(1u<<8)|50u,
        .media_count = 1,
        .media = {{
            .media_type = VHAM_SDP_MEDIA_AUDIO,
            .transport  = VHAM_SDP_TX_RTP_UDP,
            .ipv4 = (192u<<24)|(168u<<16)|(1u<<8)|50u,
            .port = 30050,
            .codec_count = 1,
            .codecs = {{ .payload_type = 0, .encoding_param = 1,
                         .clock_rate = 8000, .name = "PCMU" }},
        }},
    };
    uint8_t sdp[1024];
    int sdp_n = vham_build_sdp_body(&s, sdp, sizeof sdp);
    assert(sdp_n > 0);

    /* Callee: receives a CC_SETUP (we simulate by skipping straight
     * to "answer"), emits CC_CONN. */
    vham_cc_call_t callee;
    vham_cc_call_init(&callee, TEST_USER_B, TEST_USER_A, 42);
    callee.have_remote_leg = 1;
    callee.remote_leg_id   = 7;

    uint8_t buf[2048];
    int n = vham_cc_call_answer(&callee, sdp, (size_t)sdp_n, buf, sizeof buf);
    assert(n > 0);
    assert(callee.state == VHAM_CALL_CONNECTED);

    /* Caller's state machine should now extract the answer SDP. */
    vham_cc_call_t caller;
    vham_cc_call_init(&caller, TEST_USER_A, TEST_USER_B, 7);
    caller.state = VHAM_CALL_SETUP_SENT;
    vham_call_state_t st = vham_cc_call_recv(&caller, buf, (size_t)n);
    assert(st == VHAM_CALL_CONNECTED);
    assert(caller.have_remote_sdp);
    assert(caller.remote_sdp.media[0].port == 30050);
    assert(caller.remote_sdp.media[0].codecs[0].payload_type == 0);
}

/* When a CC_INFO carrying CallUserCtrl arrives, the state machine
 * surfaces mic_holder + mic_action. */
static void test_cc_mic_grant_decode(void) {
    vham_cc_call_t caller;
    vham_cc_call_init(&caller, TEST_USER_A, "146520", 7);
    caller.have_remote_leg = 1;
    caller.remote_leg_id   = 88;

    /* Build a CC_INFO from the peer that grants the mic to "146520". */
    vham_cc_call_t peer;
    vham_cc_call_init(&peer, "146520", TEST_USER_A, 88);
    peer.have_remote_leg = 1;
    peer.remote_leg_id   = 7;
    uint8_t buf[256];
    int n = vham_cc_call_mic_grant(&peer, VHAM_USERCTRL_REQUEST,
                                   buf, sizeof buf);
    assert(n > 0);

    caller.state = VHAM_CALL_ACTIVE;
    vham_call_state_t st = vham_cc_call_recv(&caller, buf, (size_t)n);
    (void)st;
    assert(caller.mic_action == VHAM_USERCTRL_REQUEST);
    assert(strcmp(caller.mic_holder, "146520") == 0);
}

/* CC_INFO mic-grant round-trip: build, parse the frame, walk IEs,
 * pull out the CallUserCtrl payload and verify all fields match. */
static void test_cc_mic_grant_frame(void) {
    vham_cc_call_t call;
    vham_cc_call_init(&call, TEST_USER_A, "146520", 7);
    call.have_remote_leg = 1;
    call.remote_leg_id   = 88;

    uint8_t buf[256];
    int n = vham_cc_call_mic_grant(&call, VHAM_USERCTRL_REQUEST,
                                   buf, sizeof buf);
    assert(n > 0);

    vham_tap_hdr_t    th;
    vham_srvmsg_hdr_t sh;
    vham_reader_t     rd;
    assert(vham_parse_packet(buf, (size_t)n, &th, &sh, &rd) == 0);
    assert(th.class_id == VHAM_TAP_CLASS_CC);
    assert(th.cmd      == VHAM_CC_INFO);
    assert(sh.dwSrcFsmId == 7);
    assert(sh.dwDstFsmId == 88);

    vham_ie_t ie;
    int found = 0;
    while (vham_next_ie(&rd, &ie) == 1) {
        if (ie.tag == VHAM_IE_CC_CALLUSERCTRL) {
            vham_call_userctrl_t uc;
            assert(vham_decode_call_userctrl(ie.value, ie.len, &uc) == 0);
            assert(strcmp(uc.num_a, TEST_USER_A) == 0);
            assert(strcmp(uc.num_b, "146520") == 0);
            assert(uc.action == VHAM_USERCTRL_REQUEST);
            found = 1;
        }
    }
    assert(found);
}

/* CallUserCtrl encode → decode round-trip. */
static void test_call_userctrl_roundtrip(void) {
    vham_call_userctrl_t in = {
        .action = VHAM_USERCTRL_REQUEST,
        .extra  = { 0x12, 0x34, 0x56, 0x78 },
    };
    strncpy(in.num_a, TEST_USER_A, sizeof in.num_a - 1);
    strncpy(in.num_b, "146520",       sizeof in.num_b - 1);
    uint8_t body[80];
    int n = vham_encode_call_userctrl(&in, body, sizeof body);
    assert(n > 0);
    assert(n == (int)(strlen(TEST_USER_A) + 1
                    + strlen("146520")       + 1
                    + 1 + 4));

    vham_call_userctrl_t out;
    int rc = vham_decode_call_userctrl(body, (size_t)n, &out);
    assert(rc == 0);
    assert(strcmp(out.num_a, in.num_a) == 0);
    assert(strcmp(out.num_b, in.num_b) == 0);
    assert(out.action == VHAM_USERCTRL_REQUEST);
    assert(memcmp(out.extra, in.extra, 4) == 0);
}

/* FtpServerInfo parser against captured live bytes. */
static void test_ftpinfo_parse(void) {
    const uint8_t body[] = {
        0x2f,0xfd,0x0d,0xee,             /* IP = 47.253.13.238 (BE) */
        0x52,0xe2,                       /* port = 21218 */
        'f','t','p','-','u','s','e','r','-',')','P',0x00,  /* username */
        '!','@','#','$','0','p',';','/',0x00,              /* password */
    };
    vham_ftpinfo_t f;
    int rc = vham_parse_ftpinfo(body, sizeof body, &f);
    assert(rc == 0);
    assert(f.ipv4 == ((47u<<24)|(253u<<16)|(13u<<8)|238u));
    assert(f.port == 21218);
    assert(strcmp(f.username, "ftp-user-)P") == 0);
    assert(strcmp(f.password, "!@#$0p;/") == 0);
}

/* fg_count > 0x80 should be rejected. */
static void test_user_ginfo_fg_count_bound(void) {
    uint8_t body[64] = {
        0x00, 0x01,                            /* count = 1 */
        1, 1, 1, 0,                            /* prio/type/ut/attr */
        'X', 0,                                /* num */
        0,                                     /* name empty */
        0,                                     /* ag_num empty */
        1, 1, 0x81,                            /* chan, status, fg_count (out of range) */
        0,                                     /* fg_num */
    };
    vham_user_ginfo_t info;
    assert(vham_parse_user_ginfo(body, sizeof body, &info) != 0);
}

/* Truncation should be detected, not crash. */
static void test_orglist_truncated(void) {
    const uint8_t body[] = { 0x00,0x01, '2','0',0x00 /* stops mid-entry */ };
    vham_orglist_t ol;
    assert(vham_parse_orglist(body, sizeof body, &ol) != 0);
}

int main(void) {
    test_md5();
    test_pack_be();
    test_tlv_layout();
    test_regreq_initial();
    test_auth_known();
    test_regreq_roundtrip();
    test_regrsp_challenge_parse();
    test_decoder_robustness();
    test_registration_loopback();
    test_registration_bad_password();
    test_cc_setup_roundtrip();
    test_tap_ack();
    test_sdp_audio_roundtrip();
    test_sdp_audio_video_roundtrip();
    test_sdp_type1_roundtrip();
    test_sdp_robustness();
    test_rtp_basic_roundtrip();
    test_rtp_csrc_and_extension();
    test_rtp_padding();
    test_rtp_robustness();
    test_g711_ulaw();
    test_g711_alaw();
    test_dtmf();
    test_voice_pcm_roundtrip();
    test_voice_loss_detection();
    test_voice_dtmf_roundtrip();
    test_mm_notify_call_incoming();
    test_orglist_parse();
    test_orglist_truncated();
    test_user_ginfo_parse();
    test_user_ginfo_fg_count_bound();
    test_ftpinfo_parse();
    test_watchleg();
    test_legext();
    test_gpsrec();
    test_caminfo();
    test_info();
    test_playinfo();
    test_resreport();
    test_gmember_extinfo();
    test_callext();
    test_call_streamctrl();
    test_commquery();
    test_fsmpair();
    test_verinfo();
    test_usrpos();
    test_passthrough_roundtrip();
    test_passthrough_minimal();
    test_yaoyun_extract();
    test_yaoyun_ack();
    test_cc_conn_answer_sdp();
    test_call_userctrl_roundtrip();
    test_cc_mic_grant_frame();
    test_cc_mic_grant_decode();
    test_cc_release_with_cause();
    test_cc_answer_outbound();
    test_oam_frames();
    test_oam_rsp_parse();
    test_cause_dictionary();
    test_status_notify_parse();
    test_voice_mic_gate();
    test_rtcp_sr_roundtrip();
    test_rtcp_rr_roundtrip();
    test_retx();
    test_segment_reassemble();
    test_rfc4571();
    test_im_roundtrip();
    test_gps_report();
    test_token_store();
    test_mm_quit();
    test_codec_stubs();
    test_h264_fua_roundtrip();
    test_h264_small_single();
    test_srtp_stub();
    test_codec_table();
#ifdef VHAM_WITH_OPUS
    test_codec_opus();
#endif
#ifdef VHAM_WITH_AMR
    test_codec_amrnb();
    test_codec_amrwb();
#endif
#ifdef VHAM_WITH_ILBC
    test_codec_ilbc();
#endif
#ifdef VHAM_WITH_DTLS
    test_dtls_available();
#endif
    test_jitter_reorder();
    test_jitter_late_drop();
    printf("OK\n");
    return 0;
}
