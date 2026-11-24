/*
 * Ethereum validator duties signed inside the device.
 *
 * - The signing root is computed here from the duty's fields. The host never gives a root.
 * - The slashing record (EIP-3076, minimal strategy) is written to flash before the signature
 *   is made. Two records per key alternate, so a write cut by a power loss leaves the previous
 *   record readable, and the signature was not made yet.
 * - Automatic signing has to be enabled on the device, for one network that it shows.
 */

#include <string.h>

#include "cx.h"
#include "os.h"
#include "ox_bls.h"

#include "format.h"
#include "io.h"

#include "../sw.h"
#include "../ui/display.h"
#include "bls_common.h"
#include "validator.h"

#define MAX_KEYS 32

typedef struct {
    uint32_t seq;
    uint8_t has_block;
    uint8_t has_attestation;
    uint8_t pad[2];
    uint64_t block_slot;
    uint64_t source;
    uint64_t target;
    uint32_t check;
    uint32_t pad2;
} mark_t;

typedef struct {
    uint8_t enabled;
    uint8_t genesis_root[32];
    mark_t marks[MAX_KEYS][2];
} nv_t;

const nv_t N_nv_real;
#define N_nv (*(volatile nv_t *) PIC(&N_nv_real))

char g_network_str[2 + 64 + 1];

static uint8_t g_pending_root[32];
static bool g_pending = false;

typedef struct {
    char name[8];
    uint8_t genesis_root[32];
} network_t;

/* genesis_validators_root of the networks shown by name. Any other one is shown in full. */
static const network_t NETWORKS[] = {
    {"Mainnet",
     {0x4b, 0x36, 0x3d, 0xb9, 0x4e, 0x28, 0x61, 0x20, 0xd7, 0x6e, 0xb9, 0x05, 0x34, 0x0f, 0xdd, 0x4e,
      0x54, 0xbf, 0xe9, 0xf0, 0x6b, 0xf3, 0x3f, 0xf6, 0xcf, 0x5a, 0xd2, 0x7f, 0x51, 0x1b, 0xfe, 0x95}},
    {"Hoodi",
     {0x21, 0x2f, 0x13, 0xfc, 0x4d, 0xf0, 0x78, 0xb6, 0xcb, 0x7d, 0xb2, 0x28, 0xf1, 0xc8, 0x30, 0x75,
      0x66, 0xdc, 0xec, 0xf9, 0x00, 0x86, 0x74, 0x01, 0xa9, 0x20, 0x23, 0xd7, 0xba, 0x99, 0xcb, 0x5f}},
    {"Sepolia",
     {0xd8, 0xea, 0x17, 0x1f, 0x3c, 0x94, 0xae, 0xa2, 0x1e, 0xbc, 0x42, 0xa1, 0xed, 0x61, 0x05, 0x2a,
      0xcf, 0x3f, 0x92, 0x09, 0xc0, 0x0e, 0x4e, 0xfb, 0xaa, 0xdd, 0xac, 0x09, 0xed, 0x9b, 0x80, 0x78}},
};

static uint64_t le64(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) {
        v = (v << 8) | p[i];
    }
    return v;
}

static uint32_t check_of(const mark_t *m) {
    const uint8_t *p = (const uint8_t *) m;
    uint32_t h = 0x811c9dc5;
    for (size_t i = 0; i < offsetof(mark_t, check); i++) {
        h = (h ^ p[i]) * 0x01000193;
    }
    return h;
}

/* Latest valid record of a key. A key never used has seq 0 and no flags. */
static void load_mark(uint32_t key, mark_t *out) {
    mark_t m;
    memset(out, 0, sizeof(*out));
    for (int i = 0; i < 2; i++) {
        memcpy(&m, (const void *) &N_nv.marks[key][i], sizeof(m));
        if (m.seq > out->seq && m.check == check_of(&m)) {
            *out = m;
        }
    }
}

static void store_mark(uint32_t key, mark_t *m) {
    m->seq += 1;
    m->check = check_of(m);
    nvm_write((void *) &N_nv.marks[key][m->seq % 2], m, sizeof(*m));
}

static void hash2(const uint8_t a[32], const uint8_t b[32], uint8_t out[32]) {
    uint8_t buf[64];
    memcpy(buf, a, 32);
    memcpy(buf + 32, b, 32);
    cx_hash_sha256(buf, sizeof(buf), out, 32);
}

/* hash_tree_root of a container of 5 fields, given its 5 leaves. */
static void root_of_5(uint8_t leaf[8][32], uint8_t out[32]) {
    uint8_t l[4][32];
    memset(leaf[5], 0, 96);
    for (int i = 0; i < 4; i++) {
        hash2(leaf[2 * i], leaf[2 * i + 1], l[i]);
    }
    hash2(l[0], l[1], l[0]);
    hash2(l[2], l[3], l[1]);
    hash2(l[0], l[1], out);
}

static void leaf_u64(uint8_t leaf[32], const uint8_t le[8]) {
    memset(leaf, 0, 32);
    memcpy(leaf, le, 8);
}

static void signing_root(const uint8_t object[32],
                         uint8_t domain_type,
                         const uint8_t version[4],
                         const uint8_t genesis_root[32],
                         uint8_t out[32]) {
    uint8_t v[32] = {0}, fork[32], domain[32] = {0};
    memcpy(v, version, 4);
    hash2(v, genesis_root, fork);
    domain[0] = domain_type;
    memcpy(domain + 4, fork, 28);
    hash2(object, domain, out);
}

static int sign_root(uint32_t key, const uint8_t *share, const uint8_t root[32]) {
    static const uint8_t dst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
    uint32_t path[] = {PURPOSE, COIN_TYPE, key, 0, 0};
    cx_ecfp_384_private_key_t sk;
    uint8_t hash[192], sig[96], raw[48];
    cx_err_t ret = cx_hash_to_field(root, 32, dst, sizeof(dst) - 1, hash, sizeof(hash));
    if (ret == CX_OK) {
        if (share != NULL) {
            memset(raw, 0, 16);
            memcpy(raw + 16, share, 32);
            ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_BLS12_381_G1,
                                                    raw,
                                                    sizeof(raw),
                                                    (cx_ecfp_private_key_t *) &sk);
            explicit_bzero(raw, sizeof(raw));
        } else {
            ret = get_bls_sk(path, 5, &sk);
        }
    }
    if (ret == CX_OK) {
        ret = ox_bls12381_sign(&sk, hash, sizeof(hash), sig, sizeof(sig));
    }
    explicit_bzero(&sk, sizeof(sk));
    if (ret != CX_OK) {
        return io_send_sw(SW_BAD_STATE);
    }
    return io_send_response_pointer(sig, sizeof(sig), SW_OK);
}

/* Reads key | version | genesis root, and refuses a key or a network not enabled. */
static int check_duty(const uint8_t *d, uint32_t *key) {
    *key = U4BE(d, 0);
    if (*key >= MAX_KEYS) {
        return SW_BAD_KEY;
    }
    if (N_nv.enabled != 1 || memcmp((const void *) N_nv.genesis_root, d + 8, 32) != 0) {
        return SW_NOT_ENABLED;
    }
    return 0;
}

int handler_sign_attestation(const uint8_t *d, const uint8_t *share) {
    uint32_t key;
    uint8_t leaf[8][32], object[32], root[32], e[2][32];
    mark_t m;
    int sw = check_duty(d, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    const uint8_t *a = d + DUTY_HEADER; /* slot 8 | index 8 | block 32 | source 8+32 | target 8+32 */
    uint64_t source = le64(a + 48), target = le64(a + 88);

    load_mark(key, &m);
    if (source > target) {
        return io_send_sw(SW_SLASHABLE);
    }
    if (m.has_attestation && (source < m.source || target <= m.target)) {
        return io_send_sw(SW_SLASHABLE);
    }
    m.has_attestation = 1;
    m.source = source;
    m.target = target;
    store_mark(key, &m);

    leaf_u64(leaf[0], a);
    leaf_u64(leaf[1], a + 8);
    memcpy(leaf[2], a + 16, 32);
    leaf_u64(e[0], a + 48);
    memcpy(e[1], a + 56, 32);
    hash2(e[0], e[1], leaf[3]);
    leaf_u64(e[0], a + 88);
    memcpy(e[1], a + 96, 32);
    hash2(e[0], e[1], leaf[4]);
    root_of_5(leaf, object);
    signing_root(object, 0x01, d + 4, d + 8, root);
    return sign_root(key, share, root);
}

int handler_sign_block(const uint8_t *d) {
    uint32_t key;
    uint8_t leaf[8][32], object[32], root[32];
    mark_t m;
    int sw = check_duty(d, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    const uint8_t *h = d + DUTY_HEADER; /* slot 8 | proposer 8 | parent 32 | state 32 | body 32 */
    uint64_t slot = le64(h);

    load_mark(key, &m);
    if (m.has_block && slot <= m.block_slot) {
        return io_send_sw(SW_SLASHABLE);
    }
    m.has_block = 1;
    m.block_slot = slot;
    store_mark(key, &m);

    leaf_u64(leaf[0], h);
    leaf_u64(leaf[1], h + 8);
    memcpy(leaf[2], h + 16, 96);
    root_of_5(leaf, object);
    signing_root(object, 0x00, d + 4, d + 8, root);
    return sign_root(key, NULL, root);
}

int handler_get_mark(uint32_t key) {
    mark_t m;
    if (key >= MAX_KEYS) {
        return io_send_sw(SW_BAD_KEY);
    }
    load_mark(key, &m);
    return io_send_response_pointer((const uint8_t *) &m, offsetof(mark_t, check), SW_OK);
}

int handler_enable(const uint8_t genesis_root[32]) {
    /* The SDK already refuses a command while another one waits for the user. Kept here too,
     * so that what is stored is always what was shown. */
    if (g_pending) {
        return io_send_sw(SW_BUSY);
    }
    memcpy(g_pending_root, genesis_root, 32);
    memcpy(g_network_str, "0x", 2);
    format_hex(g_pending_root, 32, g_network_str + 2, sizeof(g_network_str) - 2);
    for (size_t i = 0; i < ARRAYLEN(NETWORKS); i++) {
        if (memcmp(NETWORKS[i].genesis_root, g_pending_root, 32) == 0) {
            strlcpy(g_network_str, NETWORKS[i].name, sizeof(g_network_str));
        }
    }
    g_pending = true;
    ui_display_enable();
    return 0;
}

void enable_choice(bool approved) {
    if (!g_pending) {
        return;
    }
    g_pending = false;
    if (!approved) {
        io_send_sw(SW_DENY);
        return;
    }
    uint8_t flag = 0;
    nvm_write((void *) &N_nv.enabled, &flag, 1);
    nvm_write((void *) N_nv.genesis_root, g_pending_root, 32);
    flag = 1;
    nvm_write((void *) &N_nv.enabled, &flag, 1);
    io_send_sw(SW_OK);
}

#ifdef TEST_BUILD
/* Test builds only: raise a record, and forget everything between two test cases. */
int handler_import_mark(const uint8_t *d) {
    uint32_t key = U4BE(d, 0);
    mark_t m;
    if (key >= MAX_KEYS) {
        return io_send_sw(SW_BAD_KEY);
    }
    if (N_nv.enabled != 1 || memcmp((const void *) N_nv.genesis_root, d + 30, 32) != 0) {
        return io_send_sw(SW_NOT_ENABLED);
    }
    load_mark(key, &m);
    uint64_t slot = le64(d + 6), source = le64(d + 14), target = le64(d + 22);
    if (d[4]) {
        m.block_slot = (m.has_block && m.block_slot > slot) ? m.block_slot : slot;
        m.has_block = 1;
    }
    if (d[5]) {
        m.source = (m.has_attestation && m.source > source) ? m.source : source;
        m.target = (m.has_attestation && m.target > target) ? m.target : target;
        m.has_attestation = 1;
    }
    store_mark(key, &m);
    return io_send_sw(SW_OK);
}

int handler_reset(void) {
    mark_t zero[2];
    memset(zero, 0, sizeof(zero));
    for (int i = 0; i < MAX_KEYS; i++) {
        nvm_write((void *) &N_nv.marks[i], zero, sizeof(zero));
    }
    return io_send_sw(SW_OK);
}
#endif
