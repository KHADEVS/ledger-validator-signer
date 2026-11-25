/*
 * Ethereum validator duties signed inside the device.
 *
 * - The signing root is computed here from the duty's fields. The host never gives a root.
 * - The slashing record (EIP-3076, minimal strategy) is written to flash before the signature
 *   is made. Two records per key alternate, so a write cut by a power loss leaves the previous
 *   record readable, and the signature was not made yet.
 * - Automatic signing has to be enabled on the device, for one network that it shows.
 * - A voluntary exit needs a press each time. A builder registration is signed only for the fee
 *   recipient and gas limit that were approved on the device.
 * - Every other duty gets its own domain here, so none of them can come out as a block or a vote.
 * - A key share can be imported, encrypted to a key made in the device. The device shows what it
 *   imports and from which point it will sign, and asks. A slot then signs every duty like a key.
 */

#include <string.h>

#include "cx.h"
#include "os.h"
#include "ox_bls.h"

#include "format.h"
#include "io.h"

#include "../sw.h"
#include "../types.h"
#include "../ui/display.h"
#include "bls_common.h"
#include "get_pk.h"
#include "validator.h"

#define MAX_KEYS DERIVED_KEYS
/* Key numbers from MAX_KEYS up are the slots of imported key shares. */
#define MAX_SHARES 4
#define SLOTS      (MAX_KEYS + MAX_SHARES)
/* MAX_VALIDATORS_PER_COMMITTEE, and the same times MAX_COMMITTEES_PER_SLOT since Electra. */
#define LIMIT_BITS         2048
#define LIMIT_BITS_ELECTRA 131072

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
    uint8_t present;
    uint8_t index;        /* which share of the key: 1, 2, 3... */
    uint8_t secret[32];   /* big endian */
    uint8_t group_pk[48]; /* the validator's public key */
} share_t;

typedef struct {
    uint8_t enabled;
    uint8_t genesis_root[32];
    uint8_t fee_set;
    uint8_t fee[28]; /* fee recipient 20 | gas limit 8, little endian */
    mark_t marks[SLOTS][2];
    uint8_t import_set;
    uint8_t import_sk[32]; /* the P-256 key that shares are encrypted to */
    share_t shares[MAX_SHARES];
} nv_t;

const nv_t N_nv_real;
#define N_nv (*(volatile nv_t *) PIC(&N_nv_real))

static uint8_t g_pending_root[32];
static uint8_t g_pending_data[DUTY_HEADER + 16];
static bool g_pending = false;

/* An aggregate or a sync committee contribution, received in several commands. */
typedef struct {
    uint8_t active;
    uint8_t kind;
    uint8_t fill;
    uint8_t header[DUTY_HEADER];
    uint8_t index_leaf[32]; /* aggregator_index */
    uint8_t inner[4][32];   /* leaves of the aggregate or of the contribution */
    uint32_t bits_len;      /* serialized length of aggregation_bits, in bytes */
    uint32_t received;
    uint32_t chunks;
    uint64_t bit_length;
    uint8_t chunk[32];
    uint8_t stack[11][32];
    uint8_t sub;         /* Gloas: the subtree being filled */
    uint8_t subs[6][32]; /* Gloas: roots of the subtrees of 1, 4, 16, 64, 256 and 1024 chunks */
} stream_t;

static stream_t g_stream;

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

static void signing_root4(const uint8_t object[32],
                          const uint8_t domain_type[4],
                          const uint8_t version[4],
                          const uint8_t genesis_root[32],
                          uint8_t out[32]) {
    uint8_t v[32] = {0}, fork[32], domain[32] = {0};
    memcpy(v, version, 4);
    hash2(v, genesis_root, fork);
    memcpy(domain, domain_type, 4);
    memcpy(domain + 4, fork, 28);
    hash2(object, domain, out);
}

/* Domains of the consensus layer: one byte, then three zero bytes. */
static void signing_root(const uint8_t object[32],
                         uint8_t domain_type,
                         const uint8_t version[4],
                         const uint8_t genesis_root[32],
                         uint8_t out[32]) {
    const uint8_t type[4] = {domain_type, 0, 0, 0};
    signing_root4(object, type, version, genesis_root, out);
}

/* hash_tree_root of a BLS signature: 96 bytes, three chunks. */
static void bytes96_root(const uint8_t *sig, uint8_t out[32]) {
    uint8_t a[32], b[32], zero[32] = {0};
    hash2(sig, sig + 32, a);
    hash2(sig + 64, zero, b);
    hash2(a, b, out);
}

/* slot 8 | index 8 | block 32 | source 8+32 | target 8+32 */
static void attestation_data_root(const uint8_t *a, uint8_t out[32]) {
    uint8_t leaf[8][32], e[2][32];
    leaf_u64(leaf[0], a);
    leaf_u64(leaf[1], a + 8);
    memcpy(leaf[2], a + 16, 32);
    leaf_u64(e[0], a + 48);
    memcpy(e[1], a + 56, 32);
    hash2(e[0], e[1], leaf[3]);
    leaf_u64(e[0], a + 88);
    memcpy(e[1], a + 96, 32);
    hash2(e[0], e[1], leaf[4]);
    root_of_5(leaf, out);
}

static int sign_root(uint32_t key, const uint8_t *share, const uint8_t root[32]) {
    static const uint8_t dst[] = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
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
        } else if (key >= MAX_KEYS) {
            memset(raw, 0, 16);
            memcpy(raw + 16, (const void *) N_nv.shares[key - MAX_KEYS].secret, 32);
            ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_BLS12_381_G1,
                                                    raw,
                                                    sizeof(raw),
                                                    (cx_ecfp_private_key_t *) &sk);
            explicit_bzero(raw, sizeof(raw));
        } else {
            ret = get_signing_sk(key, &sk);
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
    if (*key >= SLOTS || (*key >= MAX_KEYS && N_nv.shares[*key - MAX_KEYS].present != 1)) {
        return SW_BAD_KEY;
    }
    if (N_nv.enabled != 1 || memcmp((const void *) N_nv.genesis_root, d + 8, 32) != 0) {
        return SW_NOT_ENABLED;
    }
    return 0;
}

int handler_sign_attestation(const uint8_t *d, const uint8_t *share) {
    uint32_t key;
    uint8_t object[32], root[32];
    mark_t m;
    int sw = check_duty(d, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    const uint8_t *a = d + DUTY_HEADER;
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

    attestation_data_root(a, object);
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
    if (key >= SLOTS) {
        return io_send_sw(SW_BAD_KEY);
    }
    load_mark(key, &m);
    return io_send_response_pointer((const uint8_t *) &m, offsetof(mark_t, check), SW_OK);
}

static void screen_action(const char *first, const char *second) {
    strlcpy(g_confirm_action[0], first, sizeof(g_confirm_action[0]));
    strlcpy(g_confirm_action[1], second, sizeof(g_confirm_action[1]));
}

static void enable_choice(bool approved);

int handler_enable(const uint8_t genesis_root[32]) {
    /* The SDK already refuses a command while another one waits for the user. Kept here too,
     * so that what is stored is always what was shown. */
    if (g_pending) {
        return io_send_sw(SW_BUSY);
    }
    memcpy(g_pending_root, genesis_root, 32);
    screen_action("Enable", "auto signing");
    strlcpy(g_confirm_title[0], "Network", sizeof(g_confirm_title[0]));
    memcpy(g_confirm_text[0], "0x", 2);
    format_hex(g_pending_root, 32, g_confirm_text[0] + 2, sizeof(g_confirm_text[0]) - 2);
    for (size_t i = 0; i < ARRAYLEN(NETWORKS); i++) {
        if (memcmp(NETWORKS[i].genesis_root, g_pending_root, 32) == 0) {
            strlcpy(g_confirm_text[0], NETWORKS[i].name, sizeof(g_confirm_text[0]));
        }
    }
    g_pending = true;
    ui_confirm(1, enable_choice);
    return 0;
}

static void enable_choice(bool approved) {
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

/* Duties that cannot be slashed: the object is small, and the device picks the domain. */
int handler_sign_small(uint8_t ins, const uint8_t *d) {
    uint32_t key;
    uint8_t object[32], root[32], a[32], b[32], domain;
    int sw = check_duty(d, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    const uint8_t *p = d + DUTY_HEADER;
    switch (ins) {
        case SIGN_AGGREGATION_SLOT: /* slot 8 */
            leaf_u64(object, p);
            domain = 0x05;
            break;
        case SIGN_RANDAO: /* epoch 8 */
            leaf_u64(object, p);
            domain = 0x02;
            break;
        case SIGN_SYNC_MESSAGE: /* beacon_block_root 32 */
            memcpy(object, p, 32);
            domain = 0x07;
            break;
        default: /* SIGN_SYNC_SELECTION: slot 8 | subcommittee_index 8 */
            leaf_u64(a, p);
            leaf_u64(b, p + 8);
            hash2(a, b, object);
            domain = 0x08;
            break;
    }
    signing_root(object, domain, d + 4, d + 8, root);
    return sign_root(key, NULL, root);
}

/* Adds one chunk to the Merkle tree being built. Only one hash per level is kept. */
static void merkle_push(const uint8_t chunk[32]) {
    uint8_t h[32], level = 0;
    uint32_t i = g_stream.chunks;
    memcpy(h, chunk, 32);
    while (i & 1) {
        hash2(g_stream.stack[level], h, h);
        i >>= 1;
        level++;
    }
    memcpy(g_stream.stack[level], h, 32);
    g_stream.chunks++;
}

/* Root of the tree of 2^depth chunks, the missing ones being zero. */
static void merkle_finish(uint8_t depth, uint8_t out[32]) {
    uint8_t zero[32] = {0}, acc[32];
    bool have = false;
    uint32_t size = g_stream.chunks;
    for (uint8_t level = 0; level < depth; level++) {
        if (size & 1) {
            hash2(g_stream.stack[level], have ? acc : zero, acc);
            have = true;
        } else if (have) {
            hash2(acc, zero, acc);
        }
        hash2(zero, zero, zero);
        size >>= 1;
    }
    if (!have) {
        memcpy(acc, (size & 1) ? g_stream.stack[depth] : zero, 32);
    }
    memcpy(out, acc, 32);
}

/*
 * One more chunk of the bit list. Since Gloas (EIP-7688) the list is hashed as a chain of
 * subtrees of 1, 4, 16... chunks, so that its root does not depend on a maximum size.
 */
static void stream_chunk(const uint8_t chunk[32]) {
    merkle_push(chunk);
    if (g_stream.kind == STREAM_AGGREGATE_GLOAS && g_stream.chunks == (1u << (2 * g_stream.sub))) {
        merkle_finish(2 * g_stream.sub, g_stream.subs[g_stream.sub]);
        g_stream.sub++;
        g_stream.chunks = 0;
    }
}

static int stream_fail(int sw) {
    g_stream.active = 0;
    return io_send_sw(sw);
}

/*
 * First part of an AggregateAndProof or of a sync committee ContributionAndProof.
 * header | kind 1 | aggregator_index 8, then
 *   aggregate:    AttestationData 128 | length of aggregation_bits in bytes 4 | committee_bits 8
 *   contribution: slot 8 | beacon_block_root 32 | subcommittee_index 8 | aggregation_bits 16
 */
int handler_stream_begin(const uint8_t *d, size_t len) {
    uint32_t key;
    memset(&g_stream, 0, sizeof(g_stream));
    if (len < DUTY_HEADER + 1) {
        return io_send_sw(SW_WRONG_DATA_LENGTH);
    }
    int sw = check_duty(d, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    uint8_t kind = d[DUTY_HEADER];
    const uint8_t *p = d + DUTY_HEADER + 1;
    if (kind == STREAM_CONTRIBUTION) {
        if (len != DUTY_HEADER + 1 + 72) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }
        leaf_u64(g_stream.inner[0], p + 8);
        memcpy(g_stream.inner[1], p + 16, 32);
        leaf_u64(g_stream.inner[2], p + 48);
        memcpy(g_stream.inner[3], p + 56, 16);
    } else if (kind == STREAM_AGGREGATE || kind == STREAM_AGGREGATE_ELECTRA ||
               kind == STREAM_AGGREGATE_GLOAS) {
        if (len != DUTY_HEADER + 1 + 148) {
            return io_send_sw(SW_WRONG_DATA_LENGTH);
        }
        attestation_data_root(p + 8, g_stream.inner[1]);
        g_stream.bits_len = U4BE(p, 136);
        uint32_t limit = kind == STREAM_AGGREGATE ? LIMIT_BITS : LIMIT_BITS_ELECTRA;
        if (g_stream.bits_len == 0 || g_stream.bits_len > limit / 8 + 1) {
            return io_send_sw(SW_BAD_DUTY);
        }
        if (kind != STREAM_AGGREGATE) {
            memcpy(g_stream.inner[3], p + 140, 8);
        }
    } else {
        return io_send_sw(SW_BAD_DUTY);
    }
    leaf_u64(g_stream.index_leaf, p);
    memcpy(g_stream.header, d, DUTY_HEADER);
    g_stream.kind = kind;
    g_stream.active = 1;
    return io_send_sw(SW_OK);
}

/* The bytes of aggregation_bits, in order. The last one holds the bit that ends the list. */
int handler_stream_bits(const uint8_t *d, size_t len) {
    if (!g_stream.active || g_stream.kind == STREAM_CONTRIBUTION || len == 0 ||
        g_stream.received + len > g_stream.bits_len) {
        return stream_fail(SW_BAD_DUTY);
    }
    uint32_t limit = g_stream.kind == STREAM_AGGREGATE ? LIMIT_BITS : LIMIT_BITS_ELECTRA;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = d[i];
        g_stream.received++;
        if (g_stream.received == g_stream.bits_len) {
            uint8_t top = 7;
            if (byte == 0) {
                return stream_fail(SW_BAD_DUTY);
            }
            while ((byte >> top) == 0) {
                top--;
            }
            g_stream.bit_length = 8 * (uint64_t) (g_stream.bits_len - 1) + top;
            if (g_stream.bit_length > limit) {
                return stream_fail(SW_BAD_DUTY);
            }
            if (top == 0) {
                break; /* the last byte only ends the list */
            }
            byte &= (uint8_t) ~(1u << top);
        }
        g_stream.chunk[g_stream.fill++] = byte;
        if (g_stream.fill == 32) {
            stream_chunk(g_stream.chunk);
            memset(g_stream.chunk, 0, 32);
            g_stream.fill = 0;
        }
    }
    return io_send_sw(SW_OK);
}

/* Last part: the aggregate signature 96 | selection_proof 96. Signs. */
int handler_stream_end(const uint8_t *d) {
    uint32_t key;
    uint8_t object[32], root[32], inner[32], a[32], b[32], zero[32] = {0}, domain;
    if (!g_stream.active) {
        return io_send_sw(SW_BAD_DUTY);
    }
    g_stream.active = 0;
    int sw = check_duty(g_stream.header, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    if (g_stream.kind == STREAM_CONTRIBUTION) {
        uint8_t leaf[8][32];
        memcpy(leaf, g_stream.inner, sizeof(g_stream.inner));
        bytes96_root(d, leaf[4]);
        root_of_5(leaf, inner);
        domain = 0x09;
    } else {
        if (g_stream.received != g_stream.bits_len) {
            return io_send_sw(SW_BAD_DUTY);
        }
        if (g_stream.fill != 0) {
            stream_chunk(g_stream.chunk);
        }
        if (g_stream.kind == STREAM_AGGREGATE_GLOAS) {
            uint8_t count = g_stream.sub;
            if (g_stream.chunks != 0) {
                merkle_finish(2 * g_stream.sub, g_stream.subs[g_stream.sub]);
                count++;
            }
            memset(a, 0, 32);
            while (count > 0) {
                count--;
                hash2(g_stream.subs[count], a, a);
            }
        } else {
            merkle_finish(g_stream.kind == STREAM_AGGREGATE ? 3 : 9, a);
        }
        memset(b, 0, 32);
        for (int i = 0; i < 8; i++) {
            b[i] = (uint8_t) (g_stream.bit_length >> (8 * i));
        }
        hash2(a, b, g_stream.inner[0]); /* the length is mixed in */
        bytes96_root(d, g_stream.inner[2]);
        if (g_stream.kind == STREAM_AGGREGATE_GLOAS) {
            /* A progressive container of four fields: the first alone, then the next three. */
            hash2(g_stream.inner[1], g_stream.inner[2], a);
            hash2(g_stream.inner[3], zero, b);
            hash2(a, b, a);
            hash2(a, zero, a);
            hash2(g_stream.inner[0], a, a);
            memset(b, 0, 32);
            b[0] = 0x0f; /* its four fields are active */
            hash2(a, b, inner);
        } else {
            hash2(g_stream.inner[0], g_stream.inner[1], a);
            hash2(g_stream.inner[2], g_stream.inner[3], b);
            hash2(a, b, inner);
        }
        domain = 0x06;
    }
    hash2(g_stream.index_leaf, inner, a);
    bytes96_root(d + 96, b);
    hash2(b, zero, b);
    hash2(a, b, object);
    signing_root(object, domain, g_stream.header + 4, g_stream.header + 8, root);
    return sign_root(key, NULL, root);
}

static void exit_choice(bool approved) {
    uint8_t object[32], root[32], a[32], b[32];
    const uint8_t *d = g_pending_data;
    if (!g_pending) {
        return;
    }
    g_pending = false;
    if (!approved) {
        io_send_sw(SW_DENY);
        return;
    }
    leaf_u64(a, d + DUTY_HEADER);
    leaf_u64(b, d + DUTY_HEADER + 8);
    hash2(a, b, object);
    signing_root(object, 0x04, d + 4, d + 8, root);
    sign_root(U4BE(d, 0), NULL, root);
}

/* header | epoch 8 | validator_index 8. Asked on the device every time. */
int handler_sign_exit(const uint8_t *d) {
    uint32_t key;
    int sw = check_duty(d, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    if (g_pending) {
        return io_send_sw(SW_BUSY);
    }
    memcpy(g_pending_data, d, sizeof(g_pending_data));
    screen_action("Exit", "validator");
    strlcpy(g_confirm_title[0], "Validator", sizeof(g_confirm_title[0]));
    format_u64(g_confirm_text[0], sizeof(g_confirm_text[0]), le64(d + DUTY_HEADER + 8));
    strlcpy(g_confirm_title[1], "Epoch", sizeof(g_confirm_title[1]));
    format_u64(g_confirm_text[1], sizeof(g_confirm_text[1]), le64(d + DUTY_HEADER));
    g_pending = true;
    ui_confirm(2, exit_choice);
    return 0;
}

static void fee_choice(bool approved) {
    if (!g_pending) {
        return;
    }
    g_pending = false;
    if (!approved) {
        io_send_sw(SW_DENY);
        return;
    }
    uint8_t flag = 0;
    nvm_write((void *) &N_nv.fee_set, &flag, 1);
    nvm_write((void *) N_nv.fee, g_pending_data, 28);
    flag = 1;
    nvm_write((void *) &N_nv.fee_set, &flag, 1);
    io_send_sw(SW_OK);
}

/* fee recipient 20 | gas limit 8. The only registrations signed afterwards are for these. */
int handler_set_fee(const uint8_t *d) {
    if (g_pending) {
        return io_send_sw(SW_BUSY);
    }
    memcpy(g_pending_data, d, 28);
    screen_action("Set fee", "recipient");
    strlcpy(g_confirm_title[0], "Recipient", sizeof(g_confirm_title[0]));
    memcpy(g_confirm_text[0], "0x", 2);
    format_hex(g_pending_data, 20, g_confirm_text[0] + 2, sizeof(g_confirm_text[0]) - 2);
    strlcpy(g_confirm_title[1], "Gas limit", sizeof(g_confirm_title[1]));
    format_u64(g_confirm_text[1], sizeof(g_confirm_text[1]), le64(g_pending_data + 20));
    g_pending = true;
    ui_confirm(2, fee_choice);
    return 0;
}

/* The validator's public key: derived here, or the one a share was imported for. */
static cx_err_t signing_pk(uint32_t key, uint8_t pk[48]) {
    if (key >= MAX_KEYS) {
        memcpy(pk, (const void *) N_nv.shares[key - MAX_KEYS].group_pk, 48);
        return CX_OK;
    }
    return derive_signing_pk(key, pk);
}

/*
 * Builder registration: header | fee recipient 20 | gas limit 8 | timestamp 8.
 * The public key in the message is the device's own. The version in the header is the genesis
 * fork version, and the domain uses a zero genesis_validators_root, as the builder API says.
 */
int handler_sign_registration(const uint8_t *d) {
    static const uint8_t builder[4] = {0, 0, 0, 1};
    uint32_t key;
    uint8_t leaf[4][32], object[32], root[32], pk[48], zero[32] = {0};
    int sw = check_duty(d, &key);
    if (sw != 0) {
        return io_send_sw(sw);
    }
    const uint8_t *r = d + DUTY_HEADER;
    if (N_nv.fee_set != 1 || memcmp((const void *) N_nv.fee, r, 28) != 0) {
        return io_send_sw(SW_SETTING);
    }
    if (signing_pk(key, pk) != CX_OK) {
        return io_send_sw(SW_BAD_STATE);
    }
    memset(leaf, 0, sizeof(leaf));
    memcpy(leaf[0], r, 20);
    memcpy(leaf[1], r + 20, 8);
    memcpy(leaf[2], r + 28, 8);
    memcpy(leaf[3], pk + 32, 16);
    hash2(pk, leaf[3], leaf[3]);
    hash2(leaf[0], leaf[1], leaf[0]);
    hash2(leaf[2], leaf[3], leaf[1]);
    hash2(leaf[0], leaf[1], object);
    signing_root4(object, builder, d + 4, zero, root);
    return sign_root(key, NULL, root);
}

/* The public key of a key, and for a slot the number of the share it holds. */
int handler_get_pk(uint32_t key) {
    uint8_t out[49];
    if (key < MAX_KEYS) {
        return handler_get_signing_pk(key);
    }
    if (key >= SLOTS || N_nv.shares[key - MAX_KEYS].present != 1) {
        return io_send_sw(SW_BAD_KEY);
    }
    memcpy(out, (const void *) N_nv.shares[key - MAX_KEYS].group_pk, 48);
    out[48] = N_nv.shares[key - MAX_KEYS].index;
    return io_send_response_pointer(out, sizeof(out), SW_OK);
}

/* The P-256 key that shares are encrypted to. It is made here at first use and never leaves. */
static cx_err_t import_key(cx_ecfp_256_private_key_t *priv, cx_ecfp_256_public_key_t *pub) {
    uint8_t raw[32];
    cx_err_t ret;
    if (N_nv.import_set != 1) {
        uint8_t flag = 1;
        ret = cx_ecfp_generate_pair_no_throw(CX_CURVE_SECP256R1,
                                             (cx_ecfp_public_key_t *) pub,
                                             (cx_ecfp_private_key_t *) priv,
                                             0);
        if (ret == CX_OK) {
            nvm_write((void *) N_nv.import_sk, priv->d, 32);
            nvm_write((void *) &N_nv.import_set, &flag, 1);
        }
        return ret;
    }
    memcpy(raw, (const void *) N_nv.import_sk, 32);
    ret = cx_ecfp_init_private_key_no_throw(CX_CURVE_SECP256R1,
                                            raw,
                                            sizeof(raw),
                                            (cx_ecfp_private_key_t *) priv);
    explicit_bzero(raw, sizeof(raw));
    if (ret == CX_OK) {
        ret = cx_ecfp_generate_pair_no_throw(CX_CURVE_SECP256R1,
                                             (cx_ecfp_public_key_t *) pub,
                                             (cx_ecfp_private_key_t *) priv,
                                             1);
    }
    return ret;
}

static uint8_t g_import_pub[65];

static void import_key_choice(bool approved) {
    if (!g_pending) {
        return;
    }
    g_pending = false;
    if (!approved) {
        io_send_sw(SW_DENY);
        return;
    }
    io_send_response_pointer(g_import_pub, sizeof(g_import_pub), SW_OK);
}

/*
 * Gives the key to encrypt a share to. The screen shows a check of it, to compare with the one
 * shown where the share is encrypted: a host in between cannot put its own key in its place.
 */
int handler_get_import_key(void) {
    cx_ecfp_256_private_key_t priv;
    cx_ecfp_256_public_key_t pub;
    uint8_t digest[32];
    if (g_pending) {
        return io_send_sw(SW_BUSY);
    }
    cx_err_t ret = import_key(&priv, &pub);
    explicit_bzero(&priv, sizeof(priv));
    if (ret != CX_OK) {
        return io_send_sw(SW_BAD_STATE);
    }
    memcpy(g_import_pub, pub.W, sizeof(g_import_pub));
    cx_hash_sha256(g_import_pub, sizeof(g_import_pub), digest, sizeof(digest));
    screen_action("Show", "import key");
    strlcpy(g_confirm_title[0], "Key check", sizeof(g_confirm_title[0]));
    format_hex(digest, 8, g_confirm_text[0], sizeof(g_confirm_text[0]));
    g_pending = true;
    ui_confirm(1, import_key_choice);
    return 0;
}

static struct {
    uint8_t header[IMPORT_HEADER];
    uint8_t secret[32];
} g_import;

/* The order of the group: a share is a number below it, and not zero. */
static const uint8_t BLS_ORDER[32] = {0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8,
                                      0x08, 0x09, 0xa1, 0xd8, 0x05, 0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe,
                                      0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01};

static void import_choice(bool approved) {
    if (!g_pending) {
        return;
    }
    g_pending = false;
    if (approved) {
        const uint8_t *h = g_import.header;
        uint8_t slot = h[0], flag = 0;
        share_t s;
        mark_t m, zero[2];
        /* The slot is empty while it is rewritten. Its record starts where the import says. */
        nvm_write((void *) &N_nv.shares[slot].present, &flag, 1);
        memset(zero, 0, sizeof(zero));
        nvm_write((void *) &N_nv.marks[MAX_KEYS + slot], zero, sizeof(zero));
        memset(&m, 0, sizeof(m));
        m.has_attestation = h[74] & 1;
        m.has_block = (h[74] >> 1) & 1;
        m.source = le64(h + 50);
        m.target = le64(h + 58);
        m.block_slot = le64(h + 66);
        store_mark(MAX_KEYS + slot, &m);
        memset(&s, 0, sizeof(s));
        s.index = h[1];
        memcpy(s.secret, g_import.secret, sizeof(s.secret));
        memcpy(s.group_pk, h + 2, sizeof(s.group_pk));
        nvm_write((void *) &N_nv.shares[slot], &s, sizeof(s));
        explicit_bzero(&s, sizeof(s));
        flag = 1;
        nvm_write((void *) &N_nv.shares[slot].present, &flag, 1);
    }
    explicit_bzero(&g_import, sizeof(g_import));
    io_send_sw(approved ? SW_OK : SW_DENY);
}

/*
 * A share of a validator key, encrypted to the device: ECDH on P-256 with a key of the sender made
 * for this message, HKDF-SHA256, AES-256-GCM. Everything in clear before the sender's key is
 * authenticated with the share: the slot, the share's number, the validator's public key, and
 * what the validator signed before (the record starts there, as in an EIP-3076 import).
 */
int handler_import_share(const uint8_t *d) {
    static const char label[] = "ledger-validator-signer share import v1";
    cx_ecfp_256_private_key_t priv;
    cx_ecfp_256_public_key_t pub;
    cx_aes_gcm_context_t gcm;
    uint8_t z[32], prk[32], k[32], zero[32] = {0};
    uint8_t info[sizeof(label) - 1 + 65 + 65 + 1];
    const uint8_t *sender = d + IMPORT_HEADER, *nonce = sender + 65, *ct = nonce + 12, *tag = ct + 32;
    uint64_t source = le64(d + 50), target = le64(d + 58), block_slot = le64(d + 66);
    const uint64_t limit = 1000000000000ULL; /* keeps the numbers readable on the screen */
    int diff = 0;

    if (g_pending) {
        return io_send_sw(SW_BUSY);
    }
    if (d[0] >= MAX_SHARES || d[1] == 0 || (d[74] & ~3) != 0 || N_nv.import_set != 1 ||
        source >= limit || target >= limit || block_slot >= limit) {
        return io_send_sw(SW_BAD_IMPORT);
    }
    /* A share already held in another slot would get a second record. */
    for (uint8_t i = 0; i < MAX_SHARES; i++) {
        if (i != d[0] && N_nv.shares[i].present == 1 &&
            N_nv.shares[i].index == d[1] &&
            memcmp((const void *) N_nv.shares[i].group_pk, d + 2, 48) == 0) {
            return io_send_sw(SW_BAD_IMPORT);
        }
    }
    cx_err_t ret = import_key(&priv, &pub);
    if (ret == CX_OK) {
        ret = cx_ecdh_no_throw((cx_ecfp_private_key_t *) &priv, CX_ECDH_X, sender, 65, z, sizeof(z));
    }
    explicit_bzero(&priv, sizeof(priv));
    if (ret == CX_OK) {
        /* HKDF-SHA256 with an empty salt. The two public keys are part of the context. */
        cx_hmac_sha256(zero, sizeof(zero), z, sizeof(z), prk, sizeof(prk));
        memcpy(info, label, sizeof(label) - 1);
        memcpy(info + sizeof(label) - 1, sender, 65);
        memcpy(info + sizeof(label) - 1 + 65, pub.W, 65);
        info[sizeof(info) - 1] = 1;
        cx_hmac_sha256(prk, sizeof(prk), info, sizeof(info), k, sizeof(k));
        cx_aes_gcm_init(&gcm);
        ret = cx_aes_gcm_set_key(&gcm, k, sizeof(k));
    }
    if (ret == CX_OK) {
        ret = cx_aes_gcm_decrypt_and_auth(&gcm,
                                          (uint8_t *) ct,
                                          32,
                                          nonce,
                                          12,
                                          d,
                                          IMPORT_HEADER,
                                          g_import.secret,
                                          tag,
                                          16);
    }
    explicit_bzero(z, sizeof(z));
    explicit_bzero(prk, sizeof(prk));
    explicit_bzero(k, sizeof(k));
    explicit_bzero(&gcm, sizeof(gcm));
    if (ret == CX_OK) {
        ret = cx_math_cmp_no_throw(g_import.secret, BLS_ORDER, 32, &diff);
    }
    if (ret != CX_OK || diff >= 0 || cx_math_is_zero(g_import.secret, 32)) {
        explicit_bzero(&g_import, sizeof(g_import));
        return io_send_sw(SW_BAD_IMPORT);
    }
    memcpy(g_import.header, d, IMPORT_HEADER);

    /* The same key in the same slot keeps the higher of the two records. */
    if (N_nv.shares[d[0]].present == 1 &&
        memcmp((const void *) N_nv.shares[d[0]].group_pk, d + 2, 48) == 0) {
        mark_t old;
        load_mark(MAX_KEYS + d[0], &old);
        if (old.has_attestation) {
            source = old.source > source || !(d[74] & 1) ? old.source : source;
            target = old.target > target || !(d[74] & 1) ? old.target : target;
            g_import.header[74] |= 1;
        }
        if (old.has_block) {
            block_slot = old.block_slot > block_slot || !(d[74] & 2) ? old.block_slot : block_slot;
            g_import.header[74] |= 2;
        }
        for (int i = 0; i < 8; i++) {
            g_import.header[50 + i] = (uint8_t) (source >> (8 * i));
            g_import.header[58 + i] = (uint8_t) (target >> (8 * i));
            g_import.header[66 + i] = (uint8_t) (block_slot >> (8 * i));
        }
    }

    char *t = g_confirm_text[0];
    size_t size = sizeof(g_confirm_text[0]);
    screen_action("Import", "key share");
    strlcpy(g_confirm_title[0], "Slot", sizeof(g_confirm_title[0]));
    format_u64(t, size, d[0]);
    strlcat(t, ", share ", size);
    format_u64(t + strlen(t), size - strlen(t), d[1]);

    t = g_confirm_text[1];
    strlcpy(g_confirm_title[1], "Group key", sizeof(g_confirm_title[1]));
    memcpy(t, "0x", 2);
    format_hex(d + 2, 6, t + 2, size - 2);
    strlcat(t, "..", size);
    format_hex(d + 2 + 42, 6, t + strlen(t), size - strlen(t));

    t = g_confirm_text[2];
    strlcpy(g_confirm_title[2], "Not before", sizeof(g_confirm_title[2]));
    if (g_import.header[74] == 0) {
        strlcpy(t, "nothing signed yet", size);
    } else {
        strlcpy(t, "source ", size);
        format_u64(t + strlen(t), size - strlen(t), source);
        strlcat(t, ", target ", size);
        format_u64(t + strlen(t), size - strlen(t), target);
        strlcat(t, ", slot ", size);
        format_u64(t + strlen(t), size - strlen(t), block_slot);
    }
    g_pending = true;
    ui_confirm(3, import_choice);
    return 0;
}

#ifdef TEST_BUILD
/* Test builds only: raise a record, and forget everything between two test cases. */
int handler_import_mark(const uint8_t *d) {
    uint32_t key = U4BE(d, 0);
    mark_t m;
    if (key >= SLOTS) {
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
    share_t none;
    memset(zero, 0, sizeof(zero));
    memset(&none, 0, sizeof(none));
    for (int i = 0; i < SLOTS; i++) {
        nvm_write((void *) &N_nv.marks[i], zero, sizeof(zero));
    }
    for (int i = 0; i < MAX_SHARES; i++) {
        nvm_write((void *) &N_nv.shares[i], &none, sizeof(none));
    }
    forget_signing_sks();
    return io_send_sw(SW_OK);
}
#endif
