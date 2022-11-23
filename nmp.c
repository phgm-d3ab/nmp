/*
 *
 */
#include "nmp.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/random.h>

#include <liburing.h>
#include <openssl/evp.h>


typedef uint8_t u8;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef uint64_t u64;


#if defined(NMP_DEBUG)

#   include <stdio.h>


static void __log_timestamp(char *output)
{
        struct timespec ts = {0};
        struct tm tm = {0};
        char buf[16] = {0};

        clock_gettime(CLOCK_REALTIME, &ts);
        localtime_r(&ts.tv_sec, &tm);
        strftime(buf, 16, "%H:%M:%S", &tm);
        snprintf(output, 64, "%s.%06ld", buf, (ts.tv_nsec / 1000l));
}

#   define __log(fmt__, ...) \
            do { char timestr__[32] = {0};                                      \
            __log_timestamp(timestr__);                                         \
            dprintf(STDERR_FILENO, "[%s][nmp][%s():%u] " fmt__ "\n", timestr__, \
                __FUNCTION__, __LINE__, ##__VA_ARGS__); } while(0)              \


#   define log(fmt_, ...)   __log(fmt_, ##__VA_ARGS__)
#   define log_errno()      log("%s", strerrordesc_np(errno))


/* make logs a bit more readable */
static const char *nmp_dbg_packet_types[] =
        {
                "request",
                "response",
                "data",
                "ack",
        };

static const char *nmp_dbg_session_status[] =
        {
                "SESSION_STATUS_NONE",
                "SESSION_STATUS_RESPONSE",
                "SESSION_STATUS_CONFIRM",
                "SESSION_STATUS_WINDOW",
                "SESSION_STATUS_ESTAB",
                "SESSION_STATUS_ACKWAIT",
        };

static const char *nmp_dbg_msg_status[] =
        {
                "MSG_TX_EMPTY",
                "MSG_TX_SENT",
                "MSG_TX_QUEUED",
                "MSG_TX_ACKED",
        };


#   define static
#   define inline

#else /* NMP_DEBUG */

#   define log(...)
#   define log_errno()

#endif /* NMP_DEBUG */


/* cosmetics */
#define UNUSED(arg_)    ((void)(arg_))
#define static_assert_pow2(x_) \
        static_assert(((x_) & ((x_) - 1)) == 0, "value must be a power of two")

#define mem_alloc(size_)                malloc(size_)
#define mem_free(ptr_)                  free(ptr_)
#define mem_zero(ptr_, len_)            memset(ptr_, 0, len_)
#define mem_copy(dest_, src_, len_)     memcpy(dest_, src_, len_)
#define mem_cmp(buf1_, buf2_, len_)     memcmp(buf1_, buf2_, len_)


/*
 * EVP api wrappers
 */
enum {
        SIPHASH_KEY = 16,
        SIPHASH_C = 2,
        SIPHASH_D = 4,
        SIPHASH_LEN = 8,
};


struct siphash_ctx {
        EVP_MAC *evp_mac;
        EVP_MAC_CTX *evp_ctx;
};


static i32 siphash_init(struct siphash_ctx *ctx,
                        u8 key[SIPHASH_KEY])
{
        if ((ctx->evp_mac = EVP_MAC_fetch(
                NULL, "siphash", "provider=default")) == NULL)
                return -1;

        u32 c_rounds = SIPHASH_C;
        u32 d_rounds = SIPHASH_D;
        u32 outsize = SIPHASH_LEN;

        const OSSL_PARAM params[] = {
                OSSL_PARAM_construct_octet_string("key", key, SIPHASH_KEY),
                OSSL_PARAM_construct_uint32("size", &outsize),
                OSSL_PARAM_construct_uint32("c-rounds", &c_rounds),
                OSSL_PARAM_construct_uint32("d-rounds", &d_rounds),
                OSSL_PARAM_END
        };


        if ((ctx->evp_ctx = EVP_MAC_CTX_new(ctx->evp_mac)) == NULL) {
                EVP_MAC_free(ctx->evp_mac);
                return 1;
        }

        if (EVP_MAC_CTX_set_params(ctx->evp_ctx, params) != 1) {
                EVP_MAC_CTX_free(ctx->evp_ctx);
                EVP_MAC_free(ctx->evp_mac);
                return 1;
        }

        return 0;
}


static i32 siphash_hash(struct siphash_ctx ctx,
                        const void *data, const u32 data_len,
                        u8 hash[SIPHASH_LEN])
{
        if (EVP_MAC_init(ctx.evp_ctx, NULL, 0, NULL) != 1)
                return 1;

        if (EVP_MAC_update(ctx.evp_ctx, data, data_len) != 1)
                return 1;

        return (EVP_MAC_final(ctx.evp_ctx, (u8 *) &hash,
                              NULL, SIPHASH_LEN) != 1);
}


static void siphash_free(struct siphash_ctx *ctx)
{
        EVP_MAC_CTX_free(ctx->evp_ctx);
        EVP_MAC_free(ctx->evp_mac);
}


enum {
        BLAKE2B_HASHLEN = 64,
};


struct blake2b_ctx {
        const EVP_MD *evp_md;
        EVP_MD_CTX *evp_ctx;
};


static i32 blake2b_init(struct blake2b_ctx *ctx)
{
        if ((ctx->evp_md = EVP_blake2b512()) == NULL)
                return 1;

        return ((ctx->evp_ctx = EVP_MD_CTX_new()) == NULL);
}


static i32 blake2b_reset(struct blake2b_ctx ctx)
{
        return (EVP_DigestInit_ex2(ctx.evp_ctx, ctx.evp_md, NULL) != 1);
}


static i32 blake2b_update(struct blake2b_ctx ctx,
                          const void *data, const u32 data_len)
{
        return (EVP_DigestUpdate(ctx.evp_ctx, data, data_len) != 1);
}


static i32 blake2b_final(struct blake2b_ctx ctx,
                         u8 out[BLAKE2B_HASHLEN])
{
        u32 outlen = BLAKE2B_HASHLEN;
        return (EVP_DigestFinal_ex(ctx.evp_ctx,
                                   out, &outlen) != 1);
}


static void blake2b_free(struct blake2b_ctx *ctx)
{
        if (ctx->evp_ctx)
                EVP_MD_CTX_free(ctx->evp_ctx);
}


struct blake2b_hmac_ctx {
        EVP_MAC *evp_mac;
        EVP_MAC_CTX *evp_ctx;
};


static i32 blake2b_hmac_init(struct blake2b_hmac_ctx *ctx)
{
        if ((ctx->evp_mac = EVP_MAC_fetch(
                NULL, "hmac", "provider=default")) == NULL)
                return 1;

        if ((ctx->evp_ctx = EVP_MAC_CTX_new(ctx->evp_mac)) == NULL) {
                EVP_MAC_free(ctx->evp_mac);
                return 1;
        }


        char digest[] = {'b', 'l', 'a', 'k', 'e',
                         '2', 'b', '5', '1', '2', 0};

        const OSSL_PARAM params[] =
                {
                        OSSL_PARAM_construct_utf8_string("digest", digest, 10),
                        OSSL_PARAM_END,
                };

        if (EVP_MAC_CTX_set_params(ctx->evp_ctx, params) != 1) {
                EVP_MAC_CTX_free(ctx->evp_ctx);
                EVP_MAC_free(ctx->evp_mac);
                return -1;
        }

        return 0;
}


static i32 blake2b_hmac_hash(struct blake2b_hmac_ctx *ctx,
                             const u8 key[BLAKE2B_HASHLEN],
                             const void *data, const u32 datalen,
                             u8 out[BLAKE2B_HASHLEN])
{
        if (EVP_MAC_init(ctx->evp_ctx, key, BLAKE2B_HASHLEN, NULL) != 1)
                return 1;

        if (EVP_MAC_update(ctx->evp_ctx, data, datalen) != 1)
                return 1;

        return (EVP_MAC_final(ctx->evp_ctx, out, NULL, BLAKE2B_HASHLEN) != 1);
}


static void blake2b_hmac_free(struct blake2b_hmac_ctx *ctx)
{
        if (ctx->evp_ctx)
                EVP_MAC_CTX_free(ctx->evp_ctx);

        if (ctx->evp_mac)
                EVP_MAC_free(ctx->evp_mac);
}


enum {
        CHACHA20POLY1305_KEYLEN = 32,
        CHACHA20POLY1305_TAGLEN = 16,
        CHACHA20POLY1305_NONCE = 12,
};


struct chacha20poly1305_ctx {
        EVP_CIPHER_CTX *evp_ctx;
};


static i32 chacha20poly1305_init(struct chacha20poly1305_ctx *ctx,
                                 const u8 key[CHACHA20POLY1305_KEYLEN])
{
        if ((ctx->evp_ctx = EVP_CIPHER_CTX_new()) == NULL)
                return 1;

        return (EVP_CipherInit_ex2(ctx->evp_ctx, EVP_chacha20_poly1305(),
                                   key, NULL, -1, NULL) != 1);
}


static i32 chacha20poly1305_set_key(struct chacha20poly1305_ctx *ctx,
                                    const u8 key[CHACHA20POLY1305_KEYLEN])
{
        return (EVP_CipherInit_ex2(ctx->evp_ctx, NULL,
                                   key, NULL, -1, NULL) != 1);
};


static i32 chacha20poly1305_encrypt(struct chacha20poly1305_ctx ctx,
                                    const u8 nonce[CHACHA20POLY1305_NONCE],
                                    const void *aad, const u32 aad_len,
                                    const void *plaintext, const u32 plainlen,
                                    u8 *ciphertext, u8 mac[CHACHA20POLY1305_TAGLEN])
{
        i32 outlen = 0;

        if (EVP_EncryptInit_ex2(ctx.evp_ctx, NULL,
                                NULL, nonce, NULL) != 1)
                return 1;

        if (EVP_EncryptUpdate(ctx.evp_ctx, NULL,
                              &outlen, aad, (i32) aad_len) != 1)
                return 1;

        if (EVP_EncryptUpdate(ctx.evp_ctx, ciphertext, &outlen,
                              plaintext, (i32) plainlen) != 1)
                return 1;

        if (EVP_EncryptFinal_ex(ctx.evp_ctx, ciphertext + outlen,
                                &outlen) != 1)
                return 1;

        return (EVP_CIPHER_CTX_ctrl(ctx.evp_ctx, EVP_CTRL_AEAD_GET_TAG,
                                    CHACHA20POLY1305_TAGLEN, mac) != 1);
}


static i32 chacha20poly1305_decrypt(struct chacha20poly1305_ctx ctx,
                                    const u8 nonce[CHACHA20POLY1305_NONCE],
                                    const void *aad, const u32 aadlen,
                                    const u8 *ciphertext, const u32 cipherlen,
                                    void *plaintext, u8 mac[CHACHA20POLY1305_TAGLEN])
{
        i32 outlen = 0;

        if (EVP_DecryptInit_ex2(ctx.evp_ctx, NULL,
                                NULL, nonce, NULL) != 1)
                return -1;

        if (EVP_DecryptUpdate(ctx.evp_ctx, NULL, &outlen,
                              aad, (i32) aadlen) != 1)
                return -1;

        if (EVP_DecryptUpdate(ctx.evp_ctx, plaintext, &outlen,
                              ciphertext, (i32) cipherlen) != 1)
                return -1;

        if (EVP_CIPHER_CTX_ctrl(ctx.evp_ctx, EVP_CTRL_AEAD_SET_TAG,
                                CHACHA20POLY1305_TAGLEN, mac) != 1)
                return -1;

        return (EVP_DecryptFinal(ctx.evp_ctx, plaintext + outlen,
                                 &outlen) != 1);

}

static void chacha20poly1305_free(struct chacha20poly1305_ctx *ctx)
{
        if (ctx->evp_ctx)
                EVP_CIPHER_CTX_free(ctx->evp_ctx);
}


enum {
        X448_KEYLEN = 56,
};


struct x448_public {
        EVP_PKEY *key;
};


static i32 x448_public_init(struct x448_public *ctx,
                            const u8 raw[X448_KEYLEN])
{
        return (ctx->key = EVP_PKEY_new_raw_public_key(
                EVP_PKEY_X448, NULL, raw, X448_KEYLEN)) == NULL;
}


static void x448_public_free(struct x448_public *ctx)
{
        EVP_PKEY_free(ctx->key);
}


struct x448_private {
        EVP_PKEY *key;
        EVP_PKEY_CTX *dh;
};


static u32 x448_private_init(struct x448_private *ctx,
                             const u8 key[X448_KEYLEN])
{
        if ((ctx->key = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, NULL, key, X448_KEYLEN)) == NULL)
                return 1;

        return (ctx->dh = EVP_PKEY_CTX_new(ctx->key, NULL)) == NULL;
}


static u32 x448_private_derive_pub(const struct x448_private *ctx,
                                   u8 pub[X448_KEYLEN])
{
        u64 keylen = X448_KEYLEN;
        return (EVP_PKEY_get_raw_public_key(ctx->key, pub, &keylen) != 1);
};


static void x448_private_free(struct x448_private *ctx)
{
        EVP_PKEY_CTX_free(ctx->dh);
        EVP_PKEY_free(ctx->key);
}


static i32 x448_dh(struct x448_private *priv,
                   struct x448_public pub,
                   u8 out[X448_KEYLEN])
{
        u64 dhlen = X448_KEYLEN;

        if (EVP_PKEY_derive_init_ex(priv->dh, NULL) != 1)
                return -1;

        if (EVP_PKEY_derive_set_peer_ex(priv->dh, pub.key, 1) != 1)
                return 1;

        return (EVP_PKEY_derive(priv->dh, out, &dhlen) != 1);
}


/*
 *  time
 */
static u64 time_get()
{
        struct timespec ts = {0};
        if (clock_gettime(CLOCK_TAI, &ts)) {
                log_errno();
                return 0;
        }

        return (u64) (ts.tv_sec * 1000llu + ts.tv_nsec / 1000000llu);
}


/*
 *  https://man7.org/linux/man-pages/man2/getrandom.2.html
 *  lets take advantage of nice things man page says about
 *  requests of up to 256 bytes
 */
enum {
        RND_POOL_SIZE = 256,
};

struct rnd_pool {
        u32 offset;
        u8 pool[RND_POOL_SIZE];
};


static u32 rnd_get(void *buf, const u32 amt)
{
        while (getrandom(buf, amt, 0) != amt) {
                /* none of this ever happens but lets check anyway */
                switch (errno) {
                case EINTR:
                        continue;

                default:
                        return 1;
                }
        }

        return 0;
}


static u32 rnd_reset_pool(struct rnd_pool *rnd)
{
        rnd->offset = 0;
        return rnd_get(rnd->pool, RND_POOL_SIZE);
}


static u32 rnd_get_bytes(struct rnd_pool *rnd, void *out, const u32 amt)
{
        assert(amt <= RND_POOL_SIZE);

        if (rnd->offset + amt > RND_POOL_SIZE) {
                if (rnd_reset_pool(rnd))
                        return 1;
        }

        mem_copy(out, rnd->pool + rnd->offset, amt);
        mem_zero(rnd->pool + rnd->offset, amt);

        rnd->offset += amt;
        return 0;
}


static u32 rnd_get32()
{
        u32 tmp = 0;

        while (!tmp) {
                if (rnd_get(&tmp, sizeof(u32)))
                        return 0;
        }

        return tmp;
}


/*
 *  https://en.wikipedia.org/wiki/Open_addressing
 *  https://en.wikipedia.org/wiki/Lazy_deletion
 */
enum {
        HT_SIZE = NMP_SESSIONS_MAX, /* @nmp.h */
        HT_RSIZE = (HT_SIZE * 2),
        HT_NOT_FOUND = (HT_SIZE + 1),
        HT_CACHE = (HT_SIZE / 4),
};

static_assert_pow2(HT_RSIZE);


enum ht_entry_status {
        HT_EMPTY = 0,
        HT_DELETED = 1,
        HT_OCCUPIED = 2,
};


struct ht_cache_entry {
        u32 id;
        u64 hash;
};


struct ht_entry {
        enum ht_entry_status status;
        u32 id;
        void *ptr;
};


struct hash_table {
        struct siphash_ctx siphash;
        u32 items;

        struct ht_cache_entry cache[HT_CACHE];
        struct ht_entry entry[HT_RSIZE];
};


static u64 ht_hash(struct hash_table *ht, const u32 key)
{
        u64 hash;
        const u32 index = key & (HT_CACHE - 1);

        if (ht->cache[index].id == key)
                return ht->cache[index].hash;

        /* fixme: this better have some better return than zero */
        if (siphash_hash(ht->siphash, &key,
                         sizeof(u32), (u8 *) &hash))
                return 0;

        ht->cache[index].id = key;
        ht->cache[index].hash = hash;

        return hash;
}


static u32 ht_slot(struct hash_table *ht, const u64 hash, const u32 item)
{
        const u32 natural_slot = (u32) hash & (HT_RSIZE - 1);

        u32 index = HT_NOT_FOUND;
        u32 index_swap = HT_NOT_FOUND;

        for (u32 i = 0; i < HT_RSIZE; i++) {
                index = (natural_slot + i) & (HT_RSIZE - 1);
                if (ht->entry[index].id == item)
                        break;

                if (ht->entry[index].status == HT_DELETED) {
                        if (index_swap == HT_NOT_FOUND)
                                index_swap = index;

                        continue;
                }

                if (ht->entry[index].status == HT_EMPTY)
                        break;
        }

        if (index_swap != HT_NOT_FOUND) {
                ht->entry[index_swap].status = HT_OCCUPIED;
                ht->entry[index_swap].id = ht->entry[index].id;
                ht->entry[index_swap].ptr = ht->entry[index].ptr;

                ht->entry[index].status = HT_DELETED;
                ht->entry[index].id = 0;
                ht->entry[index].ptr = NULL;
        }

        return index;
}


static void *ht_lookup(struct hash_table *ht, const u32 id)
{
        const u64 hash = ht_hash(ht, id);
        const u32 slot = ht_slot(ht, hash, id);

        if (slot == HT_NOT_FOUND || ht->entry[slot].id != id)
                return NULL;

        return ht->entry[slot].ptr;
}


static u32 ht_insert(struct hash_table *ht, const u32 id, void *ptr)
{
        if (ht->items >= HT_SIZE)
                return 1;

        const u64 hash = ht_hash(ht, id);
        const u32 natural_slot = (u32) hash & (HT_RSIZE - 1);

        for (u32 i = 0; i < HT_RSIZE; i++) {
                const u32 index = (natural_slot + i) & (HT_RSIZE - 1);
                if (ht->entry[index].status < HT_OCCUPIED) {
                        ht->entry[index].status = HT_OCCUPIED;
                        ht->entry[index].id = id;
                        ht->entry[index].ptr = ptr;

                        ht->items += 1;
                        return 0;
                }
        }

        return 1;
}


static void ht_remove(struct hash_table *ht, const u32 id)
{
        const u64 hash = ht_hash(ht, id);
        const u32 natural_slot = (u32) hash & (HT_RSIZE - 1);

        for (u32 i = 0; i < HT_RSIZE; i++) {
                const u32 index = (natural_slot + i) & (HT_RSIZE - 1);
                if (ht->entry[index].id == id) {
                        ht->entry[index].status = HT_DELETED;
                        ht->entry[index].id = 0;
                        ht->entry[index].ptr = NULL;

                        ht->items -= 1;
                        break;
                }
        }
}


static i32 ht_init(struct hash_table *ht,
                   u8 key[SIPHASH_KEY])
{
        return siphash_init(&ht->siphash, key);
}


static void ht_teardown(struct hash_table *ht,
                        u32 (*destructor)(void *))
{
        for (u32 i = 0; ht->items && i < HT_RSIZE; i++) {
                if (ht->entry[i].ptr) {
                        destructor(ht->entry[i].ptr);
                        ht->items -= 1;
                }
        }

        siphash_free(&ht->siphash);
}


/*
 *  message
 */

/* flags for message header length field */
#define MSG_NOACK           ((u16)(1 << 15))
#define MSG_RESERVED        ((u16)((1 << 14) | (1 << 13) | (1 << 12)))

/* flags for entries */
#define MSG_F_NOALLOC       (1u << 0)


enum {
        MSG_MASK_BITS = 64,
        MSG_WINDOW = MSG_MASK_BITS,
        MSG_TXQUEUE = NMP_QUEUELEN, /* @nmp.h */
        MSG_RXQUEUE = MSG_MASK_BITS,
        MSG_MAX_SINGLE = 1404,
        MSG_MAX_PAYLOAD = 1408,
};


enum msg_tx_status {
        MSG_TX_EMPTY = 0,
        MSG_TX_SENT = 1,
        MSG_TX_QUEUED = 2,
        MSG_TX_ACKED = 3,
};

enum msg_rx_status {
        MSG_RX_EMPTY = 0,
        MSG_RX_RECEIVED = 1,
};


struct msg_header {
        u16 sequence;
        u16 len;
        u8 data[];
};


struct msg_ack {
        u16 ack;
        u16 pad[3];
        u64 ack_mask;
};


struct msg_tx_entry {
        u8 status;
        u8 msg_flags;
        u8 pad[2];
        u16 seq;
        u16 len;
        u64 user_data;
        u8 *msg;
};


struct msg_rx_entry {
        enum msg_rx_status status;
        u16 seq;
        u16 len;
        u8 data[MSG_MAX_SINGLE];
};


struct msg_routines {
        void (*data)(const u8 *, u32, void *);
        void (*data_noack)(const u8 *, u32, void *);
        void (*ack)(u64, void *);
};


struct msg_state {
        void *context_ptr;
        u16 payload_max;

        u16 tx_seq;
        u16 tx_sent;
        u16 tx_ack;

        u16 rx_seq;
        u16 rx_delivered;

        struct msg_tx_entry tx_queue[MSG_TXQUEUE];
        struct msg_rx_entry rx_buffer[MSG_RXQUEUE];
};


/* convenience: get a pointer to entry by sequence number */
#define tx_get(ctx_, n_) ((ctx_)->tx_queue + ((n_) & (MSG_TXQUEUE - 1)))
#define rx_get(ctx_, n_) ((ctx_)->rx_buffer + ((n_) & (MSG_RXQUEUE - 1)))

static_assert_pow2(MSG_TXQUEUE);
static_assert_pow2(MSG_RXQUEUE);


/* compare sequence numbers, cover for wraparound */
static inline i32 msg_sequence_cmp(const u16 a, const u16 b)
{
        return ((a <= b) ? ((b - a) > 0xff) : ((a - b) < 0xff));
}


static inline i32 msg_payload_zeropad(u8 *payload, const i32 len)
{
        const i32 padding = (16 - len) & 15;
        const i32 payload_len = len + padding;

        for (i32 i = 0; i < padding; i++) {
                payload[len + i] = 0;
        }

        assert(payload_len <= MSG_MAX_PAYLOAD);
        return payload_len;
}


static inline void msg_tx_include(const struct msg_tx_entry *tx,
                                  struct msg_header *msg)
{
        msg->sequence = tx->seq;
        msg->len = tx->len;

        mem_copy(msg->data, tx->msg, tx->len);
        log("seq %u %s", msg->sequence, nmp_dbg_msg_status[tx->status]);
}


static inline void msg_rx_copy(struct msg_rx_entry *entry,
                               const struct msg_header *msg)
{
        entry->status = MSG_RX_RECEIVED;
        entry->seq = msg->sequence;
        entry->len = msg->len;

        mem_copy(entry->data, msg->data, msg->len);
        log("seq %u len %u", msg->sequence, msg->len);
}


static inline u64 msg_latest_acked(const struct msg_state *ctx)
{
        return tx_get(ctx, ctx->tx_ack)->user_data;
}


static void msg_context_wipe(struct msg_state *ctx)
{
        for (u16 i = ctx->tx_ack;; i++) {
                struct msg_tx_entry *entry = tx_get(ctx, i);
                if (entry->status != MSG_TX_EMPTY) {
                        if ((entry->msg_flags & MSG_F_NOALLOC) == 0)
                                mem_free(entry->msg);
                }

                if (i == ctx->tx_seq)
                        break;
        }
}


static u32 msg_queue(struct msg_state *ctx, const u8 *msg, const u16 len,
                     const u8 flags, const u64 user_data)
{
        assert(msg);

        /* pre-increment: check one ahead */
        const u32 index = (ctx->tx_seq + 1) & (MSG_TXQUEUE - 1);
        struct msg_tx_entry *entry = ctx->tx_queue + index;

        if (entry->status > MSG_TX_SENT) {
                log("cannot queue new msg");
                return 1;
        }

        ctx->tx_seq += 1;

        entry->status = MSG_TX_QUEUED;
        entry->msg_flags = flags;
        entry->seq = ctx->tx_seq;
        entry->msg = (u8 *) msg;
        entry->len = len;
        entry->user_data = user_data;

        return 0;
}


static i32 msg_assemble(struct msg_state *ctx, u8 output[MSG_MAX_PAYLOAD])
{
        struct msg_tx_entry *resend_queue[MSG_WINDOW] = {0};
        u32 resend_amt = 0;
        u32 bytes = 0;

        /*
         * plus one as queuing messages is pre-incremented,
         * and we want to look at the first fresh item
         */
        const u16 seq_lo = ctx->tx_ack + 1;
        const u16 seq_hi = seq_lo + MSG_WINDOW;

        if (ctx->tx_ack + MSG_WINDOW == ctx->tx_sent) {
                /* cannot send any fresh messages */
                return -1;
        }

        for (u16 i = seq_lo; i != seq_hi; i++) {
                struct msg_tx_entry *msg = tx_get(ctx, i);
                if (msg->status == MSG_TX_EMPTY)
                        break;

                if (msg->status == MSG_TX_SENT) {
                        resend_queue[resend_amt] = msg;
                        resend_amt += 1;
                        continue;
                }

                if (msg->status == MSG_TX_QUEUED) {
                        const u32 offset = msg->len + sizeof(struct msg_header);
                        if (bytes + offset > ctx->payload_max)
                                break;

                        msg_tx_include(msg, (struct msg_header *) (output + bytes));

                        bytes += offset;
                        msg->status = MSG_TX_SENT;
                        ctx->tx_sent = msg->seq;
                }
        }

        if (bytes == 0)
                return 0;

        for (u32 i = 0; i < resend_amt; i++) {
                const u16 offset = resend_queue[i]->len + sizeof(struct msg_header);
                if (bytes + offset > ctx->payload_max)
                        break;

                msg_tx_include(resend_queue[i], (struct msg_header *) (output + bytes));
                bytes += offset;
        }

        return msg_payload_zeropad(output, (i32) bytes);
}


static i32 msg_assemble_retry(const struct msg_state *ctx,
                              u8 output[MSG_MAX_PAYLOAD])
{
        i32 bytes = 0;

        for (u16 i = ctx->tx_ack + 1;; i++) {
                const struct msg_tx_entry *msg = tx_get(ctx, i);
                if (msg->status == MSG_TX_SENT) {
                        const u16 offset = msg->len + sizeof(struct msg_header);
                        if (bytes + offset > ctx->payload_max)
                                break;

                        msg_tx_include(msg, (struct msg_header *) (output + bytes));
                        bytes += offset;
                }

                if (i == ctx->tx_sent)
                        break;
        }

        return msg_payload_zeropad(output, bytes);
}


u32 msg_assemble_noack(struct msg_header *header,
                       const u8 *payload, const u16 len)
{
        header->sequence = 0;
        header->len = len;
        header->len |= MSG_NOACK;

        mem_copy(header->data, payload, len);
        return msg_payload_zeropad(header->data,
                                   (i32) (len + sizeof(struct msg_header)));
}


static i32 msg_read(const struct msg_routines *cb, struct msg_state *ctx,
                    const u8 *payload, const u32 len)
{
        u32 iterator = 0;
        i32 new_messages = 0;
        u32 discovered = 0;

        const u16 seq_low = ctx->rx_delivered;
        const u16 seq_high = (u16) (seq_low + MSG_WINDOW);

        for (;; discovered++) {
                const struct msg_header *msg = (const struct msg_header *) (payload + iterator);
                if ((len - iterator) <= sizeof(struct msg_header))
                        break;

                if (msg->len == 0)
                        break;

                const u16 msg_len = msg->len & ~(MSG_NOACK | MSG_RESERVED);
                if (msg->len & MSG_RESERVED) {
                        log("reserved bits");
                        return -1;
                }

                /*
                 * example: msg->len == 1000 but there are 100 bytes left
                 * to read in the packet; lets have a protection against this
                 */
                const u16 msg_maxlen = (u16) (len - iterator - sizeof(struct msg_header));
                if (msg_len > msg_maxlen) {
                        log("rejecting message size");
                        return -1;
                }

                if (msg->len & MSG_NOACK) {
                        /* mixing regular and noack messages is not allowed */
                        if (discovered) {
                                log("broken format");
                                return -1;
                        }

                        if (cb->data_noack)
                                cb->data_noack(msg->data, msg->len, ctx->context_ptr);

                        return (MSG_WINDOW + 1);
                }


                if (msg_sequence_cmp(msg->sequence, seq_low)) {
                        if (msg_sequence_cmp(msg->sequence, seq_high)) {
                                log("rejecting sequence %u over %u",
                                    msg->sequence, seq_high);

                                return -1;
                        }

                        if (msg_sequence_cmp(msg->sequence, ctx->rx_seq))
                                ctx->rx_seq = msg->sequence;

                        struct msg_rx_entry *entry = rx_get(ctx, msg->sequence);
                        if (entry->status == MSG_RX_EMPTY) {
                                new_messages += 1;
                                msg_rx_copy(entry, msg);
                        }
                }

                iterator += (msg->len + sizeof(struct msg_header));
        }

        return new_messages;
}

/*
 *  this can be called only if there are new messages to deliver
 */
static void msg_deliver_data(const struct msg_routines *cb,
                             struct msg_state *ctx)
{
        for (u16 n = ctx->rx_delivered + 1;; n++) {
                struct msg_rx_entry *entry = rx_get(ctx, n);
                if (entry->status == MSG_RX_EMPTY)
                        break;

                if (cb->data)
                        cb->data(entry->data, entry->len, ctx->context_ptr);

                ctx->rx_delivered = n;
                entry->status = MSG_RX_EMPTY;

                if (n == ctx->rx_seq)
                        break;
        }
}

/*
 *  start with all bits set, then walk backwards
 *  clearing bits for missing messages
 */
static void msg_ack_assemble(const struct msg_state *ctx, struct msg_ack *ack)
{
        u64 mask = UINT64_MAX;
        u32 shift = 0;
        const u16 seq_hi = ctx->rx_seq;
        const u16 seq_lo = ctx->rx_delivered;

        for (u16 i = seq_hi;; i--) {
                if (i == seq_lo) {
                        /*
                         * it is important not to go back beyond
                         * seq_lo: those are guaranteed to be processed
                         * so any state modifications will break the logic
                         */
                        break;
                }

                const struct msg_rx_entry *entry = rx_get(ctx, i);
                if (entry->status == MSG_RX_EMPTY) {
                        log("clearing bit %u for seq %u", i, entry->seq);
                        mask &= ~(1lu << shift);
                }

                assert(shift <= MSG_WINDOW);
                shift += 1;
        }

        ack->ack = seq_hi;
        ack->pad[0] = 0;
        ack->pad[1] = 0;
        ack->pad[2] = 0;
        ack->ack_mask = mask;
}


static i32 msg_ack_read(struct msg_state *ctx, const struct msg_ack *ack)
{
        i32 discovered = 0;
        u64 mask = ack->ack_mask;


        if (msg_sequence_cmp(ack->ack, ctx->tx_ack)) {
                if (msg_sequence_cmp(ack->ack, ctx->tx_sent)) {
                        /*
                         * remote peer tries to send ack for something
                         * we did not send yet, cannot have this
                         */
                        log("rejecting ack %u (sent %u)",
                            ack->ack, ctx->tx_sent);

                        return -1;
                }

                if ((mask & 1) == 0) {
                        /*
                         * first bit corresponds to current ack
                         * sequence, it is always set
                         */
                        log("rejecting ack: first bit not set");
                        return -1;
                }

                for (u16 i = ack->ack;; i--) {
                        if (mask & 1) {
                                struct msg_tx_entry *msg = tx_get(ctx, i);
                                if (msg->status == MSG_TX_SENT) {
                                        msg->status = MSG_TX_ACKED;
                                        discovered += 1;
                                }
                        }

                        if (i == ctx->tx_ack)
                                break;

                        mask >>= 1;
                }
        }

        return discovered;
}


static i32 msg_deliver_ack(const struct msg_routines *cb,
                           struct msg_state *ctx)
{
        i32 counter = 0;

        /*
         * plus one: tx_ack is the number of a processed
         * message, start with the next one
         */
        for (u16 i = ctx->tx_ack + 1;; i++) {
                struct msg_tx_entry *msg = tx_get(ctx, i);
                if (msg->status != MSG_TX_ACKED)
                        break;

                log("delivering ack %u", msg->seq);

                if (cb->ack)
                        cb->ack(msg->user_data, ctx->context_ptr);

                msg->status = MSG_TX_EMPTY;

                if ((msg->msg_flags & MSG_F_NOALLOC) == 0)
                        mem_free(msg->msg);

                ctx->tx_ack = msg->seq;
                counter += 1;

                if (msg->seq == ctx->tx_sent)
                        break;
        }

        if (ctx->tx_ack == ctx->tx_seq)
                return -1;

        return counter;
}


/*
 * IK:
 *   <- s
 *   ...
 *   -> e, es, s, ss
 *   <- e, ee, se
 */
enum {
        NOISE_KEYLEN = 32,
        NOISE_HASHLEN = BLAKE2B_HASHLEN,
        NOISE_DHLEN = X448_KEYLEN,
        NOISE_AEAD_MAC = CHACHA20POLY1305_TAGLEN,
        NOISE_HANDSHAKE_PAYLOAD = 128,
        NOISE_COUNTER_WINDOW = 224,
};


enum {
        NOISE_NONCE_MAX = UINT64_MAX,
};


/* "Noise_IK_448_ChaChaPoly_BLAKE2b" padded with zeros to be NOISE_HASHLEN long */
static const u8 noise_protocol_name[NOISE_HASHLEN] = {
        0x4e, 0x6f, 0x69, 0x73, 0x65, 0x5f, 0x49, 0x4b,
        0x5f, 0x34, 0x34, 0x38, 0x5f, 0x43, 0x68, 0x61,
        0x43, 0x68, 0x61, 0x50, 0x6f, 0x6c, 0x79, 0x5f,
        0x42, 0x4c, 0x41, 0x4b, 0x45, 0x32, 0x62, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};


struct noise_initiator {
        u8 ephemeral[NOISE_DHLEN];
        u8 encrypted_static[NOISE_DHLEN];
        u8 mac1[NOISE_AEAD_MAC];
        u8 encrypted_payload[NOISE_HANDSHAKE_PAYLOAD];
        u8 mac2[NOISE_AEAD_MAC];
};


struct noise_responder {
        u8 ephemeral[NOISE_DHLEN];
        u8 encrypted_payload[NOISE_HANDSHAKE_PAYLOAD];
        u8 mac[NOISE_AEAD_MAC];
};


struct noise_keypair {
        struct x448_private priv;
        u8 pub_raw[NOISE_DHLEN];
};


struct noise_handshake {
        struct rnd_pool *rnd;
        struct blake2b_hmac_ctx hmac;
        struct blake2b_ctx hash;
        struct chacha20poly1305_ctx aead;

        u8 cipher_k[NOISE_KEYLEN];
        u64 cipher_n;
        u8 symmetric_ck[NOISE_HASHLEN];
        u8 symmetric_h[NOISE_HASHLEN];

        struct noise_keypair *s;
        struct noise_keypair e;
        u8 rs[NOISE_DHLEN];
        u8 re[NOISE_DHLEN];
};


static i32 noise_hash(struct blake2b_ctx hash,
                      const void *data, const u32 data_len,
                      u8 output[NOISE_HASHLEN])
{
        if (blake2b_reset(hash))
                return -1;

        if (blake2b_update(hash, data, data_len))
                return -1;

        return blake2b_final(hash, output);
}


static inline i32 noise_hmac_hash(struct blake2b_hmac_ctx *hmac,
                                  const u8 key[NOISE_HASHLEN],
                                  const void *data, const u32 data_len,
                                  u8 output[NOISE_HASHLEN])
{
        return blake2b_hmac_hash(hmac, key, data, data_len, output);
}


/*
 * noise spec has third output, but it is not used
 * in this handshake pattern so not included here
 */
static u32 noise_hkdf(struct blake2b_hmac_ctx *hmac,
                      const u8 ck[NOISE_HASHLEN],
                      const u8 *ikm, const u32 ikm_len,
                      u8 output1[NOISE_HASHLEN],
                      u8 output2[NOISE_HASHLEN])
{
        const u8 byte_1 = 0x01;
        u8 temp_key[NOISE_HASHLEN] = {0};
        if (noise_hmac_hash(hmac, ck,
                            ikm, ikm_len,
                            temp_key))
                return 1;

        if (noise_hmac_hash(hmac, temp_key,
                            &byte_1, sizeof(u8),
                            output1))
                return 1;

        u8 buf2[NOISE_HASHLEN + 8] = {0};
        mem_copy(buf2, output1, NOISE_HASHLEN);
        buf2[NOISE_HASHLEN] = 0x02; /* h || byte(0x02) */

        return noise_hmac_hash(hmac, temp_key,
                               buf2, (NOISE_HASHLEN + sizeof(u8)),
                               output2);
}


static inline i32 noise_dh(struct blake2b_ctx hash,
                           struct noise_keypair *key_pair,
                           const u8 *pub_raw,
                           u8 shared_secret[NOISE_DHLEN])
{
        i32 err = 0;
        u8 tmp_dh[NOISE_DHLEN] = {0};
        u8 tmp_hash[NOISE_HASHLEN] = {0};
        struct x448_public pub = {0};

        if (x448_public_init(&pub, pub_raw))
                return -1;

        if ((err = x448_dh(&key_pair->priv, pub, tmp_dh)))
                goto out_fail;

        if (noise_hash(hash, tmp_dh,
                       NOISE_DHLEN, tmp_hash)) {
                err = -1;
                goto out_fail;
        }

        mem_copy(shared_secret, tmp_hash, NOISE_DHLEN);
        x448_public_free(&pub);
        return 0;

        out_fail:
        {
                x448_public_free(&pub);
                return err;
        };
}


static inline u32 noise_keypair_initialize(struct noise_keypair *pair,
                                           const u8 private[NOISE_DHLEN])
{
        if (x448_private_init(&pair->priv, private))
                return 1;

        return x448_private_derive_pub(&pair->priv, pair->pub_raw);
}


static u32 noise_keypair_generate(struct blake2b_ctx h,
                                  struct rnd_pool *rnd,
                                  struct noise_keypair *pair)
{
        u8 buf[NOISE_HASHLEN] = {0};
        if (rnd_get_bytes(rnd, &buf, sizeof(buf)))
                return 1;

        u8 hash[NOISE_HASHLEN] = {0};
        if (noise_hash(h, buf, NOISE_HASHLEN, hash))
                return 1;

        return noise_keypair_initialize(pair, hash);
}


static void noise_keypair_del(struct noise_keypair *pair)
{
        x448_private_free(&pair->priv);
}


static inline void noise_chacha20_nonce(const u64 n,
                                        u8 out[CHACHA20POLY1305_NONCE])
{
        out[0] = 0;
        out[1] = 0;
        out[2] = 0;
        out[3] = 0;
        out[4] = (u8) (n);
        out[5] = (u8) (n >> 8);
        out[6] = (u8) (n >> 16);
        out[7] = (u8) (n >> 24);
        out[8] = (u8) (n >> 32);
        out[9] = (u8) (n >> 40);
        out[10] = (u8) (n >> 48);
        out[11] = (u8) (n >> 56);
}


static inline u32 noise_encrypt(struct chacha20poly1305_ctx cipher, const u64 n,
                                const void *ad, const u32 ad_len,
                                const void *plaintext, const u32 plaintext_len,
                                u8 *ciphertext, u8 *mac)
{
        u8 nonce[CHACHA20POLY1305_NONCE];
        noise_chacha20_nonce(n, nonce);

        return chacha20poly1305_encrypt(cipher, nonce, ad, ad_len,
                                        plaintext, plaintext_len,
                                        ciphertext, mac);
}


static inline u32 noise_decrypt(struct chacha20poly1305_ctx cipher, const u64 n,
                                const void *ad, const u32 ad_len,
                                const u8 *ciphertext, const u32 ciphertext_len,
                                u8 *mac, void *plaintext)
{
        u8 nonce[CHACHA20POLY1305_NONCE];
        noise_chacha20_nonce(n, nonce);

        return chacha20poly1305_decrypt(cipher, nonce, ad, ad_len,
                                        ciphertext, ciphertext_len,
                                        plaintext, mac);
}


static u32 noise_mix_key(struct noise_handshake *state,
                         const u8 *ikm, const u32 ikm_len)
{
        u8 temp_k[NOISE_HASHLEN] = {0};

        if (noise_hkdf(&state->hmac, state->symmetric_ck,
                       ikm, ikm_len,
                       state->symmetric_ck,
                       temp_k))
                return 1;

        /* initialize_key(temp_k), truncated */
        mem_copy(state->cipher_k, temp_k, NOISE_KEYLEN);
        return 0;
}


static u32 noise_mix_hash(struct noise_handshake *state,
                          const void *data, const u32 data_len)
{
        if (blake2b_reset(state->hash))
                return 1;

        if (blake2b_update(state->hash, state->symmetric_h, NOISE_HASHLEN))
                return 1;

        if (blake2b_update(state->hash, data, data_len))
                return 1;

        return blake2b_final(state->hash, state->symmetric_h);
}


/*
 * serves as a mix_key(dh(..))
 */
static u32 noise_mix_key_dh(struct noise_handshake *state,
                            struct noise_keypair *pair,
                            const u8 *public_key)
{
        u8 temp_dh[NOISE_DHLEN] = {0};
        if (noise_dh(state->hash, pair,
                     public_key, temp_dh))
                return 1;

        if (noise_mix_key(state, temp_dh, NOISE_DHLEN))
                return 1;

        return 0;
}


static u32 noise_encrypt_and_hash(struct noise_handshake *state,
                                  const void *plaintext, const u32 plaintext_len,
                                  u8 *ciphertext, u8 *mac)
{
        if (chacha20poly1305_set_key(&state->aead, state->cipher_k))
                return 1;

        if (noise_encrypt(state->aead, state->cipher_n,
                          state->symmetric_h, NOISE_HASHLEN,
                          plaintext, plaintext_len,
                          ciphertext, mac))
                return 1;


        if (noise_mix_hash(state, ciphertext, plaintext_len))
                return 1;

        return 0;
}


static u32 noise_decrypt_and_hash(struct noise_handshake *state,
                                  const u8 *ciphertext, const u32 ciphertext_len,
                                  u8 *mac, void *plaintext)
{
        if (chacha20poly1305_set_key(&state->aead, state->cipher_k))
                return 1;

        if (noise_decrypt(state->aead, state->cipher_n,
                          state->symmetric_h, NOISE_HASHLEN,
                          ciphertext, ciphertext_len,
                          mac, plaintext))
                return 1;

        if (noise_mix_hash(state, ciphertext, ciphertext_len))
                return 1;

        return 0;
}


static u32 noise_split(struct noise_handshake *state,
                       struct chacha20poly1305_ctx *c1,
                       struct chacha20poly1305_ctx *c2)
{
        u8 temp_k1[NOISE_HASHLEN] = {0};
        u8 temp_k2[NOISE_HASHLEN] = {0};

        if (noise_hkdf(&state->hmac, state->symmetric_ck,
                       NULL, 0,
                       temp_k1, temp_k2))
                return 1;

        if (chacha20poly1305_set_key(c1, temp_k1))
                return 1;

        if (chacha20poly1305_set_key(c2, temp_k2))
                return 1;

        return 0;
}


static u32 noise_state_init(struct noise_handshake *state)
{
        /* these state normally have values set already, so: */
        return noise_mix_hash(state, state->rs, NOISE_DHLEN);
}


static void noise_state_del(struct noise_handshake *state)
{
        noise_keypair_del(&state->e);
}


static u32 noise_initiator_write(struct noise_handshake *state,
                                 struct noise_initiator *initiator,
                                 const void *ad, const u32 ad_len,
                                 const u8 *payload)
{
        if (noise_mix_hash(state, ad, ad_len))
                return 1;

        /* e */
        if (noise_keypair_generate(state->hash, state->rnd, &state->e))
                return 1;

        mem_copy(initiator->ephemeral, state->e.pub_raw, NOISE_DHLEN);
        if (noise_mix_hash(state, state->e.pub_raw, NOISE_DHLEN))
                return 1;

        /* es */
        if (noise_mix_key_dh(state, &state->e, state->rs))
                return 1;

        /* s */
        if (noise_encrypt_and_hash(state,
                                   state->s->pub_raw, NOISE_DHLEN,
                                   initiator->encrypted_static,
                                   initiator->mac1))
                return 1;

        /* ss */
        if (noise_mix_key_dh(state, state->s, state->rs))
                return 1;

        /* payload: encrypt_and_hash(payload) */
        return noise_encrypt_and_hash(state,
                                      payload, NOISE_HANDSHAKE_PAYLOAD,
                                      initiator->encrypted_payload, initiator->mac2);
}


static u32 noise_responder_read(struct noise_handshake *state,
                                struct noise_responder *responder,
                                const void *ad, const u32 ad_len,
                                u8 *payload)
{
        if (noise_mix_hash(state, ad, ad_len))
                return 1;

        /* e */
        if (noise_mix_hash(state, responder->ephemeral, NOISE_DHLEN))
                return 1;

        /* ee */
        if (noise_mix_key_dh(state, &state->e, responder->ephemeral))
                return 1;

        /* se */
        if (noise_mix_key_dh(state, state->s, responder->ephemeral))
                return 1;

        /* payload */
        return noise_decrypt_and_hash(state, responder->encrypted_payload,
                                      NOISE_HANDSHAKE_PAYLOAD,
                                      responder->mac, payload);
}


static u32 noise_initiator_read(struct noise_handshake *state,
                                struct noise_initiator *initiator,
                                const void *ad, const u32 ad_len,
                                u8 *payload)
{
        if (noise_mix_hash(state, ad, ad_len))
                return 1;

        /* e */
        mem_copy(state->re, initiator->ephemeral, NOISE_DHLEN);
        if (noise_mix_hash(state, state->re, NOISE_DHLEN))
                return 1;

        /* es */
        if (noise_mix_key_dh(state, state->s, state->re))
                return 1;

        /* s */
        if (noise_decrypt_and_hash(state, initiator->encrypted_static, NOISE_DHLEN,
                                   initiator->mac1, state->rs)) {
                log("failed to process s");
                return 1;
        }

        /* ss */
        if (noise_mix_key_dh(state, state->s, state->rs))
                return 1;

        /* payload */
        return noise_decrypt_and_hash(state, initiator->encrypted_payload,
                                      NOISE_HANDSHAKE_PAYLOAD,
                                      initiator->mac2, payload);
}


static u32 noise_responder_write(struct noise_handshake *state,
                                 struct noise_responder *responder,
                                 const void *ad, const u32 ad_len,
                                 const void *payload)
{
        if (noise_mix_hash(state, ad, ad_len))
                return 1;

        /* e */
        if (noise_keypair_generate(state->hash, state->rnd, &state->e))
                return 1;

        mem_copy(responder->ephemeral, state->e.pub_raw, NOISE_DHLEN);
        if (noise_mix_hash(state, state->e.pub_raw, NOISE_DHLEN))
                return 1;

        /* ee */
        if (noise_mix_key_dh(state, &state->e, state->re))
                return 1;

        /* se */
        if (noise_mix_key_dh(state, &state->e, state->rs))
                return 1;

        /* payload */
        return noise_encrypt_and_hash(state,
                                      payload, NOISE_HANDSHAKE_PAYLOAD,
                                      responder->encrypted_payload, responder->mac);
}


static i32 noise_counter_validate(const u32 block[8],
                                  const u64 local,
                                  const u64 remote)
{
        if (remote + NOISE_COUNTER_WINDOW < local) {
                log("rejecting counter: too old");
                return -1;
        }

        if (remote > (local + NOISE_COUNTER_WINDOW) || remote == NOISE_NONCE_MAX) {
                log("rejecting counter: outside of window / max");
                return -1;
        }

        const i32 block_index = (i32) (remote / 32) & 7;
        if (remote <= local) {
                if (block[block_index] & (1 << (remote & 31))) {
                        log("already received [%zu]", remote);
                        return -1;
                }
        }

        /*
         * at this point only sequences above local counter are left,
         * and they are within allowed forward window, so it is ok
         */
        return block_index;
}


/*
 *
 */
#define SESSION_EVENT_QUEUED        (1u << 0)   /* is this context in queue? */
#define SESSION_EVENT_ACK           (1u << 1)   /* new acks arrived */
#define SESSION_EVENT_DATA          (1u << 2)   /* new message available */


struct nmp_header {
        u8 type;
        u8 pad[3];
        u32 session_id;
};


struct nmp_request {
        struct nmp_header header;
        struct noise_initiator initiator;
};


struct nmp_response {
        struct nmp_header header;
        struct noise_responder responder;
};


struct nmp_transport {
        struct nmp_header type_pad_id;
        u64 counter;

        /* u8 ciphertext[..]; */
        /* u8 mac[16]; */
};


/*
 *  milliseconds
 */
enum {
#if defined(NMP_DEBUG_TIMERS)
        SESSION_REQUEST_TTL = 0xffffffff,
#else
        SESSION_REQUEST_TTL = 15000,
#endif
};


#define kts(sec_, ms_) (struct __kernel_timespec) {(sec_), (1000000lu * (ms_)) }

static const struct __kernel_timespec rto_table[] =
        {
                kts(0, 250),
                kts(0, 250),
                kts(0, 350),
                kts(0, 350),
                kts(0, 500),
                kts(0, 500),
                kts(0, 500),
                kts(0, 500),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
                kts(1, 0),
        };


enum retries {
        /*
         * this covers an extremely rare case when our acks and/or responses do
         * not go through: how many times we can respond to a valid request or how
         * many acks to send if received data packet did not contain any new messages
         */
        SESSION_RETRY_RESPONSE = 10,

        /* how many times to retry sending data */
        SESSION_RETRY_DATA = (sizeof(rto_table) / sizeof(struct __kernel_timespec)),

        /* how often (in seconds) to retry sending data */
        SESSION_RETRY_INTERVAL = 1,
};


enum packet_types {
        NMP_REQUEST = 0,
        NMP_RESPONSE = 1,
        NMP_DATA = 2,
        NMP_ACK = 3,
};


enum session_status {
        /* empty or marked for deletion */
        SESSION_STATUS_NONE = 0,

        /* waiting for response */
        SESSION_STATUS_RESPONSE = 1,

        /* waiting for the first message */
        SESSION_STATUS_CONFIRM = 2,

        /* maximum number of messages is in transit */
        SESSION_STATUS_WINDOW = 3,

        /* established connection */
        SESSION_STATUS_ESTAB = 4,

        /* some data is in transit, waiting for ack */
        SESSION_STATUS_ACKWAIT = 5
};


enum packet_limits {
        NET_PACKET_MAX = 1440,
        NET_PACKET_MIN = 32,
};


enum pbuf_groups {
        RING_NET_GROUP = 0,
        RING_LOCAL_GROUP = 1,
};


enum ring_params {
        RING_BATCH = 32,
        RING_RECV_BUFS = 512,
        RING_SQ = (MSG_WINDOW * RING_BATCH),
        RING_CQ = (RING_SQ * 4),
};


struct nmp_init_payload {
        u64 timestamp;
        u8 reserved[24];
        u8 data[NMP_INITIATION_PAYLOAD];
};


struct nmp_buf_send {
        union nmp_sa addr;
        struct msghdr send_hdr;
        struct iovec iov;

        union {
                struct nmp_request request;
                struct nmp_response response;
                struct nmp_transport transport;
                u8 data[NET_PACKET_MAX];
        };
};


struct nmp_pbuf_net {
        u8 data[2048];
};


struct nmp_pbuf_local {
        struct nmp_rq op[NMP_RQ_BATCH];
};


/* recvmsg multishot */
struct nmp_recv_net {
        struct io_uring_buf_ring *ring;
        struct nmp_pbuf_net *base;
        u32 size;
};


/* recv multishot */
struct nmp_recv_local {
        struct io_uring_buf_ring *ring;
        struct nmp_pbuf_local *base;
        u32 size;
};


struct nmp_session_init {
        struct noise_handshake handshake;
        struct nmp_init_payload payload;

        /* responder saves remote initiator */
        struct nmp_request request_buf;

        /* initiator/responder saves its own request/response */
        struct nmp_buf_send send_buf;
};


struct nmp_session {
        enum session_status state;
        u32 session_id;

        u8 flags;
        u8 events;
        u8 response_retries;
        u8 timer_retries;
        u8 timer_keepalive;
        u8 timer_retry_table[6];

        u64 noise_counter_send;
        u64 noise_counter_receive;
        u32 noise_counter_block[8];
        struct chacha20poly1305_ctx noise_key_receive;
        struct chacha20poly1305_ctx noise_key_send;

        union nmp_sa addr;
        u64 stat_tx;
        u64 stat_rx;
        struct __kernel_timespec kts;
        struct nmp_session_init *initiation;

        union { /* just share first member */
                void *context_ptr;
                struct msg_state transport;
        };

        u32 send_iter;
        struct nmp_buf_send send_bufs[MSG_WINDOW];
};


struct nmp_instance {
        struct io_uring ring;
        struct msghdr recv_hdr;
        struct nmp_recv_net recv_net;
        struct nmp_recv_local recv_local;

        i32 net_udp;
        i32 local_rx;
        i32 local_tx;
        u32 options;
        sa_family_t sa_family;
        struct __kernel_timespec kts;

        void *request_ctx;
        int (*request_cb)(struct nmp_rq_connect *, const u8 *, void *);
        int (*status_cb)(const enum nmp_status, const union nmp_cb_status *, void *);
        void (*stats_cb)(const u64, const u64, void *);

        struct msg_routines transport_callbacks;
        struct noise_keypair static_keys;
        struct rnd_pool rnd;

        u32 send_iter;
        struct nmp_buf_send send_bufs[RING_BATCH];

        struct hash_table sessions;

        struct blake2b_ctx hash;
        struct blake2b_hmac_ctx hmac;
        struct chacha20poly1305_ctx cipher;

        struct noise_handshake noise_empty;
        struct noise_handshake noise_precomp;
};


static_assert((u32) NMP_KEYLEN == (u32) NOISE_DHLEN, "keylen");
static_assert((u32) NMP_PAYLOAD_MAX == (u32) MSG_MAX_SINGLE, "payload");
static_assert(sizeof(struct nmp_init_payload) == NOISE_HANDSHAKE_PAYLOAD, "initiation payload");

static_assert_pow2(RING_BATCH);
static_assert_pow2(RING_SQ);
static_assert_pow2(RING_CQ);
static_assert_pow2(RING_RECV_BUFS);


#define header_init(type_, id_) (struct nmp_header) { \
                        .type = (type_),              \
                        .pad = {0,0,0},               \
                        .session_id = (id_)}          \



static inline struct io_uring_sqe *nmp_ring_sqe(struct nmp_instance *nmp)
{
        struct io_uring_sqe *sqe = io_uring_get_sqe(&nmp->ring);
        if (sqe == NULL) {
                log("retrying io_uring_get_sqe()");

                const int res = io_uring_submit(&nmp->ring);
                if (res < 0) {
                        log("submit failed %s", strerrorname_np(-res));
                        return NULL;
                }

                return io_uring_get_sqe(&nmp->ring);
        }

        return sqe;
}


static inline i32 nmp_ring_send(struct nmp_instance *nmp, void *ctx_ptr,
                                struct nmp_buf_send *buf,
                                const u32 len, const union nmp_sa *addr)
{
        assert(len >= NET_PACKET_MIN && len <= NET_PACKET_MAX);

        struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
        if (sqe == NULL)
                return -1;

        log("sending %u (%s)", len, nmp_dbg_packet_types[*buf->data]);

        buf->addr = *addr;
        buf->send_hdr.msg_name = &buf->addr;
        buf->send_hdr.msg_namelen = sizeof(union nmp_sa);
        buf->send_hdr.msg_iov = &buf->iov;
        buf->send_hdr.msg_iovlen = 1;
        buf->iov.iov_base = buf->data;
        buf->iov.iov_len = len;

        io_uring_prep_sendmsg(sqe, nmp->net_udp, &buf->send_hdr, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_sqe_set_data(sqe, ctx_ptr);
        return 0;
}


static inline i32 nmp_ring_recv_net(struct nmp_instance *nmp)
{
        struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
        if (sqe == NULL)
                return -1;

        io_uring_prep_recvmsg_multishot(sqe, nmp->net_udp, &nmp->recv_hdr, 0);
        io_uring_sqe_set_data(sqe, &nmp->net_udp);
        sqe->flags |= IOSQE_BUFFER_SELECT;
        sqe->buf_group = RING_NET_GROUP;

        return 0;
}


static inline i32 nmp_ring_recv_local(struct nmp_instance *nmp)
{
        struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
        if (sqe == NULL)
                return -1;

        io_uring_prep_recv_multishot(sqe, nmp->local_rx, NULL, 0, 0);
        io_uring_sqe_set_data(sqe, &nmp->local_rx);
        sqe->flags |= IOSQE_BUFFER_SELECT;
        sqe->buf_group = RING_LOCAL_GROUP;

        return 0;
}


static inline void nmp_ring_reuse_buf(struct io_uring_buf_ring *ring, void *addr,
                                      const u32 buflen, const u32 bid)
{
        io_uring_buf_ring_add(ring, addr, buflen, bid,
                              io_uring_buf_ring_mask(RING_RECV_BUFS), 0);
        io_uring_buf_ring_advance(ring, 1);
}


#if defined(NMP_DEBUG_TIMERS)

static u32 nmp_ring_timer_update(struct nmp_instance *nmp,
                                 struct nmp_session *ctx, const u32 value)
{
    UNUSED(nmp);
    UNUSED(ctx);
    UNUSED(value);

    log("skipping %u for %xu", value, ctx->session_id);
    return 0;
}


static u32 nmp_ring_timer_set(struct nmp_instance *nmp,
                              struct nmp_session *ctx, const u32 value)
{
    UNUSED(nmp);
    UNUSED(ctx);
    UNUSED(value);

    log("skipping %u for %xu", value, ctx->session_id);
    return 0;
}

#else /* NMP_DEBUG_TIMERS */


static i32 nmp_ring_timer_update(struct nmp_instance *nmp, void *ctx,
                                 struct __kernel_timespec *ts)
{
        log("updating timer %p [%lld:%lld]",
            ctx, ts->tv_sec, ts->tv_nsec / 1000000);

        struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
        if (sqe == NULL)
                return -1;

        io_uring_prep_timeout_update(sqe, ts, (u64) ctx, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);

        return 0;
}


static i32 nmp_ring_timer_set(struct nmp_instance *nmp, void *ctx,
                              struct __kernel_timespec *ts)
{
        log("setting timer for %p [%lld:%lld]",
            ctx, ts->tv_sec, ts->tv_nsec / 1000000);

        struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
        if (sqe == NULL)
                return -1;

        io_uring_prep_timeout(sqe, ts, 0, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_sqe_set_data(sqe, ctx);

        return 0;
}

#endif /* NMP_DEBUG_TIMERS */


static i32 session_new(struct nmp_rq_connect *rq,
                       struct noise_handshake *noise,
                       struct nmp_session **new_ctx)
{
        i32 err = 0;
        u16 xfer_pl = (rq->transport_payload) ?
                      (rq->transport_payload + sizeof(struct msg_header)) :
                      (NMP_PAYLOAD_MAX + sizeof(struct msg_header));
        if (xfer_pl < 496 || xfer_pl > MSG_MAX_PAYLOAD)
                return NMP_ERR_INVAL;

        struct chacha20poly1305_ctx c1 = {0};
        struct chacha20poly1305_ctx c2 = {0};
        struct nmp_session_init *initiation = NULL;
        struct nmp_session *ctx = NULL;

        if (chacha20poly1305_init(&c1, NULL)
            || chacha20poly1305_init(&c2, NULL)) {
                err = NMP_ERR_CRYPTO;
                goto out_fail;
        }

        initiation = mem_alloc(sizeof(struct nmp_session_init));
        ctx = mem_alloc(sizeof(struct nmp_session));
        if (initiation == NULL || ctx == NULL) {
                err = NMP_ERR_MALLOC;
                goto out_fail;
        }


        mem_zero(ctx, sizeof(struct nmp_session));
        mem_zero(initiation, sizeof(struct nmp_session_init));

        const u8 ka_to = rq->keepalive_timeout ? : NMP_KEEPALIVE_TIMEOUT;
        u8 ka_int = rq->keepalive_messages ?
                    (ka_to / rq->keepalive_messages) :
                    (ka_to / NMP_KEEPALIVE_MESSAGES);

        if (ka_int == 0)
                ka_int = (NMP_KEEPALIVE_TIMEOUT / NMP_KEEPALIVE_MESSAGES);

        u8 ka_retries = ka_to / ka_int;
        if (ka_retries == 0)
                ka_retries = NMP_KEEPALIVE_MESSAGES;

        ctx->session_id = rq->id;
        ctx->flags = rq->flags;
        ctx->context_ptr = rq->context_ptr;
        ctx->addr = rq->addr;

        ctx->timer_keepalive = ka_int;
        ctx->timer_retry_table[SESSION_STATUS_NONE] = 0;
        ctx->timer_retry_table[SESSION_STATUS_RESPONSE] = SESSION_RETRY_DATA;
        ctx->timer_retry_table[SESSION_STATUS_CONFIRM] = 1;
        ctx->timer_retry_table[SESSION_STATUS_WINDOW] = SESSION_RETRY_DATA;
        ctx->timer_retry_table[SESSION_STATUS_ESTAB] = ka_retries;
        ctx->timer_retry_table[SESSION_STATUS_ACKWAIT] = SESSION_RETRY_DATA;

        ctx->noise_key_send = c1;
        ctx->noise_key_receive = c2;
        ctx->initiation = initiation;
        initiation->handshake = *noise;

        /*
         * sequence numbers start at zero but msg_sequence_cmp() is a strict '>' so set
         * state counters to 0xffff, exactly one before the u16 wraps around to zero
         */
        ctx->transport.tx_seq = 0xffff;
        ctx->transport.tx_ack = 0xffff;
        ctx->transport.rx_seq = 0xffff;
        ctx->transport.rx_delivered = 0xffff;

        ctx->transport.payload_max = xfer_pl;

        *new_ctx = ctx;
        return 0;

        out_fail:
        {
                chacha20poly1305_free(&c1);
                chacha20poly1305_free(&c2);

                if (initiation)
                        mem_free(initiation);

                if (ctx)
                        mem_free(ctx);

                log_errno();
                *new_ctx = NULL;
                return err;
        }
}


static void session_destroy(struct nmp_session *ctx)
{
        msg_context_wipe(&ctx->transport);
        chacha20poly1305_free(&ctx->noise_key_send);
        chacha20poly1305_free(&ctx->noise_key_receive);

        if (ctx->initiation) {
                noise_state_del(&ctx->initiation->handshake);
                mem_free(ctx->initiation);
        }

        log("%xu", ctx->session_id);
        mem_zero(ctx, sizeof(struct nmp_session));
        mem_free(ctx);
}


/*
 *  remove hash table entry, notify application
 *  but do not remove it immediately, just mark
 *  this session for next timer trigger
 */
static void session_drop(struct nmp_instance *nmp,
                         struct nmp_session *ctx,
                         const enum nmp_status status,
                         const union nmp_cb_status *container)
{
        log("%xu", ctx->session_id);
        if (nmp->status_cb)
                nmp->status_cb(status, container, ctx->context_ptr);

        /*
         * any new network message or local requests related to this
         * context will be simply discarded as there is no hash table
         * entry, then when its timer fires off the context is finally
         * deleted; this prevents potential use-after-free() because timers
         * (timer fd) have context pointers and do not do any lookup
         */
        ht_remove(&nmp->sessions, ctx->session_id);
        ctx->state = SESSION_STATUS_NONE;
}


static inline struct nmp_buf_send *session_buf(struct nmp_session *ctx)
{
        ctx->send_iter += 1;
        return &ctx->send_bufs[ctx->send_iter & (MSG_WINDOW - 1)];
}


static i32 session_transport_send(struct nmp_instance *nmp, struct nmp_session *ctx,
                                  const u8 *payload, const i32 amt, const u8 type)
{
        if (ctx->noise_counter_send == NOISE_NONCE_MAX) {
                /*
                 * noise spec does not allow sending more than
                 * 2^64 - 1 messages for a single handshake
                 */
                session_drop(nmp, ctx, NMP_SESSION_EXPIRED, NULL);
                return 0;
        }

        struct nmp_buf_send *buf = session_buf(ctx);
        buf->transport.type_pad_id = header_init(type, ctx->session_id);
        buf->transport.counter = ctx->noise_counter_send;

        const u32 packet_len = sizeof(struct nmp_transport) + amt + NOISE_AEAD_MAC;
        u8 *packet = buf->data;
        u8 *ciphertext = packet + sizeof(struct nmp_transport);
        u8 *mac = ciphertext + amt;

        if (noise_encrypt(ctx->noise_key_send, ctx->noise_counter_send,
                          &buf->transport, sizeof(struct nmp_transport),
                          payload, amt,
                          ciphertext, mac))
                return NMP_ERR_CRYPTO;

        if (nmp_ring_send(nmp, ctx, buf, packet_len, &ctx->addr))
                return NMP_ERR_IORING;

        ctx->noise_counter_send += 1;
        ctx->stat_tx += packet_len;
        return 0;
}


static i32 session_transport_receive(struct nmp_session *ctx,
                                     u8 *packet, const u32 packet_len,
                                     u8 plaintext[MSG_MAX_PAYLOAD])
{
        const i32 payload_len = (i32) (packet_len
                                       - sizeof(struct nmp_transport) - NOISE_AEAD_MAC);
        if (payload_len < 0 || payload_len > MSG_MAX_PAYLOAD) {
                log("rejecting packet size");
                return -1;
        }

        const struct nmp_transport *header = (const struct nmp_transport *) packet;
        u8 *ciphertext = packet + sizeof(struct nmp_transport);
        u8 *mac = ciphertext + payload_len;
        const u64 counter_remote = header->counter;
        const i32 block_index = noise_counter_validate(ctx->noise_counter_block,
                                                       ctx->noise_counter_receive,
                                                       counter_remote);
        if (block_index < 0) {
                log("counter rejected %xu", header->type_pad_id.session_id);
                return -1;
        }


        if (noise_decrypt(ctx->noise_key_receive, counter_remote,
                          header, sizeof(struct nmp_transport),
                          ciphertext, payload_len,
                          mac, plaintext)) {
                log("decryption failed %xu", header->type_pad_id.session_id);
                return -1;
        }


        /* only after successful decryption */
        if (counter_remote > ctx->noise_counter_receive) {
                i32 i = (i32) (ctx->noise_counter_receive / 32) & 7;

                while (i != block_index) {
                        i += 1;
                        i &= 7;

                        ctx->noise_counter_block[i] = 0;
                }

                ctx->noise_counter_receive = counter_remote;
        }

        ctx->noise_counter_block[block_index] |= (1 << (u32) (counter_remote & 31));
        ctx->stat_rx += packet_len;
        return payload_len;
}


static i32 session_request(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        assert(ctx->state == SESSION_STATUS_NONE);
        assert(ctx->initiation);

        struct nmp_session_init *initiation = ctx->initiation;
        struct nmp_buf_send *buf = &initiation->send_buf;

        initiation->payload.timestamp = time_get();
        if (initiation->payload.timestamp == 0)
                return NMP_ERR_TIME;


        buf->request.header = header_init(NMP_REQUEST, ctx->session_id);
        if (noise_initiator_write(&initiation->handshake,
                                  &buf->request.initiator,
                                  &buf->request, sizeof(struct nmp_header),
                                  (u8 *) &initiation->payload)) {
                log("failed to write initiator");
                return 1;
        }

        if (nmp_ring_send(nmp, ctx, buf,
                          sizeof(struct nmp_request), &ctx->addr))
                return NMP_ERR_IORING;


        ctx->state = SESSION_STATUS_RESPONSE;
        ctx->stat_tx += sizeof(struct nmp_request);
        ctx->kts = kts(SESSION_RETRY_INTERVAL, 0);

        return nmp_ring_timer_set(nmp, ctx, &ctx->kts);
}


static u32 session_response(struct nmp_instance *nmp,
                            struct nmp_session *ctx,
                            struct nmp_init_payload *payload)
{
        assert(ctx->state == SESSION_STATUS_NONE);
        assert(ctx->initiation);

        struct nmp_session_init *initiation = ctx->initiation;
        struct nmp_buf_send *buf = &initiation->send_buf;

        buf->response.header = header_init(NMP_RESPONSE, ctx->session_id);
        if (noise_responder_write(&initiation->handshake,
                                  &buf->response.responder,
                                  &buf->response.header, sizeof(struct nmp_header),
                                  (u8 *) payload))
                return 1;

        if (nmp_ring_send(nmp, ctx, &initiation->send_buf,
                          sizeof(struct nmp_response), &ctx->addr))
                return 1;


        ctx->state = SESSION_STATUS_CONFIRM;
        ctx->stat_tx += sizeof(struct nmp_response);
        ctx->response_retries = 0;
        ctx->kts = kts(ctx->timer_keepalive, 0);

        return nmp_ring_timer_set(nmp, ctx, &ctx->kts);
}


static i32 session_data(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        /* NONE, RESPONSE, CONFIRM, WINDOW */
        if (ctx->state < SESSION_STATUS_ESTAB) {
                log("rejecting state %s", nmp_dbg_session_status[ctx->state]);
                return 0;
        }

        u8 payload[MSG_MAX_PAYLOAD];
        i32 amt;
        i32 err = 0;

        while ((amt = msg_assemble(&ctx->transport, payload))) {
                if (amt == -1) {
                        log("marking full window");
                        ctx->state = SESSION_STATUS_WINDOW;
                        return 0;
                }

                /*
                 * checking for zero here because if flag for full window
                 * is set then flag for ack wait is guaranteed to be set too
                 * but if its ack wait only, this condition is still relevant
                 */
                if (ctx->state == SESSION_STATUS_ESTAB) {
                        log("idle send retries %u", ctx->response_retries);

                        ctx->state = SESSION_STATUS_ACKWAIT;
                        ctx->kts = rto_table[ctx->timer_retries];

                        if ((err = nmp_ring_timer_update(nmp, ctx, &ctx->kts)))
                                return NMP_ERR_IORING;
                }

                if ((err = session_transport_send(nmp, ctx,
                                                  payload, amt, NMP_DATA)))
                        return err;
        }

        return 0;
}


static i32 session_data_retry(struct nmp_instance *nmp,
                              struct nmp_session *ctx)
{
        u8 payload[MSG_MAX_PAYLOAD];

        const u32 payload_len = msg_assemble_retry(&ctx->transport, payload);
        if (payload_len)
                return session_transport_send(nmp, ctx, payload,
                                              (i32) payload_len, NMP_DATA);

        return 0;
}


static u32 session_data_noack(struct nmp_instance *nmp,
                              struct nmp_session *ctx,
                              const struct msg_header *message, const u16 len)
{

        /* NONE, RESPONDER, CONFIRM mean that this context is not ready yet */
        if (ctx->state < SESSION_STATUS_WINDOW) {
                log("skipping noack (%s)", nmp_dbg_session_status[ctx->state]);
                return 0;
        }

        return session_transport_send(nmp, ctx, (const u8 *) message,
                                      len, NMP_DATA);
}


static i32 session_ack(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        if (ctx->response_retries > SESSION_RETRY_RESPONSE) {
                log("maximum response retries");
                return 0;
        }

        struct msg_ack ack;
        msg_ack_assemble(&ctx->transport, &ack);

        ctx->response_retries += 1;
        return session_transport_send(nmp, ctx, (u8 *) &ack,
                                      sizeof(struct msg_ack), NMP_ACK);
}


static i32 session_keepalive(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        assert(ctx->state == SESSION_STATUS_ESTAB);
        return session_transport_send(nmp, ctx, NULL, 0, NMP_DATA);
}


///////////////////////////////
///     local events        ///
///////////////////////////////


/*
 *  remember: message is preformed in nmp_send_noack()
 *  so we have a payload that is ready for sending
 */
static i32 local_data_noack(struct nmp_instance *nmp,
                            struct nmp_session *ctx,
                            struct nmp_rq *request)
{
        const u32 res = session_data_noack(nmp, ctx, request->entry_arg,
                                           request->len);
        mem_free(request->entry_arg);
        return (i32) res;
}


static i32 local_data(struct nmp_instance *nmp,
                      struct nmp_session *ctx,
                      struct nmp_rq *request)
{
        if (ctx == NULL)
                goto out_free;

        if (request->len > ctx->transport.payload_max)
                goto out_free;

        if (request->msg_flags & NMP_F_MSG_NOACK)
                return local_data_noack(nmp, ctx, request);

        u8 msg_flags = 0;
        if (request->msg_flags & NMP_F_MSG_NOALLOC)
                msg_flags |= MSG_F_NOALLOC;

        if (msg_queue(&ctx->transport,
                      request->entry_arg, request->len,
                      msg_flags, request->user_data)) {
                if (nmp->status_cb) {
                        const union nmp_cb_status failed =
                                {.user_data = request->user_data};

                        nmp->status_cb(NMP_ERR_QUEUE, &failed, ctx->context_ptr);
                }

                goto out_free;
        }

        /* not free()ing this request, that is done when message is acked */
        return session_data(nmp, ctx);

        out_free:
        {
                if ((request->msg_flags & NMP_F_MSG_NOALLOC) == 0)
                        mem_free(request->entry_arg);

                return 0;
        }
}


static i32 local_drop(struct nmp_instance *nmp,
                      struct nmp_session *ctx,
                      struct nmp_rq *request)
{
        UNUSED(request);
        if (ctx == NULL)
                return 0;

        /*
         * same as session_drop(), except here we are not
         * doing status callback as it does not make sense
         */
        ctx->state = SESSION_STATUS_NONE;
        ht_remove(&nmp->sessions, ctx->session_id);
        return 0;
}


static i32 local_connect(struct nmp_instance *nmp,
                         struct nmp_session *ctx_empty,
                         struct nmp_rq *request)
{
        UNUSED(ctx_empty);
        struct nmp_session *ctx = request->entry_arg;

        if (nmp->sessions.items > NMP_SESSIONS_MAX) {
                log("rejecting connection request: MAXCONN");

                const union nmp_cb_status cancelled =
                        {.session_id = request->session_id};
                if (nmp->status_cb)
                        nmp->status_cb(NMP_ERR_MAXCONN, &cancelled, ctx->context_ptr);

                session_destroy(ctx);
                return 0;
        }

        if (noise_state_init(&ctx->initiation->handshake))
                return -1;

        if (ht_insert(&nmp->sessions,
                      ctx->session_id, ctx))
                return -1;

        if (session_request(nmp, ctx))
                return -1;

        ctx->state = SESSION_STATUS_RESPONSE;
        return 0;
}


i32 local_process_rq(struct nmp_instance *nmp,
                     struct nmp_rq *request)
{
        struct nmp_session *ctx = NULL;
        const enum nmp_rq_ops type = request->op;

        /* drop, data */
        if (type < NMP_OP_CONNECT)
                ctx = ht_lookup(&nmp->sessions, request->session_id);

        switch (type) {
        case NMP_OP_SEND:
                return local_data(nmp, ctx, request);
        case NMP_OP_DROP:
                return local_drop(nmp, ctx, request);
        case NMP_OP_CONNECT:
                return local_connect(nmp, ctx, request);
        case NMP_OP_TERMINATE:
                return NMP_STATUS_LAST;

        default:
                return -1;
        }
}


static i32 event_local(struct nmp_instance *nmp,
                       const struct io_uring_cqe *cqe,
                       struct nmp_session **ctx_empty)
{
        UNUSED(ctx_empty);

        const u32 bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        struct nmp_pbuf_local *queue = nmp->recv_local.base + bid;
        const u32 queue_len = (cqe->res / sizeof(struct nmp_rq));
        i32 result = 0;

        if ((cqe->flags & IORING_CQE_F_MORE) == 0) {
                log("updating local multishot receive");
                if (nmp_ring_recv_local(nmp))
                        return NMP_ERR_IORING;

                goto out;
        }


        for (u32 i = 0; i < queue_len; i++) {
                result = local_process_rq(nmp, &queue->op[i]);
                if (result)
                        goto out;
        }

        out:
        {
                nmp_ring_reuse_buf(nmp->recv_local.ring, queue,
                                   sizeof(struct nmp_pbuf_local), bid);
                return result;
        }
}


///////////////////////////////
///     timer events        ///
///////////////////////////////


static i32 event_timer(struct nmp_instance *nmp,
                       struct nmp_session *ctx)
{
        i32 err = 0;

        /* session has been marked for deletion */
        if (ctx->state == SESSION_STATUS_NONE) {
                /*
                 * this is safe to do here: when errors occur during processing of any
                 * network or local events the state is simply marked with SESSION_STATUS_NONE,
                 * so it does not accept any remaining events from sockets (/queues)
                 */
                session_destroy(ctx);
                return 0;
        }


        ctx->timer_retries += 1;
        log("state %s try %u/%u", nmp_dbg_session_status[ctx->state],
            ctx->timer_retries, ctx->timer_retry_table[ctx->state]);

        if (ctx->timer_retries >= ctx->timer_retry_table[ctx->state]) {
                const union nmp_cb_status latest =
                        {.user_data = msg_latest_acked(&ctx->transport)};

                session_drop(nmp, ctx, NMP_SESSION_DISCONNECTED, &latest);
                session_destroy(ctx);
                return 0;
        }

        switch ((enum session_status) ctx->state) {
        case SESSION_STATUS_WINDOW:
        case SESSION_STATUS_ACKWAIT:
                ctx->kts = rto_table[ctx->timer_retries];
                if ((err = session_data_retry(nmp, ctx)))
                        return err;

                break;

        case SESSION_STATUS_ESTAB:
                if ((err = session_keepalive(nmp, ctx)))
                        return err;

                break;

        case SESSION_STATUS_RESPONSE:
                assert(ctx->initiation);

                if (nmp_ring_send(nmp, ctx, &ctx->initiation->send_buf,
                                  sizeof(struct nmp_request), &ctx->addr))
                        return NMP_ERR_IORING;

                ctx->stat_tx += sizeof(struct nmp_request);
                break;

        case SESSION_STATUS_CONFIRM:
                /*
                 * this state means we accepted valid initiator, sent a response
                 * but initiator did not send any data packets afterwards (or our
                 * response(s) did not get through). drop
                 */
                assert(ctx->initiation);

                session_drop(nmp, ctx, NMP_SESSION_DISCONNECTED, NULL);
                session_destroy(ctx);
                return 0;

        default:
                return NMP_ERR_IORING;
        }


        if (nmp->stats_cb)
                nmp->stats_cb(ctx->stat_rx, ctx->stat_tx, ctx->context_ptr);

        /* reset to a previous value */
        return nmp_ring_timer_set(nmp, ctx, &ctx->kts);
}


///////////////////////////////
///     network events      ///
///////////////////////////////


static i32 net_data_first(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        assert(ctx->initiation);

        ctx->state = SESSION_STATUS_ESTAB;
        ctx->response_retries = 0;
        noise_state_del(&ctx->initiation->handshake);

        mem_zero(ctx->initiation, sizeof(struct nmp_session_init));
        mem_free(ctx->initiation);
        ctx->initiation = NULL;

        if (nmp->status_cb)
                nmp->status_cb(NMP_SESSION_INCOMING, NULL, ctx->context_ptr);

        /* there could be a custom interval set, update needed */
        ctx->kts = kts(ctx->timer_keepalive, 0);
        return nmp_ring_timer_update(nmp, ctx, &ctx->kts);
}


static i32 net_data(struct nmp_instance *nmp, struct nmp_session *ctx,
                    const u8 *payload, const u32 payload_len)
{
        i32 err = 0;
        if (ctx->state == SESSION_STATUS_CONFIRM
            && (err = net_data_first(nmp, ctx)))
                return err;

        if (payload_len == 0) {
                ctx->timer_retries = 0;
                return 0;
        }

        const i32 new_messages = msg_read(&nmp->transport_callbacks,
                                          &ctx->transport,
                                          payload, payload_len);
        switch (new_messages) {
        case -1:
                /*
                 * mark this session with critical error but do not return -1 as this
                 * is not critical for entire library, just drop this connection
                 */
                session_drop(nmp, ctx, NMP_ERR_PROTOCOL, NULL);
                return 0;

        case 0:
                /*
                 * this is a fresh and valid packet which contains payload, no new messages
                 * for us though; no need to buffer these, just respond immediately
                 */
                return session_ack(nmp, ctx);

        case (MSG_WINDOW + 1):
                /* successful noack message */
                return 0;

        default:
                return new_messages;
        }
}


static u32 net_ack(struct nmp_instance *nmp, struct nmp_session *ctx,
                   const u8 *payload, const u32 payload_len)
{
        if (payload_len != sizeof(struct msg_ack)) {
                /* this ack did not fail authentication, but we cant read it */
                log("payload != sizeof(ack)");

                session_drop(nmp, ctx, NMP_ERR_PROTOCOL, NULL);
                return 1;
        }

        /* we only want WINDOW, ESTAB & ACKWAIT here */
        if (ctx->state < SESSION_STATUS_WINDOW) {
                log("rejecting state %s", nmp_dbg_session_status[ctx->state]);
                return 0;
        }

        const struct msg_ack *ack = (struct msg_ack *) payload;
        const i32 acks = msg_ack_read(&ctx->transport, ack);
        if (acks < 0) {
                session_drop(nmp, ctx, NMP_ERR_PROTOCOL, NULL);
                return 0;
        }

        return (u32) acks;
}


static i32 net_request_existing(struct nmp_instance *nmp,
                                struct nmp_session *ctx,
                                const struct nmp_request *request,
                                const union nmp_sa *addr)
{
        if (ctx->flags & NMP_F_ADDR_VERIFY
            && mem_cmp(&addr->sa, &ctx->addr.sa, sizeof(union nmp_sa)) != 0) {
                log("rejecting response: NMP_F_ADDR_VERIFY");
                return 0;
        }

        if (ctx->initiation && ctx->response_retries < SESSION_RETRY_RESPONSE) {
                /* comparing to a stored copy is a cheap way to authenticate here */
                if (mem_cmp(&ctx->initiation->request_buf,
                            request, sizeof(struct nmp_request)) != 0) {
                        log("failed to auth request for existing session");
                        return 0;
                }

                if (nmp_ring_send(nmp, ctx, &ctx->initiation->send_buf,
                                  sizeof(struct nmp_response), &ctx->addr))
                        return NMP_ERR_IORING;

                log("resending response for existing session %u/%u",
                    ctx->response_retries, SESSION_RETRY_RESPONSE);

                ctx->response_retries += 1;
                return 0;
        }

        log("dropping request for %xu", ctx->session_id);
        return 0;
}


static i32 net_request_accept(struct nmp_instance *nmp,
                              struct noise_handshake *handshake,
                              struct nmp_rq_connect *rq,
                              const struct nmp_request *request_save)
{
        struct nmp_session *ctx;
        struct nmp_init_payload response_payload = {0};
        mem_copy(response_payload.data,
                 rq->init_payload, NMP_INITIATION_PAYLOAD);

        session_new(rq, handshake, &ctx);
        if (ctx == NULL)
                return -1;

        if (session_response(nmp, ctx, &response_payload)) {
                log("failed to generate response");
                return -1;
        }

        if (ht_insert(&nmp->sessions, rq->id, ctx))
                return -1;

        struct nmp_session_init *initiation = ctx->initiation;
        mem_copy(&initiation->request_buf,
                 request_save, sizeof(struct nmp_request));

        if (noise_split(&initiation->handshake,
                        &ctx->noise_key_receive, &ctx->noise_key_send))
                return -1;

        ctx->noise_counter_receive = 0;
        ctx->noise_counter_send = 0;
        ctx->stat_rx += sizeof(struct nmp_request);
        return 0;
}


static i32 net_request_respond(struct nmp_instance *nmp,
                               struct noise_handshake *handshake,
                               struct nmp_rq_connect *rq)
{
        struct nmp_init_payload response_payload = {0};
        mem_copy(response_payload.data,
                 rq->init_payload, NMP_INITIATION_PAYLOAD);

        nmp->send_iter += 1;
        struct nmp_buf_send *buf = &nmp->send_bufs[nmp->send_iter & (RING_BATCH - 1)];

        buf->response.header = header_init(NMP_RESPONSE, rq->id);
        mem_copy(response_payload.data, rq->init_payload, NMP_INITIATION_PAYLOAD);

        if (noise_responder_write(handshake, &buf->response.responder,
                                  &buf->response.header, sizeof(struct nmp_header),
                                  &response_payload))
                return -1;

        return nmp_ring_send(nmp, nmp, /* ! */
                             buf, sizeof(struct nmp_response), &rq->addr) ? -1 : 0;
}


static i32 net_request(struct nmp_instance *nmp,
                       const u32 id, const union nmp_sa *addr,
                       struct nmp_request *request, const u32 len)
{
        if (nmp->request_cb == NULL || nmp->sessions.items >= HT_SIZE) {
                log("cannot accept request");
                return 0;
        }

        if (len != sizeof(struct nmp_request)) {
                log("rejecting request size %u (%xu)", len, id);
                return 0;
        }

        struct nmp_session *ctx = ht_lookup(&nmp->sessions, id);
        if (ctx)
                return net_request_existing(nmp, ctx, request, addr);

        struct noise_handshake handshake = nmp->noise_precomp;
        struct nmp_rq_connect request_cb = {0};
        struct nmp_init_payload request_payload = {0};

        if (noise_initiator_read(&handshake, &request->initiator,
                                 &request->header, sizeof(struct nmp_header),
                                 (u8 *) &request_payload)) {
                log("failed to read request for %xu", id);
                return 0;
        }

        const u64 timestamp = time_get();
        if (timestamp == 0)
                return -1;

        if (timestamp + 500 > request_payload.timestamp + SESSION_REQUEST_TTL) {
                log("request expired %xu", id);
                return 0;
        }

        request_cb.addr = *addr;
        request_cb.id = id;
        mem_copy(request_cb.pubkey, handshake.rs, NOISE_DHLEN);

        /* ask application what we do next */
        switch (nmp->request_cb(&request_cb, request_payload.data,
                                nmp->request_ctx)) {
        case NMP_CMD_ACCEPT:
                return net_request_accept(nmp, &handshake,
                                          &request_cb, request);

        case NMP_CMD_RESPOND:
                return net_request_respond(nmp, &handshake, &request_cb);

        case NMP_CMD_DROP:
        default:
                log("application dropped request %xu", id);
                return 0;
        }
}


static u32 net_response_accept(struct nmp_instance *nmp,
                               struct nmp_session *ctx)
{
        struct nmp_session_init *initiation = ctx->initiation;

        ctx->noise_counter_send = 0;
        ctx->noise_counter_receive = 0;
        if (noise_split(&initiation->handshake,
                        &ctx->noise_key_send, &ctx->noise_key_receive))
                return 1;

        noise_state_del(&initiation->handshake);

        mem_zero(ctx->initiation, sizeof(struct nmp_session_init));
        mem_free(ctx->initiation);
        ctx->initiation = NULL;
        ctx->stat_rx += sizeof(struct nmp_response);

        ctx->state = SESSION_STATUS_ESTAB;
        if (session_data(nmp, ctx))
                return 1;

        if (ctx->state == SESSION_STATUS_ACKWAIT)
                return 0;

        /* no data => keepalive */
        if (session_keepalive(nmp, ctx))
                return 1;

        ctx->kts = kts(ctx->timer_keepalive, 0);
        return nmp_ring_timer_update(nmp, ctx, &ctx->kts);
}


static u32 net_response(struct nmp_instance *nmp,
                        const u32 session_id, const union nmp_sa *addr,
                        struct nmp_response *response, const u32 amt)
{
        if (nmp->status_cb == NULL) {
                log("callback not set, skipping response.");
                return 0;
        }

        if (amt != sizeof(struct nmp_response)) {
                log("rejecting net_buf.amt != sizeof(nmp_response)");
                return 0;
        }

        struct nmp_session *ctx = ht_lookup(&nmp->sessions, session_id);
        if (ctx == NULL) {
                log("rejecting response: no context");
                return 0;
        }

        if (ctx->state != SESSION_STATUS_RESPONSE) {
                /* this also protects against duplicate responders */
                log("state != SESSION_STATUS_RESPONSE");
                return 0;
        }

        if (ctx->flags & NMP_F_ADDR_VERIFY) {
                if (mem_cmp(&ctx->addr.sa, &addr->sa, sizeof(union nmp_sa)) != 0) {
                        log("rejecting addr != recvfrom().addr");
                        return 0;
                }
        }

        struct nmp_init_payload reply_pl = {0};
        struct nmp_session_init *initiation = ctx->initiation;

        if (noise_responder_read(&initiation->handshake,
                                 &response->responder,
                                 &response->header, sizeof(struct nmp_header),
                                 (u8 *) &reply_pl)) {
                log("failed to read response for %xu", ctx->session_id);
                return 0;
        }

        const i32 res = nmp->status_cb(NMP_SESSION_RESPONSE,
                                       (const union nmp_cb_status *) reply_pl.data,
                                       ctx->context_ptr);
        switch ((enum nmp_status) res) {
        case NMP_CMD_ACCEPT:
                return net_response_accept(nmp, ctx);

        case NMP_CMD_DROP:
                /* no point having this session anymore */
                ht_remove(&nmp->sessions, ctx->session_id);
                ctx->state = SESSION_STATUS_NONE;
                return 0;

        default:
                log("application did not accept response %xu", ctx->session_id);
                return 0;
        }
}


static struct nmp_session *net_collect(struct nmp_instance *nmp,
                                       struct nmp_header *packet, const u32 packet_len,
                                       const union nmp_sa *addr)
{
        const struct nmp_header header = *packet;
        if (header.type & 0xfc /* 0b11111100 */
            || (header.pad[0] | header.pad[1] | header.pad[2])) {
                log("rejecting: header format");
                return NULL;
        }

        if (header.session_id == 0) {
                log("rejecting reserved id value");
                return NULL;
        }

        if (header.type < NMP_DATA) {
                switch (header.type) {
                case NMP_REQUEST:
                        net_request(nmp, header.session_id, addr,
                                    (struct nmp_request *) packet, packet_len);
                        return NULL;

                case NMP_RESPONSE:
                        net_response(nmp, header.session_id, addr,
                                     (struct nmp_response *) packet, packet_len);
                        return NULL;
                }
        }

        struct nmp_session *ctx = ht_lookup(&nmp->sessions, header.session_id);
        if (ctx == NULL) {
                log("rejecting %s for %xu: no context",
                    nmp_dbg_packet_types[header.type], header.session_id);
                return NULL;
        }

        if (ctx->flags & NMP_F_ADDR_VERIFY) {
                if (mem_cmp(&ctx->addr.sa, &addr->sa, sizeof(union nmp_sa)) != 0) {
                        log("rejecting addr != recvfrom().addr");
                        return NULL;
                }
        }

        if (packet_len % 16) {
                log("rejecting amt %% 16");
                return NULL;
        }

        u8 payload[MSG_MAX_PAYLOAD];
        const i32 payload_len = session_transport_receive(ctx, (u8 *) packet, packet_len,
                                                          payload);
        if (payload_len < 0)
                return NULL;


        switch (header.type) {
        case NMP_DATA:
                if (net_data(nmp, ctx, payload, payload_len) <= 0)
                        return NULL;

                ctx->events |= SESSION_EVENT_DATA;
                break;

        case NMP_ACK:
                if (!net_ack(nmp, ctx, payload, payload_len))
                        return NULL;

                ctx->events |= SESSION_EVENT_ACK;
                break;
        }

        /* if there are new events && not queued yet */
        if (ctx->events && !(ctx->events & SESSION_EVENT_QUEUED)) {
                ctx->events |= SESSION_EVENT_QUEUED;
                return ctx;
        }

        return NULL;
}


static i32 event_net(struct nmp_instance *nmp,
                     const struct io_uring_cqe *cqe,
                     struct nmp_session **ctx_ptr)
{
        const u32 bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        struct nmp_pbuf_net *buf = nmp->recv_net.base + bid;

        if ((cqe->flags & IORING_CQE_F_MORE) == 0) {
                log("updating multishot recvmsg");
                return nmp_ring_recv_net(nmp);
        }

        struct io_uring_recvmsg_out *msg_out = io_uring_recvmsg_validate(
                buf, cqe->res, &nmp->recv_hdr);
        if (msg_out == NULL) {
                log("failed to validate recvmsg");
                goto out_reuse;
        }

        if (msg_out->namelen > sizeof(union nmp_sa)) {
                log("rejecting namelen");
                goto out_reuse;
        }

        struct nmp_header *packet = io_uring_recvmsg_payload(msg_out, &nmp->recv_hdr);
        const u32 packet_len = io_uring_recvmsg_payload_length(
                msg_out, cqe->res, &nmp->recv_hdr);

        log("received %u to buf %u (%s)", packet_len, bid,
            packet->type <= NMP_ACK ? nmp_dbg_packet_types[packet->type] : "unknown");

        if (packet_len >= NET_PACKET_MIN && packet_len <= NET_PACKET_MAX) {
                *ctx_ptr = net_collect(nmp, packet, packet_len,
                                       io_uring_recvmsg_name(msg_out));
        }


        out_reuse:
        {
                nmp_ring_reuse_buf(nmp->recv_net.ring, buf,
                                   sizeof(struct nmp_pbuf_net), bid);
                return 0;
        }
}



///////////////////////////
///     public api      ///
///////////////////////////


static i32 nmp_teardown(struct nmp_instance *nmp)
{
        ht_teardown(&nmp->sessions, (void *) session_destroy);

        if (nmp->recv_net.ring
            && munmap(nmp->recv_net.ring, nmp->recv_net.size))
                return NMP_ERR_UNMAP;

        if (nmp->recv_local.ring
            && munmap(nmp->recv_local.ring, nmp->recv_local.size))
                return NMP_ERR_UNMAP;

        if (nmp->ring.enter_ring_fd != -1)
                io_uring_queue_exit(&nmp->ring);

        blake2b_free(&nmp->hash);
        blake2b_hmac_free(&nmp->hmac);
        chacha20poly1305_free(&nmp->cipher);

        const i32 descriptors[] = {
                nmp->net_udp,
                nmp->local_rx,
                nmp->local_tx,
        };

        for (u32 i = 0; i < sizeof(descriptors) / sizeof(u32); i++) {
                if (descriptors[i] == -1)
                        continue;

                if (close(descriptors[i])) {
                        log("failed to close() at index %xu", i);
                        return NMP_ERR_CLOSE;
                }
        }

        mem_zero(nmp, sizeof(struct nmp_instance));
        mem_free(nmp);

        return 0;
}


static i32 new_base(struct nmp_instance *nmp, struct nmp_conf *conf)
{
        const sa_family_t sa_family = conf->addr.sa.sa_family ? : AF_INET;
        if (sa_family != AF_INET && sa_family != AF_INET6) {
                log("sa_family");
                return NMP_ERR_INVAL;
        }

        nmp->sa_family = sa_family;
        nmp->recv_hdr.msg_namelen = sizeof(struct sockaddr_storage);

        nmp->request_ctx = conf->request_ctx;
        nmp->request_cb = conf->request_cb;
        nmp->status_cb = conf->status_cb;
        nmp->stats_cb = conf->stats_cb;

        nmp->transport_callbacks.data = conf->data_cb;
        nmp->transport_callbacks.data_noack = conf->data_noack_cb;
        nmp->transport_callbacks.ack = conf->ack_cb;

        u8 ht_key[SIPHASH_KEY];
        if (rnd_get(ht_key, SIPHASH_KEY))
                return NMP_ERR_RND;

        return (ht_init(&nmp->sessions, ht_key)) ? NMP_ERR_CRYPTO : 0;
}


static i32 new_ring(struct nmp_instance *nmp)
{
        struct io_uring_params params = {0};
        params.cq_entries = RING_CQ;
        params.flags = 0
                       | IORING_SETUP_SUBMIT_ALL
                       | IORING_SETUP_COOP_TASKRUN
                       | IORING_SETUP_CQSIZE;

        i32 res = io_uring_queue_init_params(
                RING_SQ, &nmp->ring, &params);
        if (res) {
                errno = -res;
                return NMP_ERR_IORING;
        }

        return 0;
}


static i32 new_ring_pbufs_net(struct io_uring *ring,
                              struct nmp_recv_net *buffers)
{
        buffers->size = (sizeof(struct io_uring_buf) + sizeof(struct nmp_pbuf_net))
                        * RING_RECV_BUFS;
        buffers->ring = mmap(NULL, buffers->size,
                             PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE,
                             0, 0);
        if (buffers->ring == MAP_FAILED)
                return NMP_ERR_MMAP;

        io_uring_buf_ring_init(buffers->ring);
        struct io_uring_buf_reg reg =
                {
                        .ring_addr = (u64) buffers->ring,
                        .ring_entries = RING_RECV_BUFS,
                        .bgid = RING_NET_GROUP,
                };

        if (io_uring_register_buf_ring(ring, &reg, 0))
                return NMP_ERR_IORING;

        u8 *ptr = (u8 *) buffers->ring + (sizeof(struct io_uring_buf) * RING_RECV_BUFS);
        buffers->base = (struct nmp_pbuf_net *) ptr;

        for (i32 i = 0; i < RING_RECV_BUFS; i++) {
                io_uring_buf_ring_add(buffers->ring, &buffers->base[i],
                                      sizeof(struct nmp_pbuf_net), i,
                                      io_uring_buf_ring_mask(RING_RECV_BUFS), i);
        }

        io_uring_buf_ring_advance(buffers->ring, RING_RECV_BUFS);
        return 0;
}


static i32 new_ring_pbufs_local(struct io_uring *ring,
                                struct nmp_recv_local *buffers)
{
        buffers->size = (sizeof(struct io_uring_buf) + sizeof(struct nmp_pbuf_local))
                        * RING_RECV_BUFS;
        buffers->ring = mmap(NULL, buffers->size,
                             PROT_READ | PROT_WRITE,
                             MAP_ANONYMOUS | MAP_PRIVATE,
                             0, 0);
        if (buffers->ring == MAP_FAILED)
                return NMP_ERR_MMAP;

        io_uring_buf_ring_init(buffers->ring);
        struct io_uring_buf_reg reg =
                {
                        .ring_addr = (u64) buffers->ring,
                        .ring_entries = RING_RECV_BUFS,
                        .bgid = RING_LOCAL_GROUP,
                };

        if (io_uring_register_buf_ring(ring, &reg, 0))
                return NMP_ERR_IORING;

        u8 *ptr = (u8 *) buffers->ring + (sizeof(struct io_uring_buf) * RING_RECV_BUFS);
        buffers->base = (struct nmp_pbuf_local *) ptr;

        for (i32 i = 0; i < RING_RECV_BUFS; i++) {
                io_uring_buf_ring_add(buffers->ring, &buffers->base[i],
                                      sizeof(struct nmp_pbuf_local), i,
                                      io_uring_buf_ring_mask(RING_RECV_BUFS), i);
        }

        io_uring_buf_ring_advance(buffers->ring, RING_RECV_BUFS);
        return 0;
}


static i32 new_net(struct nmp_instance *nmp, struct nmp_conf *conf)
{
        const sa_family_t sa_fam = conf->addr.sa.sa_family;
        if (sa_fam != AF_INET && sa_fam != AF_INET6)
                return NMP_ERR_INVAL;

        nmp->net_udp = socket(sa_fam, SOCK_DGRAM, IPPROTO_IP);
        if (nmp->net_udp == -1)
                return NMP_ERR_SOCKET;

        if (bind(nmp->net_udp,
                 &conf->addr.sa, sizeof(union nmp_sa)) == -1)
                return NMP_ERR_BIND;

        socklen_t nmp_sa_len = sizeof(union nmp_sa);
        if (getsockname(nmp->net_udp,
                        &conf->addr.sa, &nmp_sa_len) == -1)
                return NMP_ERR_GETSOCKNAME;

        return new_ring_pbufs_net(&nmp->ring, &nmp->recv_net);
}


static i32 new_local(struct nmp_instance *nmp)
{
        i32 socpair[2] = {0};
        if (socketpair(AF_UNIX, SOCK_DGRAM,
                       IPPROTO_IP, socpair) == -1)
                return NMP_ERR_SOCKPAIR;

        nmp->local_rx = socpair[0];
        nmp->local_tx = socpair[1];

        return new_ring_pbufs_local(&nmp->ring, &nmp->recv_local);
}


static i32 new_crypto(struct nmp_instance *nmp, struct nmp_conf *conf)
{
        if (rnd_reset_pool(&nmp->rnd))
                return NMP_ERR_RND;

        if (blake2b_init(&nmp->hash))
                return NMP_ERR_CRYPTO;

        if (blake2b_hmac_init(&nmp->hmac))
                return NMP_ERR_CRYPTO;

        if (chacha20poly1305_init(&nmp->cipher, NULL))
                return NMP_ERR_CRYPTO;

        if (noise_keypair_initialize(&nmp->static_keys, conf->key))
                return NMP_ERR_CRYPTO;


        nmp->noise_empty.rnd = &nmp->rnd;
        nmp->noise_empty.hmac = nmp->hmac;
        nmp->noise_empty.hash = nmp->hash;
        nmp->noise_empty.aead = nmp->cipher;
        nmp->noise_empty.s = &nmp->static_keys;

        mem_copy(nmp->noise_empty.symmetric_h,
                 noise_protocol_name, NOISE_HASHLEN);
        mem_copy(nmp->noise_empty.symmetric_ck,
                 noise_protocol_name, NOISE_HASHLEN);

        nmp->noise_precomp = nmp->noise_empty;
        mem_copy(nmp->noise_precomp.rs,
                 nmp->static_keys.pub_raw, NOISE_DHLEN);

        if (noise_state_init(&nmp->noise_precomp))
                return NMP_ERR_CRYPTO;


        mem_copy(conf->pubkey, nmp->static_keys.pub_raw, NOISE_DHLEN);
        return 0;
}


struct nmp_instance *nmp_new(struct nmp_conf *conf)
{
        i32 err = 0;
        if (conf == NULL)
                return NULL;

        nmp_t *tmp = mem_alloc(sizeof(struct nmp_instance));
        if (tmp == NULL) {
                conf->err = NMP_ERR_MALLOC;
                return NULL;
        }

        /* currently no options */
        UNUSED(conf->options);
        UNUSED(tmp->options);

        /*
         *  temporarily set descriptor values so that destructor can
         *  figure out which ones to close in case we have to call it
         */
        mem_zero(tmp, sizeof(struct nmp_instance));
        tmp->ring.enter_ring_fd = -1;
        tmp->local_tx = -1;
        tmp->local_rx = -1;
        tmp->net_udp = -1;


        if ((err = new_base(tmp, conf)))
                goto out_fail;

        if ((err = new_crypto(tmp, conf)))
                goto out_fail;

        if ((err = new_ring(tmp)))
                goto out_fail;

        if ((err = new_local(tmp)))
                goto out_fail;

        if ((err = new_net(tmp, conf)))
                goto out_fail;


        if ((err = nmp_ring_recv_net(tmp)))
                goto out_fail;

        if ((err = nmp_ring_recv_local(tmp)))
                goto out_fail;


        conf->err = 0;
        return tmp;
        out_fail:
        {
                log_errno();
                nmp_teardown(tmp);
                conf->err = err;
                return NULL;
        }
}


static i32 submit_connect(struct nmp_instance *nmp, struct nmp_rq *rq)
{
        UNUSED(nmp);
        struct nmp_session *session;
        struct nmp_rq_connect *connect = rq->entry_arg;
        i32 err = 0;

        if (connect->addr.sa.sa_family != nmp->sa_family)
                return NMP_ERR_INVAL;

        if ((connect->id = rnd_get32()) == 0)
                return NMP_ERR_RND;

        if ((err = session_new(connect,
                               &nmp->noise_empty, &session)))
                return err;

        mem_copy(session->initiation->handshake.rs,
                 connect->pubkey, NMP_KEYLEN);

        mem_copy(session->initiation->payload.data,
                 connect->init_payload, NMP_INITIATION_PAYLOAD);

        rq->session_id = connect->id;
        rq->entry_arg = session;
        return 0;
}


static u32 submit_validate_send(const struct nmp_rq *send)
{
        if (send->session_id == 0)
                return 1;

        if (send->len == 0)
                return 1;

        if (send->entry_arg == NULL)
                return 1;

        return 0;
}


static i32 submit_send_noack(struct nmp_instance *nmp, struct nmp_rq *rq)
{
        UNUSED(nmp);
        if (submit_validate_send(rq))
                return NMP_ERR_INVAL;

        struct msg_header *buf = mem_alloc(MSG_MAX_PAYLOAD);
        if (buf == NULL)
                return NMP_ERR_MALLOC;

        rq->len = msg_assemble_noack(buf, rq->entry_arg, rq->len);
        rq->entry_arg = buf;

        return 0;
}


static i32 submit_send(struct nmp_instance *nmp, struct nmp_rq *rq)
{
        UNUSED(nmp);
        if (submit_validate_send(rq))
                return NMP_ERR_INVAL;

        if (rq->msg_flags & NMP_F_MSG_NOACK)
                return submit_send_noack(nmp, rq);

        if ((rq->msg_flags & NMP_F_MSG_NOALLOC) == 0) {
                u8 *buf = mem_alloc(MSG_MAX_PAYLOAD);
                if (buf == NULL)
                        return NMP_ERR_MALLOC;

                mem_copy(buf, rq->entry_arg, rq->len);
                rq->entry_arg = buf;
        }

        return 0;
}


static void submit_cleanup(struct nmp_rq *rq, const i32 num_ops)
{
        for (i32 i = 0; i < num_ops; i++) {
                if (rq->entry_arg == NULL)
                        continue;

                switch ((enum nmp_rq_ops) rq->op) {
                case NMP_OP_CONNECT:
                        if (rq->session_id)
                                session_destroy(rq->entry_arg);
                        continue;

                case NMP_OP_SEND:
                        if ((rq->msg_flags & NMP_F_MSG_NOALLOC) == 0)
                                mem_free(rq->entry_arg);
                        continue;

                default:
                        continue;
                }
        }
}


int nmp_submit(struct nmp_instance *nmp,
               struct nmp_rq *rqs, const int num_ops)
{
        if (!nmp || !rqs)
                return NMP_ERR_INVAL;

        if (num_ops <= 0 || num_ops > NMP_RQ_BATCH)
                return NMP_ERR_INVAL;

        i32 i = 0;

        for (; i < num_ops; i++) {
                i32 err = 0;

                switch ((enum nmp_rq_ops) rqs[i].op) {
                case NMP_OP_SEND:
                        err = submit_send(nmp, &rqs[i]);
                        break;

                case NMP_OP_DROP:
                        err = ((rqs[i].session_id == 0) ? NMP_ERR_INVAL : 0);
                        break;

                case NMP_OP_CONNECT:
                        err = submit_connect(nmp, &rqs[i]);
                        break;

                case NMP_OP_TERMINATE:
                        break;

                default:
                        err = NMP_ERR_INVAL;
                        break;
                }

                if (err) {
                        log("failed to process rq at index %i", i);
                        submit_cleanup(rqs, i);
                        return err;
                }
        }

        if (write(nmp->local_tx, rqs, sizeof(struct nmp_rq) * num_ops) == -1) {
                submit_cleanup(rqs, i);
                return NMP_ERR_WRITE;
        }

        return 0;
}


static i32 run_events_deliver(struct nmp_instance *nmp,
                              struct nmp_session *ctx)
{
        i32 err = 0;

        if (ctx->state == SESSION_STATUS_NONE) {
                /*
                 * one (possibly out of many) received packets triggered an error
                 * that led to session_drop(), this context is not in hash table
                 * anymore so no more data after 'fatal packet' but it can still
                 * end up here in this queue => ignore
                 */
                return 0;
        }

        if (ctx->events & SESSION_EVENT_DATA) {
                msg_deliver_data(&nmp->transport_callbacks,
                                 &ctx->transport);

                if ((err = session_ack(nmp, ctx)))
                        return err;

                /* only packets that contain new messages reset this counter */
                ctx->response_retries = 0;
        }

        if (ctx->events & SESSION_EVENT_ACK) {
                switch (msg_deliver_ack(&nmp->transport_callbacks,
                                        &ctx->transport)) {
                case 0:
                        break;

                case -1:
                        /* everything has been acked */
                        ctx->state = SESSION_STATUS_ESTAB;
                        ctx->kts = kts(ctx->timer_keepalive, 0);

                        if (nmp_ring_timer_update(nmp, ctx, &ctx->kts))
                                return NMP_ERR_IORING;

                        break;

                default:
                        /*
                         * if this ack contained any new messages, trigger
                         * data transmission to fill the window back up
                         */
                        ctx->state = SESSION_STATUS_ACKWAIT;
                        if ((err = session_data(nmp, ctx)))
                                return err;

                        break;
                }
        }

        /* processed */
        ctx->events = 0;

        /*
         *  also, if this context managed to get here it is guaranteed that
         *  valid data has been received, so it makes sense to reset counter
         */
        ctx->timer_retries = 0;

        return 0;
}


static i32 run_cqe_err(struct nmp_instance *nmp,
                       struct io_uring_cqe *cqe,
                       void *ptr)
{
        switch (-cqe->res) {
        case ETIME:
                return !ptr ? nmp_ring_timer_set(nmp, NULL, &nmp->kts)
                            : event_timer(nmp, ptr);

        case ENOENT:
                return !ptr ? nmp_ring_timer_set(nmp, NULL, &nmp->kts)
                            : nmp_ring_timer_set(nmp, ptr,
                                                 &((struct nmp_session *) ptr)->kts);

        case ENOBUFS:
                if (ptr == &nmp->net_udp)
                        return nmp_ring_recv_net(nmp);

                if (ptr == &nmp->local_rx)
                        return nmp_ring_recv_local(nmp);

                return NMP_ERR_IORING;

        case EPERM:
                // todo
                return 0;

        default:
                return NMP_ERR_IORING;
        }

        return 0;
}


static i32 run_cqe_process(struct nmp_instance *nmp,
                           struct io_uring_cqe *cqe,
                           struct nmp_session **ctx)
{
        void *data = io_uring_cqe_get_data(cqe);
        if (cqe->res < 0) {
                log("cqe status %s (%p)",
                    strerrorname_np(-cqe->res),
                    io_uring_cqe_get_data(cqe));

                return run_cqe_err(nmp, cqe, data);
        }

        if ((cqe->flags & IORING_CQE_F_BUFFER) == 0) {
                log("unrecognized cqe %p", data);
                return NMP_ERR_IORING;
        }

        if (data == &nmp->net_udp)
                return event_net(nmp, cqe, ctx);

        if (data == &nmp->local_rx)
                return event_local(nmp, cqe, ctx);

        log("unrecognized buffer group");
        return 1;
}


static i32 run_wait_cqe(struct nmp_instance *nmp)
{
        const i32 submitted = io_uring_submit_and_wait(&nmp->ring, 1);
        if (submitted < 0) {
                log("submit and wait: %s", strerrorname_np(-submitted));

                /* -errno */
                switch (-submitted) {
                case EINTR:
                        return 0;

                default:
                        return NMP_ERR_IORING;
                }
        }

        return 0;
}


static i32 run_process_batch(struct nmp_instance *nmp,
                             struct nmp_session **queue)
{
        struct nmp_session *ctx = NULL;
        struct io_uring_cqe *cqe = NULL;
        u32 head = 0;
        i32 items = 0;
        u32 cqes = 0;

        io_uring_for_each_cqe(&nmp->ring, head, cqe) {
                const i32 err = run_cqe_process(nmp, cqe, &ctx);
                if (err) {
                        items = -err;
                        break;
                }

                if (ctx) {
                        queue[items] = ctx;
                        items += 1;
                }

                cqes += 1;
        }

        io_uring_cq_advance(&nmp->ring, cqes);
        return items;
}


i32 nmp_run(struct nmp_instance *nmp, const u32 timeout)
{
        i32 queued = 0;
        struct nmp_session *events_queue[RING_BATCH] = {0};

        if (timeout) {
                nmp->kts = kts(0, timeout);
                if (nmp_ring_timer_set(nmp, NULL, &nmp->kts))
                        return NMP_ERR_IORING;
        }

        while (run_wait_cqe(nmp) == 0) {
                queued = run_process_batch(nmp, events_queue);
                if (queued < 0)
                        break;

                for (i32 i = 0; i < queued; i++) {
                        if (run_events_deliver(nmp, events_queue[i]))
                                return 1;
                }
        }

        return (-queued == NMP_STATUS_LAST) ?
               nmp_teardown(nmp) : -queued;
}
