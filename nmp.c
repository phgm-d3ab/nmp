/*
 *
 */
#include "nmp.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/random.h>
#include <sys/socket.h>

#include <liburing.h>
#include <openssl/evp.h>


typedef uint8_t u8;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef uint64_t u64;
typedef size_t usize;


typedef struct {
        u16 val;
} u16le;

#define u16le_get(x_) le16toh((x_).val)
#define u16le_set(x_) (u16le) {.val = htole16((x_))}


typedef struct {
        u64 val;
} u64le;

#define u64le_get(x_) le64toh((x_).val)
#define u64le_set(x_) (u64le) {.val = htole64((x_))}


/* cosmetics */
#define UNUSED(arg_)    ((void)(arg_))
#define static_assert_pow2(x_) \
        static_assert(((x_) & ((x_) - 1)) == 0, "value must be a power of two")

#define mem_alloc(size_)                malloc(size_)
#define mem_free(ptr_)                  free(ptr_)
#define mem_zero(ptr_, len_)            memset(ptr_, 0, len_)
#define mem_copy(dest_, src_, len_)     memcpy(dest_, src_, len_)
#define mem_cmp(buf1_, buf2_, len_)     memcmp(buf1_, buf2_, len_)


#if defined(NMP_DEBUG)

#   include NMP_DEBUG


#endif


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


static bool siphash_init(struct siphash_ctx *ctx,
                         u8 key[SIPHASH_KEY])
{
        ctx->evp_mac = EVP_MAC_fetch(
                NULL, "siphash", "provider=default");
        if (ctx->evp_mac == NULL)
                return 1;

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


        ctx->evp_ctx = EVP_MAC_CTX_new(ctx->evp_mac);
        if (ctx->evp_ctx == NULL) {
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


static bool siphash_hash(struct siphash_ctx ctx,
                         const void *data, const u32 data_len,
                         u8 hash[SIPHASH_LEN])
{
        if (EVP_MAC_init(ctx.evp_ctx, NULL, 0, NULL) != 1)
                return 1;

        if (EVP_MAC_update(ctx.evp_ctx, data, data_len) != 1)
                return 1;

        return (EVP_MAC_final(ctx.evp_ctx, hash,
                              NULL, SIPHASH_LEN) != 1);
}


static void siphash_free(struct siphash_ctx *ctx)
{
        if (ctx->evp_ctx)
                EVP_MAC_CTX_free(ctx->evp_ctx);

        if (ctx->evp_mac)
                EVP_MAC_free(ctx->evp_mac);
}


enum {
        BLAKE2B_HASHLEN = 64,
};


struct blake2b_ctx {
        const EVP_MD *evp_md;
        EVP_MD_CTX *evp_ctx;
};


static bool blake2b_init(struct blake2b_ctx *ctx)
{
        ctx->evp_md = EVP_blake2b512();
        if (ctx->evp_md == NULL)
                return 1;

        return ((ctx->evp_ctx = EVP_MD_CTX_new()) == NULL);
}


static bool blake2b_reset(struct blake2b_ctx ctx)
{
        return (EVP_DigestInit_ex2(ctx.evp_ctx, ctx.evp_md, NULL) != 1);
}


static bool blake2b_update(struct blake2b_ctx ctx,
                           const void *data, const u32 data_len)
{
        return (EVP_DigestUpdate(ctx.evp_ctx, data, data_len) != 1);
}


static bool blake2b_final(struct blake2b_ctx ctx,
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


static bool blake2b_hmac_init(struct blake2b_hmac_ctx *ctx)
{
        ctx->evp_mac = EVP_MAC_fetch(NULL, "hmac", "provider=default");
        if (ctx->evp_mac == NULL)
                return 1;

        ctx->evp_ctx = EVP_MAC_CTX_new(ctx->evp_mac);
        if (ctx->evp_ctx == NULL) {
                EVP_MAC_free(ctx->evp_mac);
                return 1;
        }


        char digest[] = {'b', 'l', 'a', 'k', 'e',
                         '2', 'b', '5', '1', '2', 0};

        const OSSL_PARAM params[] = {
                OSSL_PARAM_construct_utf8_string("digest", digest, 10),
                OSSL_PARAM_END,
        };

        if (EVP_MAC_CTX_set_params(ctx->evp_ctx, params) != 1) {
                EVP_MAC_CTX_free(ctx->evp_ctx);
                EVP_MAC_free(ctx->evp_mac);
                return 1;
        }

        return 0;
}


static bool blake2b_hmac_hash(struct blake2b_hmac_ctx *ctx,
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


static bool chacha20poly1305_init(struct chacha20poly1305_ctx *ctx,
                                  const u8 key[CHACHA20POLY1305_KEYLEN])
{
        ctx->evp_ctx = EVP_CIPHER_CTX_new();
        if (ctx->evp_ctx == NULL)
                return 1;

        return (EVP_CipherInit_ex2(ctx->evp_ctx, EVP_chacha20_poly1305(),
                                   key, NULL, -1, NULL) != 1);
}


static bool chacha20poly1305_set_key(struct chacha20poly1305_ctx *ctx,
                                     const u8 key[CHACHA20POLY1305_KEYLEN])
{
        return (EVP_CipherInit_ex2(ctx->evp_ctx, NULL,
                                   key, NULL, -1, NULL) != 1);
}


static bool chacha20poly1305_encrypt(struct chacha20poly1305_ctx ctx,
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

        return (EVP_DecryptFinal(ctx.evp_ctx, ((u8 *) plaintext) + outlen,
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


static bool x448_public_init(struct x448_public *ctx,
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


static bool x448_private_init(struct x448_private *ctx,
                              const u8 key[X448_KEYLEN])
{
        ctx->key = EVP_PKEY_new_raw_private_key(
                EVP_PKEY_X448, NULL, key, X448_KEYLEN);
        if (ctx->key == NULL)
                return 1;

        return ((ctx->dh = EVP_PKEY_CTX_new(ctx->key, NULL)) == NULL);
}


static bool x448_private_derive_pub(const struct x448_private *ctx,
                                    u8 pub[X448_KEYLEN])
{
        u64 keylen = X448_KEYLEN;
        return (EVP_PKEY_get_raw_public_key(ctx->key, pub, &keylen) != 1);
}


static void x448_private_free(struct x448_private *ctx)
{
        if (ctx->dh)
                EVP_PKEY_CTX_free(ctx->dh);

        if (ctx->key)
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
 *  io_uring wrappers
 */
#define ior_for_each_cqe io_uring_for_each_cqe

typedef union nmp_sa ior_addr; /* @nmp.h */
typedef struct io_uring_sqe ior_sqe;
typedef struct io_uring_cqe ior_cqe;


enum {
        IOR_BATCH = 32,
        IOR_RECV_BUFS = 512,
        IOR_SQ = (64 * IOR_BATCH),
        IOR_CQ = (IOR_SQ * 4),
};


enum {
        IOR_UDP_MAX = 1440,
        IOR_UDP_MIN = 32,
        IOR_UDP_PBUFSIZE = 2048,
        IOR_SOCPAIR_PBUFSIZE = 768,
};


enum {
        IOR_CQE_UDP = 0,
        IOR_CQE_SP = 1,
        IOR_CQE_TIMER = 2,
        IOR_CQE_ERR = 3,
};


struct ior {
        struct io_uring ring;

        int udp_soc;
        struct io_uring_buf_ring *udp_ring;
        struct ior_udp_pbuf *udp_ring_base;
        u32 udp_ring_size;
        struct msghdr udp_hdr;

        int sp_soc;
        struct io_uring_buf_ring *sp_ring;
        struct ior_spair_pbuf *sp_ring_base;
        u32 sp_ring_size;
};


static ior_sqe *ior_sqe_get(struct ior *ctx)
{
        struct io_uring_sqe *sqe = io_uring_get_sqe(&ctx->ring);
        if (sqe == NULL) {
                const i32 res = io_uring_submit(&ctx->ring);
                if (res < 0)
                        return NULL;

                return io_uring_get_sqe(&ctx->ring);
        }

        return sqe;
}


struct ior_pbuf {
        usize item_size;
        i32 items_amt;
        i32 bgid;

        usize buf_size;
        void *ring;
        void *base;
};


struct ior_pbuf_out {
        void *pbuf;
        u32 bid;
        u32 data_len;
        void *data;
        void *name;
};


static bool ior_pbuf_setup(struct ior *ctx, struct ior_pbuf *cfg)
{
        i32 res = 0;
        cfg->buf_size = (sizeof(struct io_uring_buf) + cfg->item_size)
                        * cfg->items_amt;

        cfg->ring = mmap(NULL, cfg->buf_size,
                         PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE,
                         0, 0);
        if (cfg->ring == MAP_FAILED)
                return 1;

        io_uring_buf_ring_init(cfg->ring);
        struct io_uring_buf_reg reg = {
                .ring_addr = (u64) cfg->ring,
                .ring_entries = cfg->items_amt,
                .bgid = cfg->bgid,
        };

        res = io_uring_register_buf_ring(&ctx->ring, &reg, 0);
        if (res) {
                errno = -res;
                munmap(cfg->ring, cfg->buf_size);
                return 1;
        }

        u8 *base = (u8 *) (cfg->ring) + (sizeof(struct io_uring_buf) * cfg->items_amt);

        for (i32 i = 0; i < cfg->items_amt; i++) {
                io_uring_buf_ring_add(cfg->ring, base + (cfg->item_size * i),
                                      cfg->item_size, i,
                                      io_uring_buf_ring_mask(cfg->items_amt),
                                      i);
        }

        io_uring_buf_ring_advance(cfg->ring, cfg->items_amt);

        cfg->base = base;
        return 0;
}


struct ior_udp_pbuf {
        u8 _data[IOR_UDP_PBUFSIZE];
};


static bool ior_udp_setup(struct ior *ctx, const int udp_soc)
{
        struct ior_pbuf cfg = {0};

        cfg.item_size = sizeof(struct ior_udp_pbuf);
        cfg.items_amt = IOR_RECV_BUFS;
        cfg.bgid = IOR_CQE_UDP;

        if (ior_pbuf_setup(ctx, &cfg))
                return 1;

        ctx->udp_soc = udp_soc;
        ctx->udp_ring_size = cfg.buf_size;
        ctx->udp_ring = cfg.ring;
        ctx->udp_ring_base = cfg.base;
        ctx->udp_hdr.msg_namelen = sizeof(struct sockaddr_storage);

        return 0;
}


static bool ior_udp_recv(struct ior *ctx)
{
        ior_sqe *sqe = ior_sqe_get(ctx);
        if (sqe == NULL)
                return 1;

        io_uring_prep_recvmsg_multishot(sqe, ctx->udp_soc, &ctx->udp_hdr, 0);
        io_uring_sqe_set_data(sqe, NULL);
        sqe->flags = IOSQE_BUFFER_SELECT;
        sqe->buf_group = IOR_CQE_UDP;

        return 0;
}


static bool ior_udp_pbuf_get(struct ior *ctx, const ior_cqe *cqe,
                             struct ior_pbuf_out *out)
{
        if ((cqe->flags & IORING_CQE_F_MORE) == 0)
                return ior_udp_recv(ctx);

        if ((cqe->flags & IORING_CQE_F_BUFFER) == 0)
                return 1;

        out->bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        out->pbuf = &ctx->udp_ring_base[out->bid];

        struct io_uring_recvmsg_out *o =
                io_uring_recvmsg_validate(out->pbuf, cqe->res, &ctx->udp_hdr);
        if (o == NULL)
                return 0;

        if (o->namelen > sizeof(ior_addr))
                return 0;

        out->data = io_uring_recvmsg_payload(o, &ctx->udp_hdr);
        out->data_len = io_uring_recvmsg_payload_length(
                o, cqe->res, &ctx->udp_hdr);
        out->name = io_uring_recvmsg_name(o);

        if (out->data_len < IOR_UDP_MIN || out->data_len > IOR_UDP_MAX) {
                out->data = NULL;
                return 0;
        }

        return 0;
}


static void ior_udp_pbuf_reuse(struct ior *ctx,
                               struct ior_udp_pbuf *buf, const u32 bid)
{
        io_uring_buf_ring_add(ctx->udp_ring, buf,
                              sizeof(struct ior_udp_pbuf), bid,
                              io_uring_buf_ring_mask(IOR_RECV_BUFS), 0);
        io_uring_buf_ring_advance(ctx->udp_ring, 1);
}


struct ior_spair_pbuf {
        u8 _data[IOR_SOCPAIR_PBUFSIZE];
};


static bool ior_socpair_setup(struct ior *ctx, const int recv_soc)
{
        struct ior_pbuf cfg = {0};

        cfg.item_size = sizeof(struct ior_spair_pbuf);
        cfg.items_amt = IOR_RECV_BUFS;
        cfg.bgid = IOR_CQE_SP;

        if (ior_pbuf_setup(ctx, &cfg))
                return 1;

        ctx->sp_soc = recv_soc;
        ctx->sp_ring_size = cfg.buf_size;
        ctx->sp_ring = cfg.ring;
        ctx->sp_ring_base = cfg.base;

        return 0;
}


static bool ior_socpair_recv(struct ior *ctx)
{
        ior_sqe *sqe = ior_sqe_get(ctx);
        if (sqe == NULL)
                return 1;

        io_uring_prep_recv_multishot(sqe, ctx->sp_soc, NULL, 0, 0);
        io_uring_sqe_set_data(sqe, ctx);
        sqe->flags = IOSQE_BUFFER_SELECT;
        sqe->buf_group = IOR_CQE_SP;

        return 0;
}


static bool ior_socpair_pbuf_get(struct ior *ctx, const ior_cqe *cqe,
                                 struct ior_pbuf_out *out)
{
        if ((cqe->flags & IORING_CQE_F_MORE) == 0)
                return ior_socpair_recv(ctx);

        if ((cqe->flags & IORING_CQE_F_BUFFER) == 0)
                return 1;

        out->bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
        out->pbuf = &ctx->sp_ring_base[out->bid];
        out->data = out->pbuf;
        out->data_len = cqe->res;
        return 0;
}


static void ior_socpair_buf_reuse(struct ior *ctx,
                                  struct ior_spair_pbuf *buf, const u32 bid)
{
        io_uring_buf_ring_add(ctx->sp_ring, buf,
                              sizeof(struct ior_spair_pbuf), bid,
                              io_uring_buf_ring_mask(IOR_RECV_BUFS), 0);
        io_uring_buf_ring_advance(ctx->sp_ring, 1);
}


static bool ior_setup(struct ior *ctx,
                      const int udp_soc, const int recv_soc)
{
        i32 res = 0;
        struct io_uring_params params = {0};
        params.cq_entries = IOR_CQ;
        params.flags = 0
                       | IORING_SETUP_SUBMIT_ALL
                       | IORING_SETUP_COOP_TASKRUN
                       | IORING_SETUP_CQSIZE;

        res = io_uring_queue_init_params(
                IOR_SQ, &ctx->ring, &params);
        if (res) {
                errno = -res;
                return 1;
        }

        if (ior_udp_setup(ctx, udp_soc))
                return 1;

        if (ior_socpair_setup(ctx, recv_soc))
                return 1;

        return 0;
}


static bool ior_wait_cqe(struct ior *ctx)
{
        const i32 res = io_uring_submit_and_wait(&ctx->ring, 1);
        if (res < 0) {
                /* errno */
                switch (-res) {
                case EINTR:
                        return 0;

                default:
                        errno = -res;
                        return 1;
                }
        }

        return 0;
}


static inline u32 ior_cqe_kind(const struct ior *ctx,
                               const ior_cqe *cqe)
{
        void *data = io_uring_cqe_get_data(cqe);
        if (data == NULL)
                return IOR_CQE_UDP;

        if (data == ctx)
                return IOR_CQE_SP;

        if (cqe->res == 0)
                return IOR_CQE_TIMER;

        return IOR_CQE_ERR;
}


static void *ior_cqe_data(const ior_cqe *cqe)
{
        return io_uring_cqe_get_data(cqe);
}


static inline int ior_cqe_err(const ior_cqe *cqe)
{
        return (cqe->res < 0) ? -cqe->res : 0;
}


static void ior_cq_advance(struct ior *ctx, const u32 items)
{
        io_uring_cq_advance(&ctx->ring, items);
}


static void ior_teardown(struct ior *ctx)
{
        if (ctx->udp_ring)
                munmap(ctx->udp_ring, ctx->udp_ring_size);

        if (ctx->sp_ring)
                munmap(ctx->sp_ring, ctx->sp_ring_size);

        close(ctx->udp_soc);
        close(ctx->sp_soc);

        io_uring_queue_exit(&ctx->ring);
}


struct ior_udp_send_buf {
        ior_addr addr;
        struct msghdr hdr;
        struct iovec iov;
        u8 data[IOR_UDP_MAX];
};


static void *ior_udp_prep_send(struct ior_udp_send_buf *buf,
                               const ior_addr *addr)
{
        buf->addr = *addr;
        buf->hdr.msg_name = &buf->addr;
        buf->hdr.msg_namelen = sizeof(ior_addr);
        buf->hdr.msg_iov = &buf->iov;
        buf->hdr.msg_iovlen = 1;
        buf->iov.iov_base = buf->data;

        return buf->data;
}


static bool ior_udp_send(struct ior *ctx, void *ref,
                         struct ior_udp_send_buf *buf, const u32 data_len)
{
        ior_sqe *sqe = ior_sqe_get(ctx);
        if (sqe == NULL)
                return 1;

        buf->iov.iov_len = data_len;
        io_uring_prep_sendmsg(sqe, ctx->udp_soc, &buf->hdr, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        io_uring_sqe_set_data(sqe, ref);

        return 0;
}


struct ior_timespec {
        struct __kernel_timespec kts;
};

#define ior_ts_init(sec_, ms_) \
                { .kts.tv_sec = (sec_), .kts.tv_nsec = ((ms_) * 1000000lu), }

#define ior_ts(sec_, ms_) ((struct ior_timespec) ior_ts_init(sec_, ms_))


/*
 *  expired timer is not considered an error, so we link this
 *  to nop so that this posts zero to cq instead of ETIME
 */
static bool ior_timer_set(struct ior *ctx, struct ior_timespec *t, void *ref)
{
        ior_sqe *sqe = ior_sqe_get(ctx);
        if (sqe == NULL)
                return 1;

        io_uring_prep_timeout(sqe, &t->kts, 0,
                              IORING_TIMEOUT_ETIME_SUCCESS);
        io_uring_sqe_set_flags(sqe, IOSQE_IO_LINK | IOSQE_CQE_SKIP_SUCCESS);
        io_uring_sqe_set_data(sqe, ref);

        sqe = ior_sqe_get(ctx);
        if (sqe == NULL)
                return 1;

        io_uring_prep_nop(sqe);
        io_uring_sqe_set_data(sqe, ref);

        return 0;
}


static bool ior_timer_upd(struct ior *ctx, struct ior_timespec *t, void *ref)
{
        ior_sqe *sqe = ior_sqe_get(ctx);
        if (sqe == NULL)
                return 1;

        io_uring_prep_timeout_update(sqe, &t->kts, (u64) ref, 0);
        io_uring_sqe_set_flags(sqe, IOSQE_CQE_SKIP_SUCCESS);
        return 0;
}


/*
 *  time
 */
static u64 time_get(void)
{
        struct timespec ts = {0};
        if (clock_gettime(CLOCK_TAI, &ts))
                return 0;

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


static u32 rnd_get32(void)
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
#define HT_ERR ((void *) -1)

enum {
        HT_SIZE = 128,
};


static_assert_pow2(HT_SIZE);


enum ht_entry_status {
        HT_EMPTY = 0,
        HT_DELETED = 1,
        HT_OCCUPIED = 2,
};


struct ht_entry {
        enum ht_entry_status status;
        u32 key;
        void *val;
};


struct hash_table {
        i32 items;
        i32 capacity;
        i32 deletions;
        struct siphash_ctx siphash;
        struct ht_entry *entry;
};


static i32 ht_rebuild(struct hash_table *ht, const i32 cap_new)
{
        const u32 arr_len = sizeof(struct ht_entry) * cap_new;
        struct ht_entry *arr = mem_alloc(arr_len);
        if (arr == NULL)
                return -1;

        mem_zero(arr, arr_len);
        i32 items = 0;

        for (i32 i = 0; i < ht->capacity; i++) {
                struct ht_entry *entry = ht->entry + i;
                if (entry->status != HT_OCCUPIED)
                        continue;

                u64 hash = 0;
                if (siphash_hash(ht->siphash, &entry->key,
                                 sizeof(u32), (u8 *) &hash)) {
                        mem_free(arr);
                        return -1;
                }

                const u64 slot = (i32) hash & (cap_new - 1);
                struct ht_entry *entry_new = NULL;

                for (i32 j = 0; j < cap_new; j++) {
                        entry_new = &arr[(slot + j) & (cap_new - 1)];
                        if (entry_new->status)
                                continue;

                        *entry_new = (struct ht_entry) {
                                .status = HT_OCCUPIED,
                                .key = entry->key,
                                .val = entry->val,
                        };

                        break;
                }

                items += 1;
                if (items == ht->items)
                        break;
        }

        mem_free(ht->entry);
        ht->capacity = cap_new;
        ht->deletions = 0;
        ht->entry = arr;
        return 0;
}


static struct ht_entry *ht_slot(struct hash_table *ht,
                                const u32 key, const u64 hash)
{
        const i32 slot = (i32) hash & (ht->capacity - 1);
        struct ht_entry *entry = NULL;
        struct ht_entry *entry_swap = NULL;

        for (i32 i = 0; i < ht->capacity; i++) {
                entry = &ht->entry[(slot + i) & (ht->capacity - 1)];

                if (entry->status == HT_EMPTY)
                        break;

                if (entry->status == HT_DELETED) {
                        if (entry_swap == NULL)
                                entry_swap = entry;

                        continue;
                }

                if (entry->status == HT_OCCUPIED) {
                        if (entry->key == key)
                                break;
                }
        }

        if (entry_swap && entry->status == HT_OCCUPIED) {
                *entry_swap = *entry;
                *entry = (struct ht_entry) {
                        .status = HT_DELETED,
                        .key = 0,
                        .val = 0,
                };

                entry = entry_swap;
        }

        return entry;
}


static void *ht_find(struct hash_table *ht, const u32 key)
{
        u64 hash = 0;
        if (siphash_hash(ht->siphash, &key, sizeof(u32),
                         (u8 *) &hash))
                return HT_ERR;

        struct ht_entry *entry = ht_slot(ht, key, hash);
        if (entry->status == HT_OCCUPIED && entry->key == key)
                return entry->val;

        return NULL;
}


static i32 ht_insert(struct hash_table *ht, const u32 key, void *val)
{
        u64 hash = 0;
        if (siphash_hash(ht->siphash, &key, sizeof(u32),
                         (u8 *) &hash))
                return -1;

        const i32 slot = (i32) hash & (ht->capacity - 1);
        struct ht_entry *entry = NULL;

        for (i32 i = 0; i < ht->capacity; i++) {
                entry = &ht->entry[(slot + i) & (ht->capacity - 1)];

                if (entry->status < HT_OCCUPIED) {
                        *entry = (struct ht_entry) {
                                .status = HT_OCCUPIED,
                                .key = key,
                                .val = val,
                        };

                        ht->items += 1;
                        return (ht->items > (ht->capacity / 2)) ?
                               ht_rebuild(ht, ht->capacity * 2) : 0;
                }
        }

        return 1;
}


static i32 ht_remove(struct hash_table *ht, const u32 key)
{
        u64 hash = 0;
        if (siphash_hash(ht->siphash, &key, sizeof(u32),
                         (u8 *) &hash))
                return -1;

        struct ht_entry *entry = ht_slot(ht, key, hash);
        if (entry->status == HT_OCCUPIED && entry->key == key) {
                *entry = (struct ht_entry) {
                        .status = HT_DELETED,
                        .key = 0,
                        .val = 0,
                };

                ht->items -= 1;
                ht->deletions += 1;
                if (ht->deletions > (ht->capacity / 2))
                        return ht_rebuild(ht, ht->capacity);

                /* noop */
        }

        return 0;
}


static bool ht_init(struct hash_table *ht, u8 key[SIPHASH_KEY])
{
        const u32 arrlen = sizeof(struct ht_entry) * HT_SIZE;
        struct ht_entry *arr = mem_alloc(arrlen);
        if (arr == NULL)
                return 1;

        if (siphash_init(&ht->siphash, key)) {
                mem_free(arr);
                return 1;
        }

        ht->items = 0;
        ht->capacity = HT_SIZE;
        ht->deletions = 0;
        ht->entry = arr;
        mem_zero(arr, arrlen);

        return 0;
}


static void ht_teardown(struct hash_table *ht,
                        void (destructor)(void *))
{
        if (ht->items == 0 || destructor == NULL)
                goto out;

        for (i32 i = 0; ht->items && i < ht->capacity; i++) {
                if (ht->entry[i].val) {
                        ht->items -= 1;
                        destructor(ht->entry[i].val);
                }
        }

        out:
        {
                siphash_free(&ht->siphash);
                mem_free(ht->entry);
        }
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
        MSG_MAX_MSGLEN = 1404,
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
        u16le sequence;
        u16le len;
        u8 data[];
};


struct msg_ack {
        u16le ack;
        u16 pad[3];
        u64le ack_mask;
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
        u8 data[MSG_MAX_MSGLEN];
};


struct msg_cbs {
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
static inline bool msg_sequence_cmp(const u16 a, const u16 b)
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
        msg->sequence = u16le_set(tx->seq);
        msg->len = u16le_set(tx->len);

        mem_copy(msg->data, tx->msg, tx->len);
}


static inline void msg_rx_copy(struct msg_rx_entry *entry,
                               const struct msg_header *msg, const u16 msg_len)
{
        entry->status = MSG_RX_RECEIVED;
        entry->seq = u16le_get(msg->sequence);
        entry->len = msg_len;

        mem_copy(entry->data, msg->data, msg_len);
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


static bool msg_queue(struct msg_state *ctx, const u8 *msg, const u16 len,
                      const u8 flags, const u64 user_data)
{
        assert(msg);

        /* pre-increment: check one ahead */
        const u32 index = (ctx->tx_seq + 1) & (MSG_TXQUEUE - 1);
        struct msg_tx_entry *entry = ctx->tx_queue + index;

        if (entry->status != MSG_TX_EMPTY)
                return 1;

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


static i32 msg_assemble_noack(struct msg_header *header,
                              const u8 *payload, const u16 len)
{
        header->sequence = u16le_set(0);
        header->len = u16le_set(len | MSG_NOACK);

        mem_copy(header->data, payload, len);
        return msg_payload_zeropad(header->data,
                                   (i32) (len + sizeof(struct msg_header)));
}


static i32 msg_read(const struct msg_cbs *cb, struct msg_state *ctx,
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

                const u16 msgseq = u16le_get(msg->sequence);
                const u16 msglen_bits = u16le_get(msg->len);
                if (msglen_bits & MSG_RESERVED)
                        return -1;

                const u16 msg_len = msglen_bits & ~(MSG_NOACK | MSG_RESERVED);
                if (msg_len == 0)
                        break;

                /*
                 * example: msg->len == 1000 but there are 100 bytes left
                 * to read in the packet; lets have a protection against this
                 */
                const u16 msg_maxlen = (u16) (len - iterator - sizeof(struct msg_header));
                if (msg_len > msg_maxlen)
                        return -1;

                if (msglen_bits & MSG_NOACK) {
                        /* mixing regular and noack messages is not allowed */
                        if (discovered)
                                return -1;

                        if (cb->data_noack)
                                cb->data_noack(msg->data, msg_len, ctx->context_ptr);

                        return (MSG_WINDOW + 1);
                }


                if (msg_sequence_cmp(msgseq, seq_low)) {
                        if (msg_sequence_cmp(msgseq, seq_high))
                                return -1;

                        if (msg_sequence_cmp(msgseq, ctx->rx_seq))
                                ctx->rx_seq = msgseq;

                        struct msg_rx_entry *entry = rx_get(ctx, msgseq);
                        if (entry->status == MSG_RX_EMPTY) {
                                new_messages += 1;
                                msg_rx_copy(entry, msg, msg_len);
                        }
                }

                iterator += (msg_len + sizeof(struct msg_header));
        }

        return new_messages;
}

/*
 *  this can be called only if there are new messages to deliver
 */
static void msg_deliver_data(const struct msg_cbs *cb,
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
                if (entry->status == MSG_RX_EMPTY)
                        mask &= ~(1lu << shift);

                assert(shift <= MSG_WINDOW);
                shift += 1;
        }

        ack->ack = u16le_set(seq_hi);
        ack->pad[0] = 0;
        ack->pad[1] = 0;
        ack->pad[2] = 0;
        ack->ack_mask = u64le_set(mask);
}


static i32 msg_ack_read(struct msg_state *ctx,
                        const struct msg_ack *ack_ptr)
{
        i32 discovered = 0;
        u64 mask = u64le_get(ack_ptr->ack_mask);
        const u16 ack = u16le_get(ack_ptr->ack);


        if (!msg_sequence_cmp(ack, ctx->tx_ack))
                return 0;

        if (msg_sequence_cmp(ack, ctx->tx_sent)) {
                /*
                 * remote peer tries to send ack for something
                 * we did not send yet, cannot have this
                 */
                return -1;
        }

        if ((mask & 1) == 0) {
                /*
                 * first bit corresponds to current ack
                 * sequence, it is always set
                 */
                return -1;
        }

        for (u16 i = ack;; i--) {
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

        return discovered;
}


static i32 msg_deliver_ack(const struct msg_cbs *cb,
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
#define NOISE_NONCE_MAX UINT64_MAX

enum {
        NOISE_KEYLEN = 32,
        NOISE_HASHLEN = BLAKE2B_HASHLEN,
        NOISE_DHLEN = X448_KEYLEN,
        NOISE_AEAD_MAC = CHACHA20POLY1305_TAGLEN,
        NOISE_HANDSHAKE_PAYLOAD = 128,
        NOISE_COUNTER_WINDOW = 224,
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


static bool noise_hash(struct blake2b_ctx hash,
                       const void *data, const u32 data_len,
                       u8 output[NOISE_HASHLEN])
{
        if (blake2b_reset(hash))
                return 1;

        if (blake2b_update(hash, data, data_len))
                return 1;

        return blake2b_final(hash, output);
}


static inline bool noise_hmac_hash(struct blake2b_hmac_ctx *hmac,
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
static bool noise_hkdf(struct blake2b_hmac_ctx *hmac,
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
        i32 res = 0;
        u8 tmp_dh[NOISE_DHLEN] = {0};
        u8 tmp_hash[NOISE_HASHLEN] = {0};
        struct x448_public pub = {0};

        if (x448_public_init(&pub, pub_raw))
                return -1;

        res = x448_dh(&key_pair->priv, pub, tmp_dh);
        if (res)
                goto out_fail;

        if (noise_hash(hash, tmp_dh,
                       NOISE_DHLEN, tmp_hash)) {
                res = -1;
                goto out_fail;
        }

        mem_copy(shared_secret, tmp_hash, NOISE_DHLEN);
        x448_public_free(&pub);
        return 0;

        out_fail:
        {
                x448_public_free(&pub);
                return res;
        }
}


static inline bool noise_keypair_initialize(struct noise_keypair *pair,
                                            const u8 private[NOISE_DHLEN])
{
        if (x448_private_init(&pair->priv, private))
                return 1;

        return x448_private_derive_pub(&pair->priv, pair->pub_raw);
}


static bool noise_keypair_generate(struct blake2b_ctx h,
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
        const u64le tmp = u64le_set(n);

        out[0] = 0;
        out[1] = 0;
        out[2] = 0;
        out[3] = 0;
        out[4] = (u8) (tmp.val);
        out[5] = (u8) (tmp.val >> 8);
        out[6] = (u8) (tmp.val >> 16);
        out[7] = (u8) (tmp.val >> 24);
        out[8] = (u8) (tmp.val >> 32);
        out[9] = (u8) (tmp.val >> 40);
        out[10] = (u8) (tmp.val >> 48);
        out[11] = (u8) (tmp.val >> 56);
}


static inline bool noise_encrypt(struct chacha20poly1305_ctx cipher, const u64 n,
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


static inline i32 noise_decrypt(struct chacha20poly1305_ctx cipher, const u64 n,
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


static bool noise_mix_key(struct noise_handshake *state,
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


static bool noise_mix_hash(struct noise_handshake *state,
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
static i32 noise_mix_key_dh(struct noise_handshake *state,
                            struct noise_keypair *pair,
                            const u8 *public_key)
{
        u8 temp_dh[NOISE_DHLEN] = {0};
        i32 res = 0;

        res = noise_dh(state->hash, pair,
                       public_key, temp_dh);
        if (res)
                return res;

        if (noise_mix_key(state, temp_dh, NOISE_DHLEN))
                return -1;

        return 0;
}


static bool noise_encrypt_and_hash(struct noise_handshake *state,
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


static i32 noise_decrypt_and_hash(struct noise_handshake *state,
                                  const u8 *ciphertext, const u32 ciphertext_len,
                                  u8 *mac, void *plaintext)
{
        i32 res = 0;
        if (chacha20poly1305_set_key(&state->aead, state->cipher_k))
                return -1;

        res = noise_decrypt(state->aead, state->cipher_n,
                            state->symmetric_h, NOISE_HASHLEN,
                            ciphertext, ciphertext_len,
                            mac, plaintext);
        if (res)
                return res;

        if (noise_mix_hash(state, ciphertext, ciphertext_len))
                return -1;

        return 0;
}


static bool noise_split(struct noise_handshake *state,
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


static bool noise_state_init(struct noise_handshake *state)
{
        /* these states normally have values set already, so: */
        return noise_mix_hash(state, state->rs, NOISE_DHLEN);
}


static void noise_state_del(struct noise_handshake *state)
{
        noise_keypair_del(&state->e);
}


static i32 noise_initiator_write(struct noise_handshake *state,
                                 struct noise_initiator *initiator,
                                 const void *ad, const u32 ad_len,
                                 const u8 *payload)
{
        i32 res = 0;

        if (noise_mix_hash(state, ad, ad_len))
                return -1;

        /* e */
        if (noise_keypair_generate(state->hash, state->rnd, &state->e))
                return -1;

        mem_copy(initiator->ephemeral, state->e.pub_raw, NOISE_DHLEN);
        if (noise_mix_hash(state, state->e.pub_raw, NOISE_DHLEN))
                return -1;

        /* es */
        res = noise_mix_key_dh(state, &state->e, state->rs);
        if (res)
                return res;

        /* s */
        if (noise_encrypt_and_hash(state,
                                   state->s->pub_raw, NOISE_DHLEN,
                                   initiator->encrypted_static,
                                   initiator->mac1))
                return -1;

        /* ss */
        res = noise_mix_key_dh(state, state->s, state->rs);
        if (res)
                return res;

        /* payload: encrypt_and_hash(payload) */
        if (noise_encrypt_and_hash(state, payload, NOISE_HANDSHAKE_PAYLOAD,
                                   initiator->encrypted_payload, initiator->mac2))
                return -1;

        return 0;
}


static i32 noise_responder_read(struct noise_handshake *state,
                                struct noise_responder *responder,
                                const void *ad, const u32 ad_len,
                                u8 *payload)
{
        i32 res = 0;

        if (noise_mix_hash(state, ad, ad_len))
                return -1;

        /* e */
        if (noise_mix_hash(state, responder->ephemeral, NOISE_DHLEN))
                return -1;

        /* ee */
        res = noise_mix_key_dh(state, &state->e, responder->ephemeral);
        if (res)
                return res;

        /* se */
        res = noise_mix_key_dh(state, state->s, responder->ephemeral);
        if (res)
                return res;

        /* payload */
        return noise_decrypt_and_hash(state, responder->encrypted_payload,
                                      NOISE_HANDSHAKE_PAYLOAD,
                                      responder->mac, payload);
}


static i32 noise_initiator_read(struct noise_handshake *state,
                                struct noise_initiator *initiator,
                                const void *ad, const u32 ad_len,
                                u8 *payload)
{
        i32 res = 0;

        if (noise_mix_hash(state, ad, ad_len))
                return -1;

        /* e */
        mem_copy(state->re, initiator->ephemeral, NOISE_DHLEN);
        if (noise_mix_hash(state, state->re, NOISE_DHLEN))
                return -1;

        /* es */
        res = noise_mix_key_dh(state, state->s, state->re);
        if (res)
                return res;

        /* s */
        res = noise_decrypt_and_hash(state, initiator->encrypted_static,
                                     NOISE_DHLEN, initiator->mac1, state->rs);
        if (res)
                return res;


        /* ss */
        res = noise_mix_key_dh(state, state->s, state->rs);
        if (res)
                return res;

        /* payload */
        return noise_decrypt_and_hash(state, initiator->encrypted_payload,
                                      NOISE_HANDSHAKE_PAYLOAD,
                                      initiator->mac2, payload);
}


static i32 noise_responder_write(struct noise_handshake *state,
                                 struct noise_responder *responder,
                                 const void *ad, const u32 ad_len,
                                 const void *payload)
{
        i32 res = 0;

        if (noise_mix_hash(state, ad, ad_len))
                return -1;

        /* e */
        if (noise_keypair_generate(state->hash, state->rnd, &state->e))
                return -1;

        mem_copy(responder->ephemeral, state->e.pub_raw, NOISE_DHLEN);
        if (noise_mix_hash(state, state->e.pub_raw, NOISE_DHLEN))
                return -1;

        /* ee */
        res = noise_mix_key_dh(state, &state->e, state->re);
        if (res)
                return res;

        /* se */
        res = noise_mix_key_dh(state, &state->e, state->rs);
        if (res)
                return res;

        /* payload */
        if (noise_encrypt_and_hash(state, payload, NOISE_HANDSHAKE_PAYLOAD,
                                   responder->encrypted_payload, responder->mac))
                return -1;

        return 0;
}


static i32 noise_counter_validate(const u32 block[8],
                                  const u64 local,
                                  const u64 remote)
{
        if (remote + NOISE_COUNTER_WINDOW < local)
                return -1;

        if (remote > (local + NOISE_COUNTER_WINDOW) || remote == NOISE_NONCE_MAX)
                return -1;

        const i32 block_index = (i32) (remote / 32) & 7;
        if (remote <= local) {
                if (block[block_index] & (1u << (remote & 31u)))
                        return -1;
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
        u64le counter;
        u8 data[];
};


/*
 *  milliseconds
 */
enum {
#if defined(NMP_DEBUG_TIMERS)
        SESSION_REQUEST_TTL = INT32_MAX,
#else
        SESSION_REQUEST_TTL = 15000,
#endif
};


static const struct ior_timespec rto_table[] = {
        ior_ts_init(0, 250),
        ior_ts_init(0, 250),
        ior_ts_init(0, 350),
        ior_ts_init(0, 350),
        ior_ts_init(0, 500),
        ior_ts_init(0, 500),
        ior_ts_init(0, 500),
        ior_ts_init(0, 500),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
        ior_ts_init(1, 0),
};


enum retries {
        /*
         * this covers an extremely rare case when our acks and/or responses do
         * not go through: how many times we can respond to a valid request or how
         * many acks to send if received data packet did not contain any new messages
         */
        SESSION_RETRY_RESPONSE = 10,

        /* how many times to retry sending data */
        SESSION_RETRY_DATA = (sizeof(rto_table) / sizeof(struct ior_timespec)),

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


struct nmp_init_payload {
        u64 timestamp;
        u8 _reserved[24];
        u8 data[NMP_INITIATION_PAYLOAD];
};


struct nmp_session_init {
        struct noise_handshake handshake;
        struct nmp_init_payload payload;

        /* responder saves remote initiator */
        struct nmp_request request_buf;

        /* initiator/responder saves its own request/response */
        struct ior_udp_send_buf send_buf;
};


struct nmp_event {
        i32 err;
        struct nmp_session *ctx;
        struct ior_pbuf_out buf;
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

        u64 noise_cnt_send;
        u64 noise_cnt_recv;
        u32 noise_cnt_block[8];
        struct chacha20poly1305_ctx noise_key_recv;
        struct chacha20poly1305_ctx noise_key_send;

        union nmp_sa addr;
        u64 stat_tx;
        u64 stat_rx;
        struct ior_timespec its;
        struct nmp_session_init *initiation;

        union { /* just share first member */
                void *context_ptr;
                struct msg_state transport;
        };

        u32 send_iter;
        struct ior_udp_send_buf send_bufs[MSG_WINDOW];
};


struct nmp_instance {
        struct ior io;

        i32 local_tx;
        u32 options;
        sa_family_t sa_family;
        struct ior_timespec its;

        void *request_ctx;
        int (*request_cb)(struct nmp_rq_connect *, const u8 *, void *);
        int (*status_cb)(const enum nmp_status, const union nmp_cb_status *, void *);
        void (*stats_cb)(const u64, const u64, void *);

        struct msg_cbs transport_cbs;
        struct noise_keypair static_keys;
        struct rnd_pool rnd;

        u32 send_iter;
        struct ior_udp_send_buf send_bufs[IOR_BATCH];

        struct hash_table sessions;

        struct blake2b_ctx hash;
        struct blake2b_hmac_ctx hmac;
        struct chacha20poly1305_ctx cipher;

        struct noise_handshake noise_empty;
        struct noise_handshake noise_precomp;
};


static_assert((u32) NMP_KEYLEN == (u32) NOISE_DHLEN, "keylen");
static_assert((u32) NMP_PAYLOAD_MAX == (u32) MSG_MAX_MSGLEN, "payload");
static_assert(sizeof(struct nmp_init_payload) == NOISE_HANDSHAKE_PAYLOAD, "initiation payload");


#define header_init(type_, id_) (struct nmp_header) { \
                        .type = (type_),              \
                        .pad = {0,0,0},               \
                        .session_id = (id_)}          \



static inline struct ior_udp_send_buf *session_buf(struct nmp_session *ctx)
{
        ctx->send_iter += 1;
        return &ctx->send_bufs[ctx->send_iter & (MSG_WINDOW - 1)];
}


static i32 session_new(struct nmp_rq_connect *rq,
                       struct noise_handshake *noise,
                       struct nmp_session **new_ctx)
{
        i32 res = 0;
        u16 xfer_pl = (rq->transport_payload) ?
                      (rq->transport_payload + sizeof(struct msg_header)) :
                      (NMP_PAYLOAD_MAX + sizeof(struct msg_header));
        if (xfer_pl < 496 || xfer_pl > MSG_MAX_PAYLOAD)
                return -NMP_ERR_INVAL;

        struct chacha20poly1305_ctx c1 = {0};
        struct chacha20poly1305_ctx c2 = {0};
        struct nmp_session_init *ini = NULL;
        struct nmp_session *ctx = NULL;

        if (chacha20poly1305_init(&c1, NULL)
            || chacha20poly1305_init(&c2, NULL)) {
                res = -NMP_ERR_CRYPTO;
                goto out_fail;
        }

        ini = mem_alloc(sizeof(struct nmp_session_init));
        ctx = mem_alloc(sizeof(struct nmp_session));
        if (ini == NULL || ctx == NULL) {
                res = -NMP_ERR_MALLOC;
                goto out_fail;
        }


        mem_zero(ctx, sizeof(struct nmp_session));
        mem_zero(ini, sizeof(struct nmp_session_init));

        const u8 ka_to = rq->keepalive_timeout ?
                         rq->keepalive_timeout : NMP_KEEPALIVE_TIMEOUT;

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
        ctx->noise_key_recv = c2;
        ctx->initiation = ini;
        ini->handshake = *noise;

        /*
         * sequence numbers start at zero but msg_sequence_cmp() is a strict '>' so set
         * state counters to 0xffff, exactly one before the u16 wraps around to zero
         */
        ctx->transport.tx_seq = UINT16_MAX;
        ctx->transport.tx_ack = UINT16_MAX;
        ctx->transport.rx_seq = UINT16_MAX;
        ctx->transport.rx_delivered = UINT16_MAX;

        ctx->transport.payload_max = xfer_pl;

        *new_ctx = ctx;
        return 0;

        out_fail:
        {
                chacha20poly1305_free(&c1);
                chacha20poly1305_free(&c2);

                if (ini)
                        mem_free(ini);

                if (ctx)
                        mem_free(ctx);

                *new_ctx = NULL;
                return res;
        }
}


static void session_destroy(void *ptr)
{
        struct nmp_session *ctx = ptr;

        msg_context_wipe(&ctx->transport);
        chacha20poly1305_free(&ctx->noise_key_send);
        chacha20poly1305_free(&ctx->noise_key_recv);

        if (ctx->initiation) {
                noise_state_del(&ctx->initiation->handshake);
                mem_free(ctx->initiation);
        }

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


static i32 session_transp_send(struct nmp_instance *nmp, struct nmp_session *ctx,
                               const u8 *payload, const i32 amt, const u8 type)
{
        if (ctx->noise_cnt_send == NOISE_NONCE_MAX) {
                /*
                 * noise spec does not allow sending more than
                 * 2^64 - 1 messages for a single handshake
                 */
                const union nmp_cb_status latest = {
                        .user_data = msg_latest_acked(&ctx->transport),
                };

                session_drop(nmp, ctx, NMP_SESSION_EXPIRED, &latest);
                return 0;
        }

        struct ior_udp_send_buf *buf = session_buf(ctx);
        struct nmp_transport *pkt = ior_udp_prep_send(buf, &ctx->addr);
        const u32 pkt_len = amt + sizeof(struct nmp_transport) + NOISE_AEAD_MAC;

        pkt->type_pad_id = header_init(type, ctx->session_id);
        pkt->counter = u64le_set(ctx->noise_cnt_send);

        if (noise_encrypt(ctx->noise_key_send, ctx->noise_cnt_send,
                          pkt, sizeof(struct nmp_transport),
                          payload, amt,
                          pkt->data, pkt->data + amt))
                return -NMP_ERR_CRYPTO;

        if (ior_udp_send(&nmp->io, ctx, buf, pkt_len))
                return -NMP_ERR_IORING;

        ctx->noise_cnt_send += 1;
        ctx->stat_tx += pkt_len;
        return 0;
}


static i32 session_transp_recv(struct nmp_session *ctx,
                               u8 *packet, const u32 packet_len,
                               u8 plaintext[MSG_MAX_PAYLOAD])
{
        i32 res = 0;
        const i32 payload_len = (i32) (packet_len
                                       - sizeof(struct nmp_transport) - NOISE_AEAD_MAC);
        if (payload_len < 0 || payload_len > MSG_MAX_PAYLOAD)
                return -1;

        const struct nmp_transport *header = (const struct nmp_transport *) packet;
        u8 *ciphertext = packet + sizeof(struct nmp_transport);
        u8 *mac = ciphertext + payload_len;
        const u64 counter_remote = u64le_get(header->counter);
        const i32 block_index = noise_counter_validate(ctx->noise_cnt_block,
                                                       ctx->noise_cnt_recv,
                                                       counter_remote);
        if (block_index < 0)
                return -1;

        res = noise_decrypt(ctx->noise_key_recv, counter_remote,
                            header, sizeof(struct nmp_transport),
                            ciphertext, payload_len,
                            mac, plaintext);
        switch (res) {
        case 1:
                return -1;
        case -1:
                return -NMP_ERR_CRYPTO;
        case 0:
        default:
                break;
        }

        /* only after successful decryption */
        if (counter_remote > ctx->noise_cnt_recv) {
                i32 i = (i32) (ctx->noise_cnt_recv / 32) & 7;

                while (i != block_index) {
                        i += 1;
                        i &= 7;

                        ctx->noise_cnt_block[i] = 0;
                }

                ctx->noise_cnt_recv = counter_remote;
        }

        ctx->noise_cnt_block[block_index] |= (1u << (u32) (counter_remote & 31u));
        ctx->stat_rx += packet_len;

        return payload_len;
}


static i32 session_request(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        assert(ctx->state == SESSION_STATUS_NONE);
        assert(ctx->initiation);

        i32 res = 0;
        struct nmp_session_init *ini = ctx->initiation;
        struct ior_udp_send_buf *buf = &ini->send_buf;
        struct nmp_request *request = ior_udp_prep_send(buf, &ctx->addr);

        ini->payload.timestamp = time_get();
        if (ini->payload.timestamp == 0)
                return -NMP_ERR_TIME;

        request->header = header_init(NMP_REQUEST, ctx->session_id);
        res = noise_initiator_write(&ini->handshake, &request->initiator,
                                    request, sizeof(struct nmp_header),
                                    (u8 *) &ini->payload);
        if (res)
                return res;

        if (ior_udp_send(&nmp->io, ctx, buf,
                         sizeof(struct nmp_request)))
                return -NMP_ERR_IORING;


        ctx->state = SESSION_STATUS_RESPONSE;
        ctx->stat_tx += sizeof(struct nmp_request);
        ctx->its = ior_ts(SESSION_RETRY_INTERVAL, 0);

        return ior_timer_set(&nmp->io, &ctx->its, ctx) ?
               -NMP_ERR_IORING : 0;
}


static i32 session_response(struct nmp_instance *nmp,
                            struct nmp_session *ctx,
                            struct nmp_init_payload *payload)
{
        assert(ctx->state == SESSION_STATUS_NONE);

        i32 res = 0;
        struct nmp_session_init *ini = ctx->initiation;
        struct nmp_response *response = ior_udp_prep_send(&ini->send_buf, &ctx->addr);

        response->header = header_init(NMP_RESPONSE, ctx->session_id);
        res = noise_responder_write(&ini->handshake, &response->responder,
                                    &response->header, sizeof(struct nmp_header),
                                    (u8 *) payload);
        if (res)
                return res;

        if (ior_udp_send(&nmp->io, ctx,
                         &ini->send_buf, sizeof(struct nmp_response)))
                return -NMP_ERR_IORING;


        ctx->state = SESSION_STATUS_CONFIRM;
        ctx->stat_tx += sizeof(struct nmp_response);
        ctx->response_retries = 0;
        ctx->its = ior_ts(ctx->timer_keepalive, 0);

        return ior_timer_set(&nmp->io, &ctx->its, ctx) ?
               -NMP_ERR_IORING : 0;
}


static i32 session_data(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        /* NONE, RESPONSE, CONFIRM, WINDOW */
        if (ctx->state < SESSION_STATUS_ESTAB)
                return 0;

        u8 payload[MSG_MAX_PAYLOAD] = {0};
        i32 amt = 0;
        i32 res = 0;

        while ((amt = msg_assemble(&ctx->transport, payload))) {
                if (amt == -1) {
                        ctx->state = SESSION_STATUS_WINDOW;
                        return 0;
                }

                /*
                 * checking for zero here because if flag for full window
                 * is set then flag for ack wait is guaranteed to be set too
                 * but if its ack wait only, this condition is still relevant
                 */
                if (ctx->state == SESSION_STATUS_ESTAB) {
                        ctx->state = SESSION_STATUS_ACKWAIT;
                        ctx->its = rto_table[ctx->timer_retries];

                        if (ior_timer_upd(&nmp->io, &ctx->its, ctx))
                                return -NMP_ERR_IORING;
                }

                res = session_transp_send(nmp, ctx, payload, amt, NMP_DATA);
                if (res)
                        return res;
        }

        return 0;
}


static i32 session_data_retry(struct nmp_instance *nmp,
                              struct nmp_session *ctx)
{
        u8 payload[MSG_MAX_PAYLOAD];

        const u32 payload_len = msg_assemble_retry(&ctx->transport, payload);
        if (payload_len)
                return session_transp_send(nmp, ctx, payload,
                                           (i32) payload_len, NMP_DATA);

        return 0;
}


static i32 session_data_noack(struct nmp_instance *nmp,
                              struct nmp_session *ctx,
                              const struct msg_header *message, const u16 len)
{

        /* NONE, RESPONDER, CONFIRM mean that this context is not ready yet */
        if (ctx->state < SESSION_STATUS_WINDOW)
                return 0;

        return session_transp_send(nmp, ctx, (const u8 *) message,
                                   len, NMP_DATA);
}


static i32 session_ack(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        if (ctx->response_retries > SESSION_RETRY_RESPONSE)
                return 0;

        struct msg_ack ack;
        msg_ack_assemble(&ctx->transport, &ack);

        ctx->response_retries += 1;
        return session_transp_send(nmp, ctx, (u8 *) &ack,
                                   sizeof(struct msg_ack), NMP_ACK);
}


static i32 session_keepalive(struct nmp_instance *nmp, struct nmp_session *ctx)
{
        assert(ctx->state == SESSION_STATUS_ESTAB);
        return session_transp_send(nmp, ctx, NULL, 0, NMP_DATA);
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
        i32 res = 0;
        struct nmp_session *ctx = request->entry_arg;

        if (nmp->sessions.items > NMP_SESSIONS_MAX) {
                const union nmp_cb_status cancelled =
                        {.session_id = request->session_id};
                if (nmp->status_cb)
                        nmp->status_cb(NMP_ERR_MAXCONN, &cancelled, ctx->context_ptr);

                session_destroy(ctx);
                return 0;
        }

        if (noise_state_init(&ctx->initiation->handshake)) {
                res = -NMP_ERR_CRYPTO;
                goto out_fail;
        }

        if (ht_insert(&nmp->sessions,
                      ctx->session_id, ctx)) {
                res = -NMP_ERR_CRYPTO;
                goto out_fail;
        }

        res = session_request(nmp, ctx);
        if (res)
                goto out_fail;

        ctx->state = SESSION_STATUS_RESPONSE;
        return 0;

        out_fail:
        {
                return res;
        }
}


static i32 local_process_rq(struct nmp_instance *nmp,
                            struct nmp_rq *request)
{
        struct nmp_session *ctx = NULL;
        const enum nmp_rq_ops type = request->op;

        /* drop, data */
        if (type < NMP_OP_CONNECT) {
                ctx = ht_find(&nmp->sessions, request->session_id);
                if (ctx == HT_ERR)
                        return -NMP_ERR_CRYPTO;
        }

        switch (type) {
        case NMP_OP_SEND:
                return local_data(nmp, ctx, request);
        case NMP_OP_DROP:
                return local_drop(nmp, ctx, request);
        case NMP_OP_CONNECT:
                return local_connect(nmp, ctx, request);
        case NMP_OP_TERMINATE:
                return -NMP_STATUS_LAST;
        default:
                return -NMP_ERR_INVAL;
        }
}


static void event_local(struct nmp_instance *nmp,
                        const ior_cqe *cqe,
                        struct nmp_event *event)
{
        const i32 err = ior_cqe_err(cqe);
        if (err) {
                if (err != ENOBUFS || ior_socpair_recv(&nmp->io)) {
                        event->err = -NMP_ERR_IORING;
                }

                return;
        }

        if (ior_socpair_pbuf_get(&nmp->io, cqe, &event->buf)) {
                event->err = -NMP_ERR_IORING;
                return;
        }

        struct nmp_rq *queue = event->buf.data;
        const u32 queue_len = (event->buf.data_len / sizeof(struct nmp_rq));

        for (u32 i = 0; i < queue_len; i++) {
                event->err = local_process_rq(nmp, &queue[i]);
                if (event->err)
                        break;
        }

        ior_socpair_buf_reuse(&nmp->io, event->buf.pbuf, event->buf.bid);
}


///////////////////////////////
///     timer events        ///
///////////////////////////////


static void event_timer(struct nmp_instance *nmp,
                        const ior_cqe *cqe,
                        struct nmp_event *event)
{
        struct nmp_session *ctx = ior_cqe_data(cqe);
        if (ctx == NULL) {
                event->err = ior_timer_set(&nmp->io, &nmp->its, NULL) ?
                             -NMP_ERR_IORING : 0;
                return;
        }

        /* session has been marked for deletion */
        if (ctx->state == SESSION_STATUS_NONE) {
                /*
                 * this is safe to do here: when errors occur during processing of any
                 * network or local events the state is simply marked with SESSION_STATUS_NONE,
                 * so it does not accept any remaining events from sockets (/queues)
                 */
                session_destroy(ctx);
                return;
        }


        ctx->timer_retries += 1;

        if (ctx->timer_retries >= ctx->timer_retry_table[ctx->state]) {
                const union nmp_cb_status latest =
                        {.user_data = msg_latest_acked(&ctx->transport)};

                session_drop(nmp, ctx, NMP_SESSION_DISCONNECTED, &latest);
                session_destroy(ctx);
                return;
        }

        switch (ctx->state) {
        case SESSION_STATUS_WINDOW:
        case SESSION_STATUS_ACKWAIT:
                ctx->its = rto_table[ctx->timer_retries];
                event->err = session_data_retry(nmp, ctx);
                if (event->err)
                        return;

                break;

        case SESSION_STATUS_ESTAB:
                event->err = session_keepalive(nmp, ctx);
                if (event->err)
                        return;

                break;

        case SESSION_STATUS_RESPONSE:
                assert(ctx->initiation);

                if (ior_udp_send(&nmp->io, ctx,
                                 &ctx->initiation->send_buf,
                                 sizeof(struct nmp_request))) {
                        event->err = -NMP_ERR_IORING;
                        return;
                }

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
                return;

        default:
                event->err = -NMP_ERR_IORING;
                return;
        }


        if (nmp->stats_cb)
                nmp->stats_cb(ctx->stat_rx, ctx->stat_tx, ctx->context_ptr);

        /* reset to a previous value */
        event->err = ior_timer_set(&nmp->io, &ctx->its, ctx) ?
                     -NMP_ERR_IORING : 0;
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
        ctx->its = ior_ts(ctx->timer_keepalive, 0);
        return ior_timer_upd(&nmp->io, &ctx->its, ctx) ?
               -NMP_ERR_IORING : 0;
}


static i32 net_data(struct nmp_instance *nmp, struct nmp_session *ctx,
                    const u8 *payload, const u32 payload_len)
{
        i32 res = 0;
        if (ctx->state == SESSION_STATUS_CONFIRM) {
                res = net_data_first(nmp, ctx);
                if (res)
                        return res;
        }

        if (payload_len == 0) {
                ctx->timer_retries = 0;
                return 0;
        }

        res = msg_read(&nmp->transport_cbs,
                       &ctx->transport,
                       payload, payload_len);
        switch (res) {
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
                return res;
        }
}


static i32 net_ack(struct nmp_instance *nmp, struct nmp_session *ctx,
                   const u8 *payload, const u32 payload_len)
{
        if (payload_len != sizeof(struct msg_ack)) {
                /* this ack did not fail authentication, but we cant read it */
                session_drop(nmp, ctx, NMP_ERR_PROTOCOL, NULL);
                return 0;
        }

        /* we only want WINDOW, ESTAB & ACKWAIT here */
        if (ctx->state < SESSION_STATUS_WINDOW)
                return 0;

        const struct msg_ack *ack = (struct msg_ack *) payload;
        const i32 acks = msg_ack_read(&ctx->transport, ack);
        if (acks < 0) {
                session_drop(nmp, ctx, NMP_ERR_PROTOCOL, NULL);
                return 0;
        }

        return acks;
}


static i32 net_request_existing(struct nmp_instance *nmp,
                                struct nmp_session *ctx,
                                const struct nmp_request *request,
                                const union nmp_sa *addr)
{
        if (ctx->flags & NMP_F_ADDR_VERIFY
            && mem_cmp(&addr->sa, &ctx->addr.sa, sizeof(union nmp_sa)) != 0)
                return 0;

        if (ctx->initiation && ctx->response_retries < SESSION_RETRY_RESPONSE) {
                /* comparing to a stored copy is a cheap way to authenticate here */
                if (mem_cmp(&ctx->initiation->request_buf,
                            request, sizeof(struct nmp_request)) != 0)
                        return 0;

                if (ior_udp_send(&nmp->io, ctx,
                                 &ctx->initiation->send_buf, sizeof(struct nmp_response)))
                        return -NMP_ERR_IORING;

                ctx->response_retries += 1;
        }

        return 0;
}


static i32 net_request_accept(struct nmp_instance *nmp,
                              struct noise_handshake *handshake,
                              struct nmp_rq_connect *connect,
                              const struct nmp_request *request_save)
{
        i32 res = 0;
        struct nmp_session *ctx = NULL;
        struct nmp_init_payload response_payload = {0};
        mem_copy(response_payload.data,
                 connect->init_payload, NMP_INITIATION_PAYLOAD);

        res = session_new(connect, handshake, &ctx);
        if (res) {
                if (res == -NMP_ERR_INVAL && nmp->status_cb) {
                        const union nmp_cb_status err =
                                {.session_id = connect->id};

                        nmp->status_cb(NMP_ERR_INVAL, &err, connect->context_ptr);
                }

                return res;
        }

        res = session_response(nmp, ctx, &response_payload);
        if (res)
                goto out_fail;

        if (ht_insert(&nmp->sessions, connect->id, ctx)) {
                res = -NMP_ERR_CRYPTO;
                goto out_fail;
        }

        struct nmp_session_init *ini = ctx->initiation;
        mem_copy(&ini->request_buf,
                 request_save, sizeof(struct nmp_request));

        if (noise_split(&ini->handshake,
                        &ctx->noise_key_recv,
                        &ctx->noise_key_send)) {
                res = -NMP_ERR_CRYPTO;
                goto out_fail;
        }

        ctx->noise_cnt_recv = 0;
        ctx->noise_cnt_send = 0;
        ctx->stat_rx += sizeof(struct nmp_request);
        return 0;

        out_fail:
        {
                return res;
        }
}


static i32 net_request_respond(struct nmp_instance *nmp,
                               struct noise_handshake *handshake,
                               struct nmp_rq_connect *rq)
{
        struct nmp_init_payload response_payload = {0};
        mem_copy(response_payload.data,
                 rq->init_payload, NMP_INITIATION_PAYLOAD);

        /* ! */
        nmp->send_iter += 1;
        struct ior_udp_send_buf *buf = &nmp->send_bufs[nmp->send_iter & (IOR_BATCH - 1)];
        struct nmp_response *response = ior_udp_prep_send(buf, &rq->addr);

        response->header = header_init(NMP_RESPONSE, rq->id);
        mem_copy(response_payload.data, rq->init_payload, NMP_INITIATION_PAYLOAD);

        if (noise_responder_write(handshake, &response->responder,
                                  &response->header, sizeof(struct nmp_header),
                                  &response_payload))
                return -NMP_ERR_CRYPTO;

        return ior_udp_send(&nmp->io, nmp, /* ! */
                            buf, sizeof(struct nmp_response)) ?
               -NMP_ERR_IORING : 0;
}


static i32 net_request(struct nmp_instance *nmp,
                       const u32 id, const union nmp_sa *addr,
                       struct nmp_request *request, const u32 len)
{
        if (nmp->request_cb == NULL || nmp->sessions.items >= NMP_SESSIONS_MAX)
                return 0;

        if (len != sizeof(struct nmp_request))
                return 0;

        struct nmp_session *ctx = ht_find(&nmp->sessions, id);
        if (ctx) {
                if (ctx == HT_ERR)
                        return -NMP_ERR_CRYPTO;

                return net_request_existing(nmp, ctx, request, addr);
        }

        i32 res = 0;
        struct noise_handshake handshake = nmp->noise_precomp;
        struct nmp_rq_connect request_cb = {0};
        struct nmp_init_payload request_payload = {0};

        res = noise_initiator_read(&handshake, &request->initiator,
                                   &request->header, sizeof(struct nmp_header),
                                   (u8 *) &request_payload);
        if (res)
                return (res == 1) ? 0 : -NMP_ERR_CRYPTO;

        const u64 timestamp = time_get();
        if (timestamp == 0)
                return -NMP_ERR_TIME;

        if (timestamp >= request_payload.timestamp + SESSION_REQUEST_TTL)
                return 0;

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
                return 0;
        }
}


static i32 net_response_accept(struct nmp_instance *nmp,
                               struct nmp_session *ctx)
{
        i32 res = 0;
        struct nmp_session_init *initiation = ctx->initiation;

        ctx->noise_cnt_send = 0;
        ctx->noise_cnt_recv = 0;
        if (noise_split(&initiation->handshake,
                        &ctx->noise_key_send, &ctx->noise_key_recv))
                return -NMP_ERR_CRYPTO;

        noise_state_del(&initiation->handshake);

        mem_zero(ctx->initiation, sizeof(struct nmp_session_init));
        mem_free(ctx->initiation);
        ctx->initiation = NULL;
        ctx->stat_rx += sizeof(struct nmp_response);

        ctx->state = SESSION_STATUS_ESTAB;
        res = session_data(nmp, ctx);
        if (res)
                return res;

        if (ctx->state == SESSION_STATUS_ACKWAIT)
                return 0;

        /* no data => keepalive */
        res = session_keepalive(nmp, ctx);
        if (res)
                return res;

        ctx->its = ior_ts(ctx->timer_keepalive, 0);
        return ior_timer_upd(&nmp->io, &ctx->its, ctx) ?
               -NMP_ERR_IORING : 0;
}


static i32 net_response(struct nmp_instance *nmp,
                        const u32 session_id, const union nmp_sa *addr,
                        struct nmp_response *response, const u32 amt)
{
        if (nmp->status_cb == NULL)
                return 0;

        if (amt != sizeof(struct nmp_response))
                return 0;

        struct nmp_session *ctx = ht_find(&nmp->sessions, session_id);
        if (ctx == NULL)
                return 0;

        if (ctx == HT_ERR)
                return -NMP_ERR_CRYPTO;

        if (ctx->state != SESSION_STATUS_RESPONSE) {
                /* this also protects against duplicate responders */
                return 0;
        }

        if (ctx->flags & NMP_F_ADDR_VERIFY) {
                if (mem_cmp(&ctx->addr.sa, &addr->sa, sizeof(union nmp_sa)) != 0)
                        return 0;
        }

        i32 res = 0;
        struct nmp_init_payload reply_pl = {0};
        struct nmp_session_init *ini = ctx->initiation;

        res = noise_responder_read(&ini->handshake,
                                   &response->responder,
                                   &response->header, sizeof(struct nmp_header),
                                   (u8 *) &reply_pl);
        if (res)
                return (res == -1) ? -NMP_ERR_CRYPTO : 0;

        res = nmp->status_cb(NMP_SESSION_RESPONSE,
                             (const union nmp_cb_status *) reply_pl.data,
                             ctx->context_ptr);
        switch ((enum nmp_status) res) {
        case NMP_CMD_ACCEPT:
                return net_response_accept(nmp, ctx);

        case NMP_CMD_DROP:
                ht_remove(&nmp->sessions, ctx->session_id);
                ctx->state = SESSION_STATUS_NONE;
                return 0;

        default:
                return 0;
        }
}


static void net_collect(struct nmp_instance *nmp,
                        struct nmp_event *event)
{
        const struct nmp_header header = *((struct nmp_header *) event->buf.data);
        if (header.type & 0xfc /* 0b11111100 */
            || (header.pad[0] | header.pad[1] | header.pad[2]))
                return;

        if (header.session_id == 0)
                return;

        if (header.type < NMP_DATA) {
                switch (header.type) {
                case NMP_REQUEST:
                        event->err = net_request(nmp, header.session_id, event->buf.name,
                                                 event->buf.data, event->buf.data_len);
                        return;

                case NMP_RESPONSE:
                        event->err = net_response(nmp, header.session_id, event->buf.name,
                                                  event->buf.data, event->buf.data_len);
                        return;
                }
        }

        struct nmp_session *ctx = ht_find(&nmp->sessions, header.session_id);
        if (ctx == NULL)
                return;

        if (ctx == HT_ERR) {
                event->err = -NMP_ERR_CRYPTO;
                return;
        }

        if (ctx->flags & NMP_F_ADDR_VERIFY) {
                if (mem_cmp(&ctx->addr.sa, event->buf.name, sizeof(union nmp_sa)) != 0)
                        return;
        }

        if (event->buf.data_len % 16)
                return;

        u8 payload[MSG_MAX_PAYLOAD];
        i32 payload_msgs = 0;
        i32 payload_len = session_transp_recv(ctx, event->buf.data,
                                              event->buf.data_len, payload);
        if (payload_len < 0) {
                if (payload_len != -1)
                        event->err = payload_len;

                return;
        }

        switch (header.type) {
        case NMP_DATA:
                payload_msgs = net_data(nmp, ctx, payload, payload_len);
                if (payload_msgs <= 0) {
                        event->err = payload_msgs;
                        return;
                }

                ctx->events |= SESSION_EVENT_DATA;
                break;

        case NMP_ACK:
                if (!net_ack(nmp, ctx, payload, payload_len))
                        return;

                ctx->events |= SESSION_EVENT_ACK;
                break;
        }

        /* if there are new events && not queued yet */
        if (ctx->events && !(ctx->events & SESSION_EVENT_QUEUED)) {
                ctx->events |= SESSION_EVENT_QUEUED;
                event->ctx = ctx;
        }
}


static void event_net(struct nmp_instance *nmp,
                      const ior_cqe *cqe,
                      struct nmp_event *event)
{
        const i32 err = ior_cqe_err(cqe);
        if (err) {
                if (err != ENOBUFS || ior_udp_recv(&nmp->io))
                        event->err = -NMP_ERR_IORING;

                return;
        }

        if (ior_udp_pbuf_get(&nmp->io, cqe, &event->buf)) {
                event->err = -NMP_ERR_IORING;
                return;
        }

        if (event->buf.data)
                net_collect(nmp, event);

        ior_udp_pbuf_reuse(&nmp->io, event->buf.pbuf, event->buf.bid);
}



///////////////////////////
///     public api      ///
///////////////////////////


static i32 nmp_teardown(struct nmp_instance *nmp)
{
        ior_teardown(&nmp->io);
        ht_teardown(&nmp->sessions, session_destroy);

        if (nmp->local_tx != -1)
                close(nmp->local_tx);

        blake2b_free(&nmp->hash);
        blake2b_hmac_free(&nmp->hmac);
        chacha20poly1305_free(&nmp->cipher);

        mem_zero(nmp, sizeof(struct nmp_instance));
        mem_free(nmp);

        return -NMP_STATUS_LAST;
}


static i32 new_base(struct nmp_instance *nmp, struct nmp_conf *conf)
{
        const sa_family_t sa_family = conf->addr.sa.sa_family ?
                                      conf->addr.sa.sa_family : AF_INET;
        if (sa_family != AF_INET && sa_family != AF_INET6)
                return -NMP_ERR_INVAL;

        nmp->sa_family = sa_family;

        nmp->request_ctx = conf->request_ctx;
        nmp->request_cb = conf->request_cb;
        nmp->status_cb = conf->status_cb;
        nmp->stats_cb = conf->stats_cb;

        nmp->transport_cbs.data = conf->data_cb;
        nmp->transport_cbs.data_noack = conf->data_noack_cb;
        nmp->transport_cbs.ack = conf->ack_cb;

        u8 ht_key[SIPHASH_KEY] = {0};
        if (rnd_get(ht_key, SIPHASH_KEY))
                return -NMP_ERR_RND;

        return (ht_init(&nmp->sessions, ht_key)) ?
               -NMP_ERR_CRYPTO : 0;
}


static i32 new_ior(struct nmp_instance *nmp, struct nmp_conf *conf)
{
        UNUSED(conf);

        const int udp = socket(nmp->sa_family, SOCK_DGRAM, 0);
        if (udp == -1)
                return -NMP_ERR_SOCKET;

        if (bind(udp, &conf->addr.sa, sizeof(union nmp_sa)))
                return -NMP_ERR_BIND;

        socklen_t sa_len = sizeof(union nmp_sa);
        if (getsockname(udp, &conf->addr.sa, &sa_len))
                return -NMP_ERR_GETSOCKNAME;

        int sp[2] = {0};
        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp))
                return -NMP_ERR_SOCKPAIR;

        if (ior_setup(&nmp->io, udp, sp[0]))
                return -NMP_ERR_IORING;

        nmp->local_tx = sp[1];
        return 0;
}


static i32 new_crypto(struct nmp_instance *nmp, struct nmp_conf *conf)
{
        if (rnd_reset_pool(&nmp->rnd))
                return -NMP_ERR_RND;

        if (blake2b_init(&nmp->hash))
                return -NMP_ERR_CRYPTO;

        if (blake2b_hmac_init(&nmp->hmac))
                return -NMP_ERR_CRYPTO;

        if (chacha20poly1305_init(&nmp->cipher, NULL))
                return -NMP_ERR_CRYPTO;

        if (noise_keypair_initialize(&nmp->static_keys, conf->key))
                return -NMP_ERR_CRYPTO;


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
                return -NMP_ERR_CRYPTO;


        mem_copy(conf->pubkey, nmp->static_keys.pub_raw, NOISE_DHLEN);
        return 0;
}


struct nmp_instance *nmp_new(struct nmp_conf *conf)
{
        i32 res = 0;
        if (conf == NULL)
                return NULL;

        nmp_t *tmp = mem_alloc(sizeof(struct nmp_instance));
        if (tmp == NULL) {
                conf->err = -NMP_ERR_MALLOC;
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
        tmp->local_tx = -1;

        res = new_base(tmp, conf);
        if (res)
                goto out_fail;

        res = new_ior(tmp, conf);
        if (res)
                goto out_fail;

        res = new_crypto(tmp, conf);
        if (res)
                goto out_fail;


        if (ior_udp_recv(&tmp->io) || ior_socpair_recv(&tmp->io))
                goto out_fail;


        conf->err = 0;
        return tmp;
        out_fail:
        {
                nmp_teardown(tmp);
                conf->err = -res;
                return NULL;
        }
}


static i32 submit_connect(struct nmp_instance *nmp, struct nmp_rq *rq)
{
        UNUSED(nmp);
        struct nmp_session *session = NULL;
        struct nmp_rq_connect *connect = rq->entry_arg;
        i32 res = 0;

        if (connect->addr.sa.sa_family != nmp->sa_family)
                return -NMP_ERR_INVAL;

        connect->id = rnd_get32();
        if (connect->id == 0)
                return -NMP_ERR_RND;

        res = session_new(connect, &nmp->noise_empty, &session);
        if (res)
                return res;

        mem_copy(session->initiation->handshake.rs,
                 connect->pubkey, NMP_KEYLEN);

        mem_copy(session->initiation->payload.data,
                 connect->init_payload, NMP_INITIATION_PAYLOAD);

        rq->session_id = connect->id;
        rq->entry_arg = session;
        return 0;
}


static bool submit_validate_send(const struct nmp_rq *send)
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
                return -NMP_ERR_INVAL;

        struct msg_header *buf = mem_alloc(MSG_MAX_PAYLOAD);
        if (buf == NULL)
                return -NMP_ERR_MALLOC;

        rq->len = msg_assemble_noack(buf, rq->entry_arg, rq->len);
        rq->entry_arg = buf;

        return 0;
}


static i32 submit_send(struct nmp_instance *nmp, struct nmp_rq *rq)
{
        UNUSED(nmp);
        if (submit_validate_send(rq))
                return -NMP_ERR_INVAL;

        if (rq->msg_flags & NMP_F_MSG_NOACK)
                return submit_send_noack(nmp, rq);

        if ((rq->msg_flags & NMP_F_MSG_NOALLOC) == 0) {
                u8 *buf = mem_alloc(MSG_MAX_PAYLOAD);
                if (buf == NULL)
                        return -NMP_ERR_MALLOC;

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
                        err = -NMP_ERR_INVAL;
                        break;
                }

                if (err) {
                        submit_cleanup(rqs, i);
                        return -err;
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
        i32 res = 0;

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
                msg_deliver_data(&nmp->transport_cbs,
                                 &ctx->transport);

                res = session_ack(nmp, ctx);
                if (res)
                        return res;

                /* only packets that contain new messages reset this counter */
                ctx->response_retries = 0;
        }

        if (ctx->events & SESSION_EVENT_ACK) {
                switch (msg_deliver_ack(&nmp->transport_cbs,
                                        &ctx->transport)) {
                case 0:
                        break;

                case -1:
                        /* everything has been acked */
                        ctx->state = SESSION_STATUS_ESTAB;
                        ctx->its = ior_ts(ctx->timer_keepalive, 0);

                        if (ior_timer_upd(&nmp->io, &ctx->its, ctx))
                                return -NMP_ERR_IORING;

                        break;

                default:
                        /*
                         * if this ack contained any new messages, trigger
                         * data transmission to fill the window back up
                         */
                        ctx->state = SESSION_STATUS_ACKWAIT;
                        res = session_data(nmp, ctx);
                        if (res)
                                return res;

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


static i32 run_process_err(struct nmp_instance *nmp,
                           const ior_cqe *cqe)
{
        struct nmp_session *ctx = ior_cqe_data(cqe);
        const i32 err = ior_cqe_err(cqe);
        if (err == 0)
                return -NMP_ERR_IORING;


        switch (err) {
        case ECANCELED: /* timers */
                return 0;

        case ENOENT: /* timers */
                return ior_timer_set(&nmp->io, &ctx->its, ctx) ?
                       -NMP_ERR_IORING : 0;

        case EACCES: /* sendmsg */
        case EPERM:
        case ENETUNREACH:
        case ENETDOWN:
                if (ctx == NULL) {
                        /* discard error of CMD_RESPOND, no owner */
                        return 0;
                }

                if (ctx->state == SESSION_STATUS_NONE)
                        return 0;

                const union nmp_cb_status perm = {
                        .addr = ctx->addr,
                };

                errno = err;
                if (nmp->status_cb &&
                    nmp->status_cb(NMP_ERR_SEND, &perm, ctx->context_ptr) == NMP_CMD_DROP) {
                        ht_remove(&nmp->sessions, ctx->session_id);
                        ctx->state = SESSION_STATUS_NONE;
                }

                return 0;

        default:
                break;
        }

        return -NMP_ERR_IORING;
}


static i32 run_process_batch(struct nmp_instance *nmp,
                             struct nmp_session **queue)
{
        ior_cqe *cqe = NULL;
        u32 head = 0;
        u32 cqes = 0;
        i32 items = 0;

        ior_for_each_cqe(&nmp->io.ring, head, cqe) {
                struct nmp_event event = {0};

                switch (ior_cqe_kind(&nmp->io, cqe)) {
                case IOR_CQE_UDP:
                        event_net(nmp, cqe, &event);
                        break;

                case IOR_CQE_SP:
                        event_local(nmp, cqe, &event);
                        break;

                case IOR_CQE_TIMER:
                        event_timer(nmp, cqe, &event);
                        break;

                default:
                        event.err = run_process_err(nmp, cqe);
                        break;
                }

                if (event.err)
                        return event.err;

                if (event.ctx) {
                        queue[items] = event.ctx;
                        items += 1;
                }

                cqes += 1;
                if (items == IOR_BATCH)
                        break;
        }

        ior_cq_advance(&nmp->io, cqes);
        return items;
}


i32 nmp_run(struct nmp_instance *nmp, const u32 timeout)
{
        i32 queued = 0;
        i32 res = 0;
        struct nmp_session *events_queue[IOR_BATCH] = {0};

        if (timeout) {
                nmp->its = ior_ts(0, timeout);
                if (ior_timer_set(&nmp->io, &nmp->its, NULL))
                        return NMP_ERR_IORING;
        }

        for (;;) {
                if (ior_wait_cqe(&nmp->io))
                        return NMP_ERR_IORING;

                queued = run_process_batch(nmp, events_queue);
                if (queued < 0)
                        break;

                for (i32 i = 0; i < queued; i++) {
                        res = run_events_deliver(nmp, events_queue[i]);
                        if (res)
                                return -res;
                }
        }

        res = -queued;
        if (res == NMP_STATUS_LAST)
                return -nmp_teardown(nmp);

        assert(res > NMP_ERR_SEND);
        return res;
}
