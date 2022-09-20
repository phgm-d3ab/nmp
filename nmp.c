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
#include <openssl/evperr.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>


typedef uint8_t u8;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef uint64_t u64;
typedef ssize_t isize;

// library debug features
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
        {   char timestr__[32] = {0};                                           \
            __log_timestamp(timestr__);                                         \
            dprintf(STDERR_FILENO, "[%s][nmp][%s():%u] " fmt__ "\n", timestr__, \
                __FUNCTION__, __LINE__, ##__VA_ARGS__); } while(0)              \


#   define log(fmt_, ...)   __log(fmt_, ##__VA_ARGS__)
#   define log_errno()      log("%s", strerrordesc_np(errno))


// make logs a bit more readable
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

#else // NMP_DEBUG

#   define log(...)
#   define log_errno()

#endif // NMP_DEBUG


#define UNUSED(arg_)    ((void)(arg_))


// cosmetics mainly
#define mem_alloc(size_)                malloc(size_)
#define mem_free(ptr_)                  free(ptr_)
#define mem_zero(ptr_, len_)            memset(ptr_, 0, len_)
#define mem_copy(dest_, src_, len_)     memcpy(dest_, src_, len_)
#define mem_cmp(buf1_, buf2_, len_)     memcmp(buf1_, buf2_, len_)



/*
 *  time
 */
static u64 time_get()
{
    struct timespec ts = {0};
    if (clock_gettime(CLOCK_TAI, &ts))
    {
        log_errno();
        return 0;
    }

    return (u64) (ts.tv_sec * 1000ll + ts.tv_nsec / 1000000ll);
}


/*
 *  randomness
 */
static u32 rnd_get(void *output, const u32 amt)
{
    while (getrandom(output, amt, 0) != amt)
    {
        log_errno();

        // none of this ever happens
        // but lets check anyway
        switch (errno)
        {
            case EINTR:
                continue;

            default:
                return 1;
        }
    }

    return 0;
}


static u32 rnd_get32()
{
    u32 tmp = 0;

    while (!tmp)
    {
        if (rnd_get(&tmp, sizeof(u32)))
        {
            return 0;
        }
    }

    return tmp;
}


/*
 *  https://en.wikipedia.org/wiki/SipHash
 */
#define SIPHASH_KEY 16
#define SIPHASH_C 2
#define SIPHASH_D 4

#define rotl64(x, n) ((u64)((x) << (n)) | ((x) >> (-(n) & 63)))

#define u8_u64le(x)           \
(                             \
    ((u64) (x)[0]        |    \
    ((u64) (x)[1] << 8)  |    \
    ((u64) (x)[2] << 16) |    \
    ((u64) (x)[3] << 24) |    \
    ((u64) (x)[4] << 32) |    \
    ((u64) (x)[5] << 40) |    \
    ((u64) (x)[6] << 48) |    \
    ((u64) (x)[7] << 56) )    \
)


static inline void sip_round(u64 v[4])
{
    v[0] += v[1];
    v[1] = rotl64(v[1], 13);
    v[1] ^= v[0];
    v[0] = rotl64(v[0], 32);
    v[2] += v[3];
    v[3] = rotl64(v[3], 16);
    v[3] ^= v[2];

    v[0] += v[3];
    v[3] = rotl64(v[3], 21);
    v[3] ^= v[0];

    v[2] += v[1];
    v[1] = rotl64(v[1], 17);
    v[1] ^= v[2];
    v[2] = rotl64(v[2], 32);
}


static u64 siphash(const u8 *key, const u8 *data, const u32 len)
{
    const u64 k0 = u8_u64le((key));
    const u64 k1 = u8_u64le((key + 8));

    u64 v[4] =
            {
                    k0 ^ 0x736f6d6570736575,
                    k1 ^ 0x646f72616e646f6d,
                    k0 ^ 0x6c7967656e657261,
                    k1 ^ 0x7465646279746573,
            };


    const u32 len_aligned = len & ~7;
    const u32 len_remainder = len - len_aligned;

    for (u32 i = 0; i < len_aligned; i += 8)
    {
        const u64 m = u8_u64le((data + i));

        v[3] ^= m;

        for (u32 n = 0; n < SIPHASH_C; n++)
        {
            sip_round(v);
        }

        v[0] ^= m;
    }

    u64 remainder = (u64) (len & 0xff) << 56;
    if (len_remainder)
    {
        data += len_aligned;

        for (u32 i = 0; i < len_remainder; i++)
        {
            remainder |= (u64) data[i] << (i * 8);
        }
    }

    v[3] ^= remainder;

    for (u32 n = 0; n < SIPHASH_C; n++)
    {
        sip_round(v);
    }

    v[0] ^= remainder;

    v[2] ^= 0xff;

    for (u32 i = 0; i < SIPHASH_D; i++)
    {
        sip_round(v);
    }

    return (v[0] ^ v[1] ^ v[2] ^ v[3]);
}


/*
 *  https://en.wikipedia.org/wiki/Open_addressing
 *  https://en.wikipedia.org/wiki/Lazy_deletion
 */
#define HASH_TABLE_SIZE     NMP_SESSIONS
#define HASH_TABLE_RS       (HASH_TABLE_SIZE * 2) // real size
#define HASH_TABLE_NF       (HASH_TABLE_SIZE + 1) // not found
#define HASH_TABLE_CACHE    (HASH_TABLE_SIZE / 8)

static_assert((HASH_TABLE_SIZE & (HASH_TABLE_SIZE - 1)) == 0,
              "hash table size must be a power of two");


struct hash_table
{
    u32 items;
    u8 key[SIPHASH_KEY];

    struct
    {
        u32 id;
        u64 hash;

    } cache[HASH_TABLE_CACHE];

    struct
    {
        enum
        {
            entry_empty = 0,
            entry_deleted = 1,
            entry_occupied = 2,

        } status;

        u32 id;
        void *ptr;

    } entry[HASH_TABLE_RS];
};


static u64 hash_table_hash(struct hash_table *ht, const u32 key)
{
    const u32 index = key & (HASH_TABLE_CACHE - 1);
    if (ht->cache[index].id == key)
        return ht->cache[index].hash;

    const u64 hash = siphash(ht->key, (const u8 *) &key, sizeof(u32));
    ht->cache[index].id = key;
    ht->cache[index].hash = hash;

    return hash;
}


static u32 hash_table_slot(struct hash_table *ht, const u64 hash, const u32 item)
{
    const u32 natural_slot = (u32) hash & (HASH_TABLE_RS - 1);

    u32 index = HASH_TABLE_NF;
    u32 index_swap = HASH_TABLE_NF;

    for (u32 i = 0; i < HASH_TABLE_RS; i++)
    {
        index = (natural_slot + i) & (HASH_TABLE_RS - 1);
        if (ht->entry[index].id == item)
            break;

        if (ht->entry[index].status == entry_deleted)
        {
            if (index_swap == HASH_TABLE_NF)
                index_swap = index;

            continue;
        }

        if (ht->entry[index].status == entry_empty)
            break;
    }

    if (index_swap != HASH_TABLE_NF)
    {
        ht->entry[index_swap].status = entry_occupied;
        ht->entry[index_swap].id = ht->entry[index].id;
        ht->entry[index_swap].ptr = ht->entry[index].ptr;

        ht->entry[index].status = entry_deleted;
        ht->entry[index].id = 0;
        ht->entry[index].ptr = NULL;
    }

    return index;
}


static void *hash_table_lookup(struct hash_table *ht, const u32 id)
{
    const u64 hash = hash_table_hash(ht, id);
    const u32 slot = hash_table_slot(ht, hash, id);

    if (slot == HASH_TABLE_NF || ht->entry[slot].id != id)
        return NULL;

    return ht->entry[slot].ptr;
}


static u32 hash_table_insert(struct hash_table *ht, const u32 id, void *ptr)
{
    if (ht->items >= HASH_TABLE_SIZE)
        return 1;

    const u64 hash = hash_table_hash(ht, id);
    const u32 natural_slot = (u32) hash & (HASH_TABLE_RS - 1);

    for (u32 i = 0; i < HASH_TABLE_RS; i++)
    {
        const u32 index = (natural_slot + i) & (HASH_TABLE_RS - 1);
        if (ht->entry[index].status < entry_occupied)
        {
            ht->entry[index].status = entry_occupied;
            ht->entry[index].id = id;
            ht->entry[index].ptr = ptr;

            ht->items += 1;
            return 0;
        }
    }

    return 1;
}


static void hash_table_remove(struct hash_table *ht, const u32 id)
{
    const u64 hash = hash_table_hash(ht, id);
    const u32 natural_slot = (u32) hash & (HASH_TABLE_RS - 1);

    for (u32 i = 0; i < HASH_TABLE_RS; i++)
    {
        const u32 index = (natural_slot + i) & (HASH_TABLE_RS - 1);
        if (ht->entry[index].id == id)
        {
            ht->entry[index].status = entry_deleted;
            ht->entry[index].id = 0;
            ht->entry[index].ptr = NULL;

            ht->items -= 1;
            break;
        }
    }
}


static i32 hash_table_wipe(struct hash_table *ht, u32 (*destructor)(void *))
{
    for (u32 i = 0; ht->items && i < HASH_TABLE_RS; i++)
    {
        if (ht->entry[i].ptr)
        {
            destructor(ht->entry[i].ptr);
            ht->items -= 1;
        }
    }

    return 0;
}



/*
 *
 */
#define MSG_MASK_BITS       64
#define MSG_MASK_INIT       UINT64_MAX
#define MSG_WINDOW          64
#define MSG_TXQUEUE         NMP_QUEUE
#define MSG_RXQUEUE         MSG_MASK_BITS
#define MSG_MAX_SINGLE      1404
#define MSG_MAX_PAYLOAD     1408

// these are the flags for message header length field
#define MSG_NOACK       ((u16)(1 << 15))
#define MSG_RESERVED    ((u16)(1 << 14))


enum msg_status
{
    MSG_TX_EMPTY = 0,
    MSG_TX_SENT = 1,
    MSG_TX_QUEUED = 2,
    MSG_TX_ACKED = 3,

    MSG_RX_EMPTY = 0,
    MSG_RX_RECEIVED = 1,
};


// payload message
struct msg_header
{
    u16 sequence;
    u16 len;
    u8 data[];
};


// acknowledgement packet
struct msg_ack
{
    u16 ack;
    u16 pad[3];
    u64 ack_mask;
};


struct msg_tx
{
    enum msg_status status;
    u16 seq;
    u16 len;
    u64 id;
    u8 *msg;
};


struct msg_rx
{
    enum msg_status status;
    u16 seq;
    u16 len;
    u8 data[MSG_MAX_SINGLE];
};


struct msg_routines
{
    void (*data)(const u8 *, u32, void *);
    void (*data_noack)(const u8 *, u32, void *);
    void (*ack)(u64, void *);
};


struct msg_state
{
    void *context_ptr;

    u16 tx_seq;
    u16 tx_sent;
    u16 tx_ack;
    u64 tx_counter;

    u16 rx_seq;
    u16 rx_delivered;

    struct msg_tx tx_queue[MSG_TXQUEUE];
    struct msg_rx rx_buffer[MSG_RXQUEUE];
};


// convenience: get a pointer to entry by sequence number
#define tx_get(ctx_, n_) ((ctx_)->tx_queue + ((n_) & (MSG_TXQUEUE - 1)))
#define rx_get(ctx_, n_) ((ctx_)->rx_buffer + ((n_) & (MSG_RXQUEUE - 1)))

// tx_get() and rx_get() require precautions
static_assert((MSG_TXQUEUE & (MSG_TXQUEUE - 1)) == 0, "MSG_TXQUEUE must be a power of two");
static_assert((MSG_RXQUEUE & (MSG_RXQUEUE - 1)) == 0, "MSG_RXQUEUE must be a power of two");


/*
 *  compare sequence numbers:
 *  cover for 'wraparound'
 */
static inline i32 msg_sequence_cmp(const u16 a, const u16 b)
{
    return ((a <= b) ? ((b - a) > 0xff) : ((a - b) < 0xff));
}


/*
 *  zero pad payload, make total length multiple of 16
 */
static inline i32 msg_payload_zeropad(u8 *payload, const i32 len)
{
    const i32 padding = (16 - len) & 15;
    const i32 payload_len = len + padding;

    for (i32 i = 0; i < padding; i++)
    {
        payload[len + i] = 0;
    }

    assert(payload_len <= MSG_MAX_PAYLOAD);
    return payload_len;
}


static inline void msg_tx_include(const struct msg_tx *tx,
                                  struct msg_header *msg)
{
    msg->sequence = tx->seq;
    msg->len = tx->len;

    mem_copy(msg->data, tx->msg, tx->len);
    log("seq %u %s", msg->sequence, nmp_dbg_msg_status[tx->status]);
}


static inline void msg_rx_copy(struct msg_rx *entry,
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
    return tx_get(ctx, ctx->tx_ack)->id;
}


/*
 *  simply free() remaining messages
 *  that were not acknowledged yet
 */
static void msg_context_wipe(struct msg_state *ctx)
{
    for (u16 i = ctx->tx_ack;; i++)
    {
        struct msg_tx *entry = tx_get(ctx, i);
        if (entry->status != MSG_TX_EMPTY)
            mem_free(entry->msg);

        if (i == ctx->tx_seq)
            break;
    }
}


/*
 *
 */
static u32 msg_queue(struct msg_state *ctx, const u8 *msg, const u16 len)
{
    assert(msg);

    // pre-increment: check one ahead
    const u32 index = (ctx->tx_seq + 1) & (MSG_TXQUEUE - 1);
    struct msg_tx *entry = ctx->tx_queue + index;

    if (entry->status > MSG_TX_SENT)
    {
        log("cannot queue new msg");
        return 1;
    }

    ctx->tx_seq += 1;

    entry->status = MSG_TX_QUEUED;
    entry->seq = ctx->tx_seq;
    entry->msg = (u8 *) msg;
    entry->len = len;
    entry->id = ctx->tx_counter;

    ctx->tx_counter += 1;
    return 0;
}


/*
 *  gather messages into payload
 *  returns number of bytes in payload
 */
static i32 msg_assemble(struct msg_state *ctx,
                        u8 output[MSG_MAX_PAYLOAD], const u32 payload_limit)
{
    struct msg_tx *resend_queue[MSG_WINDOW] = {0};
    u32 resend_amt = 0;
    u32 bytes = 0;

    // plus one as queuing messages is pre-incremented,
    // and we want to look at the first fresh item
    const u16 seq_lo = ctx->tx_ack + 1;
    const u16 seq_hi = seq_lo + MSG_WINDOW;

    if (ctx->tx_ack + MSG_WINDOW == ctx->tx_sent)
    {
        // cannot send any fresh messages
        return -1;
    }

    for (u16 i = seq_lo; i != seq_hi; i++)
    {
        struct msg_tx *msg = tx_get(ctx, i);
        if (msg->status == MSG_TX_EMPTY)
        {
            // end of queue
            break;
        }

        if (msg->status == MSG_TX_SENT)
        {
            resend_queue[resend_amt] = msg;
            resend_amt += 1;
            continue;
        }

        if (msg->status == MSG_TX_QUEUED)
        {
            const u32 offset = msg->len + sizeof(struct msg_header);
            if (bytes + offset > payload_limit)
            {
                break;
            }

            msg_tx_include(msg, (struct msg_header *) (output + bytes));

            bytes += offset;
            msg->status = MSG_TX_SENT;
            ctx->tx_sent = msg->seq;
        }
    }

    if (bytes == 0)
    {
        return 0;
    }

    for (u32 i = 0; i < resend_amt; i++)
    {
        const u16 offset = resend_queue[i]->len + sizeof(struct msg_header);
        if (bytes + offset > payload_limit)
        {
            break;
        }

        msg_tx_include(resend_queue[i], (struct msg_header *) (output + bytes));
        bytes += offset;
    }

    return msg_payload_zeropad(output, (i32) bytes);
}


static u32 msg_assemble_retry(struct msg_state *ctx,
                              u8 *output, const u32 payload_limit)
{
    u32 bytes = 0;

    for (u16 i = ctx->tx_ack + 1;; i++)
    {
        struct msg_tx *msg = tx_get(ctx, i);
        if (msg->status == MSG_TX_SENT)
        {
            const u16 offset = msg->len + sizeof(struct msg_header);
            if (bytes + offset > payload_limit)
                break;

            msg_tx_include(msg, (struct msg_header *) (output + bytes));
            bytes += offset;
        }

        if (i == ctx->tx_sent)
            break;
    }

    return (u32) msg_payload_zeropad(output, (i32) bytes);
}

/*
 *  build a noack message in-place
 */
u32 msg_assemble_noack(struct msg_header *header,
                       const u8 *payload, const u16 len)
{
    header->sequence = 0;
    header->len = len;
    header->len |= MSG_NOACK;

    mem_copy(header->data, payload, len);
    return msg_payload_zeropad(header->data, (i32) (len + sizeof(struct msg_header)));
}


/*
 *  return number of new messages
 */
static i32 msg_read(const struct msg_routines *cb, struct msg_state *ctx,
                    const u8 *payload, const u32 len)
{
    u32 iterator = 0;
    i32 new_messages = 0;
    u32 discovered = 0;

    const u16 seq_low = ctx->rx_delivered;
    const u16 seq_high = (u16) (seq_low + MSG_WINDOW);

    for (;; discovered++)
    {
        const struct msg_header *msg = (const struct msg_header *) (payload + iterator);
        if ((len - iterator) <= sizeof(struct msg_header))
            break;

        if (msg->len == 0)
            break;

        const u16 msg_len = msg->len & ~(MSG_NOACK | MSG_RESERVED);
        // example: msg->len == 1000 but there are 100 bytes left
        // to read in the packet; lets have a protection against this
        const u16 msg_maxlen = (u16) (len - iterator - sizeof(struct msg_header));
        if (msg_len > msg_maxlen)
        {
            log("rejecting message size");
            return -1;
        }

        if (msg->len & MSG_NOACK)
        {
            // mixing regular and noack messages is not allowed
            if (discovered)
            {
                log("broken format");
                return -1;
            }

            if (cb->data_noack)
                cb->data_noack(msg->data, msg->len, ctx->context_ptr);

            return (MSG_WINDOW + 1);
        }

        if (msg->len & MSG_RESERVED)
        { /* not used for now */ }


        // no point processing anything below latest delivered
        if (msg_sequence_cmp(msg->sequence, seq_low))
        {
            // detect message with sequence number higher
            // than latest acked (from our side) + MSG_WINDOW
            if (msg_sequence_cmp(msg->sequence, seq_high))
            {
                log("rejecting sequence %u over %u",
                    msg->sequence, seq_high);

                return -1;
            }

            if (msg_sequence_cmp(msg->sequence, ctx->rx_seq))
                ctx->rx_seq = msg->sequence;

            struct msg_rx *entry = rx_get(ctx, msg->sequence);
            if (entry->status == MSG_RX_EMPTY)
            {
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
    for (u16 n = ctx->rx_delivered + 1;; n++)
    {
        struct msg_rx *entry = rx_get(ctx, n);
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
static u32 msg_ack_assemble(const struct msg_state *ctx, struct msg_ack *ack)
{
    u64 mask = MSG_MASK_INIT;
    u32 shift = 0;
    const u16 seq_hi = ctx->rx_seq;
    const u16 seq_lo = ctx->rx_delivered;

    for (u16 i = seq_hi;; i--)
    {
        if (i == seq_lo)
        {
            // it is important not to go back beyond
            // seq_lo: those are guaranteed to be processed
            // so any state modifications will break the logic
            break;
        }

        const struct msg_rx *entry = rx_get(ctx, i);
        if (entry->status == MSG_RX_EMPTY)
        {
            log("clearing bit %u for seq %u", i, entry->seq);
            mask &= ~(1u << shift);
        }

        assert(shift <= MSG_WINDOW);
        shift += 1;
    }

    ack->ack = seq_hi;
    ack->pad[0] = 0;
    ack->pad[1] = 0;
    ack->pad[2] = 0;
    ack->ack_mask = mask;

    return 1;
}


/*
 *
 */
static i32 msg_ack_read(struct msg_state *ctx, const struct msg_ack *ack)
{
    i32 discovered = 0;
    u64 mask = ack->ack_mask;


    if (msg_sequence_cmp(ack->ack, ctx->tx_ack))
    {
        if (msg_sequence_cmp(ack->ack, ctx->tx_sent))
        {
            // remote peer tries to send ack for something
            // we did not send yet, cannot have this
            log("rejecting ack %u (sent %u)",
                ack->ack, ctx->tx_sent);

            return -1;
        }

        if ((mask & 1) == 0)
        {
            // first bit corresponds to current ack
            // sequence, it is always set
            return -1;
        }

        for (u16 i = ack->ack;; i--)
        {
            if (mask & 1)
            {
                struct msg_tx *msg = tx_get(ctx, i);
                if (msg->status == MSG_TX_SENT)
                {
                    log("acked %u", msg->seq);

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


/*
 *
 */
static i32 msg_deliver_ack(const struct msg_routines *cb,
                           struct msg_state *ctx)
{
    i32 counter = 0;

    // plus one: tx_ack is the number of a processed
    // message, start with the next one
    for (u16 i = ctx->tx_ack + 1;; i++)
    {
        struct msg_tx *msg = tx_get(ctx, i);
        if (msg->status != MSG_TX_ACKED)
            break;

        if (cb->ack)
            cb->ack(msg->id, ctx->context_ptr);

        mem_free(msg->msg);
        msg->status = MSG_TX_EMPTY;

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
#define NOISE_KEYLEN            32
#define NOISE_HASHLEN           64
#define NOISE_DHLEN             56
#define NOISE_AEAD_MAC          16
#define NOISE_NONCE_MAX         UINT64_MAX
#define NOISE_HANDSHAKE_PAYLOAD 128

#define NOISE_COUNTER_WINDOW    224


// "Noise_IK_448_ChaChaPoly_BLAKE2b" padded
// with zeros to be NOISE_HASHLEN long
const u8 noise_protocol_name[NOISE_HASHLEN] =
        {
                0x4e, 0x6f, 0x69, 0x73, 0x65, 0x5f, 0x49, 0x4b,
                0x5f, 0x34, 0x34, 0x38, 0x5f, 0x43, 0x68, 0x61,
                0x43, 0x68, 0x61, 0x50, 0x6f, 0x6c, 0x79, 0x5f,
                0x42, 0x4c, 0x41, 0x4b, 0x45, 0x32, 0x62, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        };


struct noise_initiator
{
    u8 ephemeral[NOISE_DHLEN];
    u8 encrypted_static[NOISE_DHLEN];
    u8 mac1[NOISE_AEAD_MAC];
    u8 encrypted_payload[NOISE_HANDSHAKE_PAYLOAD];
    u8 mac2[NOISE_AEAD_MAC];
};


struct noise_responder
{
    u8 ephemeral[NOISE_DHLEN];
    u8 encrypted_payload[NOISE_HANDSHAKE_PAYLOAD];
    u8 mac[NOISE_AEAD_MAC];
};


struct noise_keypair
{
    EVP_PKEY *evp_priv;
    EVP_PKEY_CTX *evp_dh;
    u8 public[NOISE_DHLEN];
};


struct noise_handshake
{
    HMAC_CTX *evp_hmac;
    EVP_MD_CTX *evp_md;
    EVP_CIPHER_CTX *evp_cipher;

    u8 cipher_k[NOISE_KEYLEN];
    u64 cipher_n;
    u8 symmetric_ck[NOISE_HASHLEN];
    u8 symmetric_h[NOISE_HASHLEN];

    struct noise_keypair *s;
    struct noise_keypair e;
    u8 rs[NOISE_DHLEN];
    u8 re[NOISE_DHLEN];
};


static u32 noise_hash(EVP_MD_CTX *md,
                      const void *data, const u32 data_len,
                      u8 output[NOISE_HASHLEN])
{
    if (EVP_MD_CTX_reset(md) != 1)
        return 1;

    if (EVP_DigestInit_ex(md, EVP_blake2b512(), NULL) != 1)
        return 1;

    if (EVP_DigestUpdate(md, data, data_len) != 1)
        return 1;

    if (EVP_DigestFinal_ex(md, output, NULL) != 1)
        return 1;

    return 0;
}


static inline u32 noise_hmac_hash(HMAC_CTX *hmac,
                                  const u8 key[NOISE_HASHLEN],
                                  const void *data, const u32 data_len,
                                  u8 output[NOISE_HASHLEN])
{
    if (HMAC_Init_ex(hmac, key, NOISE_HASHLEN, EVP_blake2b512(), NULL) != 1)
        return 1;

    if (HMAC_Update(hmac, data, data_len) != 1)
        return 1;

    if (HMAC_Final(hmac, output, NULL) != 1)
        return 1;

    return 0;
}


// noise spec has third output, but it is not used
// in this handshake pattern so not included here
static u32 noise_hkdf(HMAC_CTX *hmac, const u8 *ck,
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
    buf2[NOISE_HASHLEN] = 0x02; // h || byte(0x02)
    if (noise_hmac_hash(hmac, temp_key,
                        buf2, (NOISE_HASHLEN + sizeof(u8)),
                        output2))
        return 1;

    return 0;
}


static inline u32 noise_dh(EVP_MD_CTX *evp_md,
                           const struct noise_keypair *key_pair,
                           const u8 *public_key,
                           u8 shared_secret[NOISE_DHLEN])
{
    u64 dhlen = NOISE_DHLEN;
    u8 temp[NOISE_DHLEN] = {0};
    EVP_PKEY *remote_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X448, NULL,
                                                       public_key, NOISE_DHLEN);
    if (remote_pub == NULL)
        return 1;

    if (EVP_PKEY_derive_init(key_pair->evp_dh) != 1)
        return 1;

    if (EVP_PKEY_derive_set_peer(key_pair->evp_dh, remote_pub) != 1)
        return 1;

    if (EVP_PKEY_derive(key_pair->evp_dh, temp, &dhlen) != 1)
        return 1;

    EVP_PKEY_free(remote_pub);

    u8 temp_dh[NOISE_HASHLEN] = {0};
    if (noise_hash(evp_md, temp, NOISE_DHLEN, temp_dh))
        return 1;

    // discard some bytes
    mem_copy(shared_secret, temp_dh, NOISE_DHLEN);
    return 0;
}


static inline u32 noise_keypair_initialize(struct noise_keypair *pair,
                                           const u8 private[NOISE_DHLEN])
{
    if (private)
    {
        if (pair->evp_priv)
            return 1;

        pair->evp_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL,
                                                      private, NOISE_DHLEN);
        if (pair->evp_priv == NULL)
            return 1;
    }

    pair->evp_dh = EVP_PKEY_CTX_new(pair->evp_priv, NULL);
    if (pair->evp_dh == NULL)
        return 1;

    u64 keylen = NOISE_DHLEN;
    if (EVP_PKEY_get_raw_public_key(pair->evp_priv, pair->public, &keylen) != 1)
        return 1;

    return 0;
}


static u32 noise_keypair_generate(EVP_MD_CTX *evp_md,
                                  struct noise_keypair *pair)
{
    u8 buf[NOISE_HASHLEN] = {0};
    if (rnd_get(&buf, sizeof(buf)))
        return 1;

    u8 hash[NOISE_HASHLEN] = {0};
    if (noise_hash(evp_md, buf, NOISE_HASHLEN, hash))
        return 1;

    pair->evp_priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X448, NULL,
                                                  hash, NOISE_DHLEN);
    if (pair->evp_priv == NULL)
        return 1;

    return noise_keypair_initialize(pair, NULL);
}


static void noise_keypair_del(struct noise_keypair *pair)
{
    EVP_PKEY_CTX_free(pair->evp_dh);
    EVP_PKEY_free(pair->evp_priv);
}


static inline void noise_chacha20_nonce(const u64 counter, u8 output[12])
{
    output[0] = 0;
    output[1] = 0;
    output[2] = 0;
    output[3] = 0;
    output[4] = (u8) (counter);
    output[5] = (u8) (counter >> 8);
    output[6] = (u8) (counter >> 16);
    output[7] = (u8) (counter >> 24);
    output[8] = (u8) (counter >> 32);
    output[9] = (u8) (counter >> 40);
    output[10] = (u8) (counter >> 48);
    output[11] = (u8) (counter >> 56);
}


static inline u32 noise_encrypt(EVP_CIPHER_CTX *evp_cipher, const u64 n,
                                const void *ad, const u32 ad_len,
                                const void *plaintext, const u32 plaintext_len,
                                u8 *ciphertext, u8 *mac)
{
    i32 output_len = 0;
    u8 nonce[12];
    noise_chacha20_nonce(n, nonce);

    if (EVP_EncryptInit_ex(evp_cipher, NULL, NULL, NULL, nonce) != 1)
        return 1;

    if (EVP_EncryptUpdate(evp_cipher, NULL, &output_len,
                          ad, (int) ad_len) != 1)
        return 1;

    if (EVP_EncryptUpdate(evp_cipher, ciphertext, &output_len,
                          plaintext, (i32) plaintext_len) != 1)
        return 1;

    if (EVP_EncryptFinal(evp_cipher, ciphertext + output_len,
                         &output_len) != 1)
        return 1;

    if (EVP_CIPHER_CTX_ctrl(evp_cipher, EVP_CTRL_AEAD_GET_TAG,
                            NOISE_AEAD_MAC, mac) != 1)
        return 1;

    return 0;
}


static inline u32 noise_decrypt(EVP_CIPHER_CTX *evp_cipher, const u64 n,
                                const void *ad, const u32 ad_len,
                                const u8 *ciphertext, const u32 ciphertext_len,
                                u8 *mac, void *plaintext)
{
    i32 output_len = 0;
    u8 nonce[12];
    noise_chacha20_nonce(n, nonce);

    if (EVP_DecryptInit_ex(evp_cipher, NULL, NULL, NULL, nonce) != 1)
        return 1;

    if (EVP_DecryptUpdate(evp_cipher, NULL, &output_len,
                          ad, (int) ad_len) != 1)
        return 1;

    if (EVP_DecryptUpdate(evp_cipher, plaintext, &output_len,
                          ciphertext, (i32) ciphertext_len) != 1)
        return 1;

    if (EVP_CIPHER_CTX_ctrl(evp_cipher, EVP_CTRL_AEAD_SET_TAG,
                            NOISE_AEAD_MAC, mac) != 1)
        return 1;

    return (EVP_DecryptFinal(evp_cipher, plaintext + output_len,
                             &output_len) != 1);
}


static u32 noise_mix_key(struct noise_handshake *state,
                         const u8 *ikm, const u32 ikm_len)
{
    u8 temp_k[NOISE_HASHLEN] = {0};

    if (noise_hkdf(state->evp_hmac, state->symmetric_ck,
                   ikm, ikm_len,
                   state->symmetric_ck,
                   temp_k))
        return 1;

    // initialize_key(temp_k), truncated
    mem_copy(state->cipher_k, temp_k, NOISE_KEYLEN);
    return 0;
}


static u32 noise_mix_hash(struct noise_handshake *state,
                          const void *data, const u32 data_len)
{
    if (EVP_MD_CTX_reset(state->evp_md) != 1)
        return 1;

    if (EVP_DigestInit_ex(state->evp_md, EVP_blake2b512(), NULL) != 1)
        return 1;

    if (EVP_DigestUpdate(state->evp_md,
                         state->symmetric_h, NOISE_HASHLEN) != 1)
        return 1;

    if (EVP_DigestUpdate(state->evp_md,
                         data, data_len) != 1)
        return 1;

    if (EVP_DigestFinal_ex(state->evp_md, state->symmetric_h, NULL) != 1)
        return 1;

    return 0;
}


// serves as a mix_key(dh(..))
static u32 noise_mix_key_dh(struct noise_handshake *state,
                            const struct noise_keypair *pair,
                            const u8 *public_key)
{
    u8 temp_dh[NOISE_DHLEN] = {0};
    if (noise_dh(state->evp_md, pair, public_key, temp_dh))
        return 1;

    if (noise_mix_key(state, temp_dh, NOISE_DHLEN))
        return 1;

    return 0;
}


static u32 noise_encrypt_and_hash(struct noise_handshake *state,
                                  const void *plaintext, const u32 plaintext_len,
                                  u8 *ciphertext, u8 *mac)
{
    if (EVP_EncryptInit_ex(state->evp_cipher, EVP_chacha20_poly1305(), NULL,
                           state->cipher_k, NULL) != 1)
        return 1;

    if (noise_encrypt(state->evp_cipher, state->cipher_n,
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
    if (EVP_DecryptInit_ex(state->evp_cipher, EVP_chacha20_poly1305(), NULL,
                           state->cipher_k, NULL) != 1)
        return 1;

    if (noise_decrypt(state->evp_cipher, state->cipher_n,
                      state->symmetric_h, NOISE_HASHLEN,
                      ciphertext, ciphertext_len,
                      mac, plaintext))
        return 1;

    if (noise_mix_hash(state, ciphertext, ciphertext_len))
        return 1;

    return 0;
}


static u32 noise_split(const struct noise_handshake *state,
                       u8 *c1, u8 *c2)
{
    u8 temp_k1[NOISE_HASHLEN] = {0};
    u8 temp_k2[NOISE_HASHLEN] = {0};

    if (noise_hkdf(state->evp_hmac, state->symmetric_ck,
                   NULL, 0,
                   temp_k1, temp_k2))
        return 1;

    mem_copy(c1, temp_k1, NOISE_KEYLEN);
    mem_copy(c2, temp_k2, NOISE_KEYLEN);

    return 0;
}


static u32 noise_initiator_init(struct noise_handshake *state,
                                HMAC_CTX *evp_hmac,
                                EVP_MD_CTX *evp_md,
                                EVP_CIPHER_CTX *evp_cipher,
                                struct noise_keypair *s,
                                const u8 *rs)
{
    state->evp_hmac = evp_hmac;
    state->evp_cipher = evp_cipher;
    state->evp_md = evp_md;
    mem_copy(state->symmetric_h, noise_protocol_name, NOISE_HASHLEN);
    mem_copy(state->symmetric_ck, noise_protocol_name, NOISE_HASHLEN);

    state->s = s;
    mem_copy(state->rs, rs, NOISE_DHLEN);

    return noise_mix_hash(state, rs, NOISE_DHLEN);
}


static u32 noise_initiator_write(struct noise_handshake *state,
                                 struct noise_initiator *initiator,
                                 const void *ad, const u32 ad_len,
                                 const u8 *payload)
{
    if (noise_mix_hash(state, ad, ad_len))
        return 1;

    // e
    if (noise_keypair_generate(state->evp_md, &state->e))
        return 1;

    mem_copy(initiator->ephemeral, state->e.public, NOISE_DHLEN);
    if (noise_mix_hash(state, state->e.public, NOISE_DHLEN))
        return 1;

    // es
    if (noise_mix_key_dh(state, &state->e, state->rs))
        return 1;

    // s
    if (noise_encrypt_and_hash(state,
                               state->s->public, NOISE_DHLEN,
                               initiator->encrypted_static,
                               initiator->mac1))
        return 1;

    // ss
    if (noise_mix_key_dh(state, state->s, state->rs))
        return 1;

    // payload: encrypt_and_hash(payload)
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

    // e
    if (noise_mix_hash(state, responder->ephemeral, NOISE_DHLEN))
        return 1;

    // ee
    if (noise_mix_key_dh(state, &state->e, responder->ephemeral))
        return 1;

    // se
    if (noise_mix_key_dh(state, state->s, responder->ephemeral))
        return 1;

    // payload
    return noise_decrypt_and_hash(state,
                                  responder->encrypted_payload, NOISE_HANDSHAKE_PAYLOAD,
                                  responder->mac, payload);
}


static u32 noise_responder_init(struct noise_handshake *state,
                                HMAC_CTX *evp_hmac,
                                EVP_MD_CTX *evp_md,
                                EVP_CIPHER_CTX *evp_cipher,
                                struct noise_keypair *s)
{
    state->evp_hmac = evp_hmac;
    state->evp_cipher = evp_cipher;
    state->evp_md = evp_md;
    state->s = s;

    mem_copy(state->symmetric_h, noise_protocol_name, NOISE_HASHLEN);
    mem_copy(state->symmetric_ck, noise_protocol_name, NOISE_HASHLEN);

    return noise_mix_hash(state, s->public, NOISE_DHLEN);
}


static u32 noise_initiator_read(struct noise_handshake *state,
                                struct noise_initiator *initiator,
                                const void *ad, const u32 ad_len,
                                u8 *payload)
{
    if (noise_mix_hash(state, ad, ad_len))
        return 1;

    // e
    mem_copy(state->re, initiator->ephemeral, NOISE_DHLEN);
    if (noise_mix_hash(state, state->re, NOISE_DHLEN))
        return 1;

    // es
    if (noise_mix_key_dh(state, state->s, state->re))
        return 1;

    // s
    if (noise_decrypt_and_hash(state, initiator->encrypted_static, NOISE_DHLEN,
                               initiator->mac1, state->rs))
    {
        log("failed to process s");
        return 1;
    }

    // ss
    if (noise_mix_key_dh(state, state->s, state->rs))
        return 1;

    // payload
    return noise_decrypt_and_hash(state,
                                  initiator->encrypted_payload, NOISE_HANDSHAKE_PAYLOAD,
                                  initiator->mac2, payload);
}


static u32 noise_responder_write(struct noise_handshake *state,
                                 struct noise_responder *responder,
                                 const void *ad, const u32 ad_len,
                                 const void *payload)
{
    if (noise_mix_hash(state, ad, ad_len))
        return 1;

    // e
    if (noise_keypair_generate(state->evp_md, &state->e))
        return 1;

    mem_copy(responder->ephemeral, state->e.public, NOISE_DHLEN);
    if (noise_mix_hash(state, state->e.public, NOISE_DHLEN))
        return 1;

    // ee
    if (noise_mix_key_dh(state, &state->e, state->re))
        return 1;

    // se
    if (noise_mix_key_dh(state, &state->e, state->rs))
        return 1;

    // payload
    return noise_encrypt_and_hash(state,
                                  payload, NOISE_HANDSHAKE_PAYLOAD,
                                  responder->encrypted_payload, responder->mac);
}


static u32 noise_state_del(struct noise_handshake *state)
{
    log("cleaning up state %p", state->e.evp_priv);

    noise_keypair_del(&state->e);
    return 0;
}


static i32 noise_counter_validate(const u32 block[8],
                                  const u64 local,
                                  const u64 remote)
{
    if (remote + NOISE_COUNTER_WINDOW < local)
    {
        log("rejecting counter: too old");
        return -1;
    }

    if (remote > (local + NOISE_COUNTER_WINDOW) || remote == NOISE_NONCE_MAX)
    {
        log("rejecting counter: outside of window / max");
        return -1;
    }

    const i32 block_index = (i32) (remote / 32) & 7;
    if (remote <= local)
    {
        if (block[block_index] & (1 << (remote & 31)))
        {
            log("already received [%zu]", remote);
            return -1;
        }
    }

    // at this point only sequences above local counter are left,
    // and they are within allowed forward window, so it is ok
    return block_index;
}


/*
 *
 *
 */
// this covers an extremely rare case when our acks and/or responses
// do not go through: how many times we can respond to a valid
// request or how many acks to send if received data packet
// did not contain any new messages
#define SESSION_RESPONSE_RETRY      10

#define SESSION_EVENT_QUEUED        1   // is this context in queue?
#define SESSION_EVENT_ACK           2   // new acks arrived
#define SESSION_EVENT_DATA          4   // new message available

#define SESSION_TIMER_RETRY         1   // interval for retransmissions
#define SESSION_TIMER_KEEPALIVE     NMP_KEEPALIVE_DEFAULT // @nmp.h
#define SESSION_TIMER_RETRIES_MAX   10  // amount of retransmission attempts
#define SESSION_TIMER_TTL           30  // inactivity timeout before session drop
#define SESSION_TIMER_RETRIES_TTL   3   // default value for inactivity retries

#define SESSION_REQUEST_TTL         15000 // ms

#define NET_PACKET_MAX              1440
#define NET_PACKET_MIN              32

#define RING_BATCH                  32
#define RING_SQ                     256
#define RING_CQ                     (RING_SQ * 4)
#define RING_BUFFERS                512
#define RING_SEND_BUFFERS           (RING_BATCH * 2)

#define RING_NET_GROUP              0
#define RING_LOCAL_GROUP            1


#define header_initialize(type_, id_) (struct nmp_header) { \
                        .type = (type_),                    \
                        .pad = {0,0,0},                     \
                        .session_id = (id_)}

static_assert(NMP_KEYLEN == NOISE_DHLEN, "keylen");
static_assert(NMP_PAYLOAD_MAX == MSG_MAX_SINGLE, "payload");


struct nmp_header
{
    u8 type;
    u8 pad[3];
    u32 session_id;
};


struct nmp_request
{
    struct nmp_header header;
    struct noise_initiator initiator;
};


struct nmp_response
{
    struct nmp_header header;
    struct noise_responder responder;
};


struct nmp_transport
{
    struct nmp_header type_pad_id;
    u64 counter;

    // u8 ciphertext[..];
    // u8 mac[16];
};


enum packet_types
{
    NMP_REQUEST = 0,
    NMP_RESPONSE = 1,
    NMP_DATA = 2,
    NMP_ACK = 3,
};


enum session_status
{
    SESSION_STATUS_NONE = 0,     // empty or marked for deletion
    SESSION_STATUS_RESPONSE = 1, // waiting for response
    SESSION_STATUS_CONFIRM = 2,  // waiting for the first message
    SESSION_STATUS_WINDOW = 3,   // maximum number of messages in transit
    SESSION_STATUS_ESTAB = 4,    // established connection
    SESSION_STATUS_ACKWAIT = 5   // some data is in transit
};

struct nmp_buf_send
{
    union nmp_sa addr;
    struct msghdr send_hdr;
    struct iovec iov;

    union
    {
        struct nmp_request request;
        struct nmp_response response;
        struct nmp_transport transport;
        u8 data[NET_PACKET_MAX];
    };
};


struct nmp_local_request
{
    u16 type;
    u16 len;
    u32 session;

    union
    {
        struct session *payload_ctx_new;
        struct msg_header *payload_noack;
        u8 *payload_data;
        void *payload_ptr;
    };
};


enum nmp_cqe_mark
{
    RING_CQ_NET = 0,
    RING_CQ_LOCAL = 1,
    RING_CQ_SEND = 2,
};


struct nmp_recv_buf
{
    u8 data[2048];
};


// recvmsg multishot
struct nmp_recv_net
{
    struct io_uring_buf_ring *ring;
    struct nmp_recv_buf *base;
    u32 size;
};


// recv multishot
struct nmp_recv_local
{
    struct io_uring_buf_ring *ring;
    struct nmp_local_request *base;
    u32 size;
};


struct session_initiation
{
    struct noise_handshake handshake;
    struct
    {
        u64 timestamp;
        u8 data[NMP_INITIATION_PAYLOAD];

    } payload[2];

    union
    {
        struct nmp_request request;
        struct nmp_response response;

    } recv_buf;

    struct nmp_buf_send send_buf;
};


struct session
{
    u8 state;
    u8 events;
    u8 timer_retries;
    u8 response_retries;
    u32 session_id;

    u64 noise_counter_send;
    u64 noise_counter_receive;
    u32 noise_counter_block[8];
    EVP_CIPHER_CTX *noise_key_receive;
    EVP_CIPHER_CTX *noise_key_send;

    union nmp_sa addr;
    u64 stat_tx;
    u64 stat_rx;
    struct __kernel_timespec kts;
    struct session_initiation *initiation;

    union /* just share first member */
    {
        void *context_ptr;
        struct msg_state transport;
    };
};


struct nmp_data
{
    struct io_uring ring;
    struct msghdr recv_hdr;
    struct nmp_recv_net recv_net;
    struct nmp_recv_local recv_local;

    i32 net_udp;
    i32 local_rx;
    i32 local_tx;
    u16 payload;
    u16 keepalive_interval;
    u32 options;
    sa_family_t sa_family;
    u8 retries[6];

    HMAC_CTX *evp_hmac;
    EVP_MD_CTX *evp_md_ctx;
    EVP_CIPHER_CTX *evp_cipher;

    void *request_context;
    enum nmp_status (*request_cb)(const u8 *,
                                  struct nmp_request_container *, void *);
    enum nmp_status (*status_cb)(const enum nmp_status,
                                 const union nmp_status_container *, void *);
    void (*stats_cb)(const u64, const u64, void *);

    struct msg_routines transport_callbacks;
    struct noise_keypair static_keys;

    u32 send_iterator;
    struct nmp_buf_send send_buffers[RING_SEND_BUFFERS];

    struct hash_table sessions;
    struct noise_handshake responder_precomp;
};


static inline struct io_uring_sqe *nmp_ring_sqe(struct nmp_data *nmp)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&nmp->ring);
    if (sqe == NULL)
    {
        log("retrying io_uring_get_sqe()");

        const int res = io_uring_submit(&nmp->ring);
        if (res < 0)
        {
            log("submit failed %s", strerrorname_np(-res));
            return NULL;
        }

        return io_uring_get_sqe(&nmp->ring);
    }

    return sqe;
}


static inline struct nmp_buf_send *nmp_ring_send_buf(struct nmp_data *nmp)
{
    nmp->send_iterator += 1;
    nmp->send_iterator &= (RING_SEND_BUFFERS - 1);

    return &nmp->send_buffers[nmp->send_iterator];
}


static inline u32 nmp_ring_send(struct nmp_data *nmp,
                                struct nmp_buf_send *buf,
                                const u32 len, const union nmp_sa *addr)
{
    assert(len >= NET_PACKET_MIN && len <= NET_PACKET_MAX);

    struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
    if (sqe == NULL)
        return 1;

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
    io_uring_sqe_set_data64(sqe, RING_CQ_SEND);
    return 0;
}


static inline u32 nmp_ring_recv_net(struct nmp_data *nmp)
{
    struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
    if (sqe == NULL)
        return 1;

    io_uring_prep_recvmsg_multishot(sqe, nmp->net_udp, &nmp->recv_hdr, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->user_data = RING_CQ_NET;
    sqe->buf_group = RING_NET_GROUP;

    return 0;
}


static inline u32 nmp_ring_recv_local(struct nmp_data *nmp)
{
    struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
    if (sqe == NULL)
        return 1;

    io_uring_prep_recv_multishot(sqe, nmp->local_rx, NULL, 0, 0);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->user_data = RING_CQ_LOCAL;
    sqe->buf_group = RING_LOCAL_GROUP;

    return 0;
}


static inline void nmp_ring_reuse_buf(struct io_uring_buf_ring *ring, void *addr,
                                      const u32 buflen, const u32 bid)
{
    io_uring_buf_ring_add(ring, addr, buflen, bid,
                          io_uring_buf_ring_mask(RING_BUFFERS), 0);
    io_uring_buf_ring_advance(ring, 1);
}


static u32 nmp_ring_setup_net(struct io_uring *ring,
                              struct nmp_recv_net *buffers)
{
    buffers->size = (sizeof(struct io_uring_buf) + sizeof(struct nmp_recv_buf))
                    * RING_BUFFERS;
    buffers->ring = mmap(NULL, buffers->size,
                         PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE,
                         0, 0);
    if (buffers->ring == MAP_FAILED)
    {
        log_errno();
        return 1;
    }

    io_uring_buf_ring_init(buffers->ring);
    struct io_uring_buf_reg reg =
            {
                    .ring_addr = (u64) buffers->ring,
                    .ring_entries = RING_BUFFERS,
                    .bgid = RING_NET_GROUP,
            };

    if (io_uring_register_buf_ring(ring, &reg, 0))
    {
        return 1;
    }

    u8 *ptr = (u8 *) buffers->ring + (sizeof(struct io_uring_buf) * RING_BUFFERS);
    buffers->base = (struct nmp_recv_buf *) ptr;

    for (i32 i = 0; i < RING_BUFFERS; i++)
    {
        io_uring_buf_ring_add(buffers->ring, &buffers->base[i],
                              sizeof(struct nmp_recv_buf), i,
                              io_uring_buf_ring_mask(RING_BUFFERS), i);
    }

    io_uring_buf_ring_advance(buffers->ring, RING_BUFFERS);
    return 0;
}


static u32 nmp_ring_setup_local(struct io_uring *ring,
                                struct nmp_recv_local *buffers)
{
    buffers->size = (sizeof(struct io_uring_buf) + sizeof(struct nmp_local_request))
                    * RING_BUFFERS;
    buffers->ring = mmap(NULL, buffers->size,
                         PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE,
                         0, 0);
    if (buffers->ring == MAP_FAILED)
    {
        log_errno();
        return 1;
    }

    io_uring_buf_ring_init(buffers->ring);
    struct io_uring_buf_reg reg =
            {
                    .ring_addr = (u64) buffers->ring,
                    .ring_entries = RING_BUFFERS,
                    .bgid = RING_LOCAL_GROUP,
            };

    if (io_uring_register_buf_ring(ring, &reg, 0))
    {
        return 1;
    }

    u8 *ptr = (u8 *) buffers->ring + (sizeof(struct io_uring_buf) * RING_BUFFERS);
    buffers->base = (struct nmp_local_request *) ptr;

    for (i32 i = 0; i < RING_BUFFERS; i++)
    {
        io_uring_buf_ring_add(buffers->ring, &buffers->base[i],
                              sizeof(struct nmp_local_request), i,
                              io_uring_buf_ring_mask(RING_BUFFERS), i);
    }

    io_uring_buf_ring_advance(buffers->ring, RING_BUFFERS);
    return 0;
}


static u32 nmp_ring_timer_update(struct nmp_data *nmp,
                                 struct session *ctx, const u32 value)
{
    log("updating timer %xu to %u", ctx->session_id, value);

    struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
    if (sqe == NULL)
        return 1;

    ctx->kts.tv_sec = value;
    io_uring_prep_timeout_update(sqe, &ctx->kts, (u64) ctx, 0);

    return 0;
}


static u32 nmp_ring_timer_set(struct nmp_data *nmp,
                              struct session *ctx, const u32 value)
{
    log("setting %u for %xu", value, ctx->session_id);

    struct io_uring_sqe *sqe = nmp_ring_sqe(nmp);
    if (sqe == NULL)
        return 1;

    ctx->kts.tv_sec = value;
    io_uring_prep_timeout(sqe, &ctx->kts, 0, 0);
    io_uring_sqe_set_data(sqe, ctx);

    return 0;
}


static struct session *session_new()
{
    EVP_CIPHER_CTX *c1 = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *c2 = EVP_CIPHER_CTX_new();
    if (!c1 || !c2)
        goto out_fail;

    struct session_initiation *initiation = mem_alloc(sizeof(struct session_initiation));
    if (initiation == NULL)
        goto out_fail;

    struct session *ctx = mem_alloc(sizeof(struct session));
    if (ctx == NULL)
        goto out_fail;


    mem_zero(ctx, sizeof(struct session));
    mem_zero(initiation, sizeof(struct session_initiation));

    ctx->initiation = initiation;
    ctx->noise_key_send = c1;
    ctx->noise_key_receive = c2;

    // sequence numbers start at zero but msg_sequence_cmp()
    // is a strict '>' so set state counters to 0xffff,
    // exactly one before the u16 wraps around to zero
    ctx->transport.tx_seq = 0xffff;
    ctx->transport.tx_ack = 0xffff;
    ctx->transport.rx_seq = 0xffff;
    ctx->transport.rx_delivered = 0xffff;

    return ctx;
    out_fail:
    {
        if (c1)
            mem_free(c1);

        if (c2)
            mem_free(c2);

        if (initiation)
            mem_free(initiation);

        if (ctx)
            mem_free(ctx);

        log_errno();
        return NULL;
    };
}


static void session_destroy(struct session *ctx)
{
    msg_context_wipe(&ctx->transport);
    EVP_CIPHER_CTX_free(ctx->noise_key_receive);
    EVP_CIPHER_CTX_free(ctx->noise_key_send);

    log("%xu", ctx->session_id);
    mem_zero(ctx, sizeof(struct session));
    mem_free(ctx);
}


/*
 *  remove hash table entry, notify application
 *  but do not remove it immediately, just mark
 *  this session for next timer trigger
 */
static void session_drop(struct nmp_data *nmp,
                         struct session *ctx,
                         const enum nmp_status status,
                         const union nmp_status_container *container)
{
    log("%xu", ctx->session_id);
    if (nmp->status_cb)
        nmp->status_cb(status, container, ctx->context_ptr);

    // any new network message or local requests related to this
    // context will be simply discarded as there is no hash table
    // entry, then when its timer fires off the context is finally
    // deleted; this prevents potential use-after-free() because timers
    // (timer fd) have context pointers and do not do any lookup
    hash_table_remove(&nmp->sessions, ctx->session_id);
    ctx->state = SESSION_STATUS_NONE;
}


static u32 session_transport_send(struct nmp_data *nmp, struct session *ctx,
                                  const u8 *payload, const i32 amt, const u8 type)
{
    assert(amt % 16 == 0);
    if (ctx->noise_counter_send == NOISE_NONCE_MAX)
    {
        // noise spec does not allow sending more than
        // 2^64 - 1 messages for a single handshake
        session_drop(nmp, ctx, NMP_SESSION_EXPIRED, NULL);
        return 0;
    }

    struct nmp_buf_send *buf = nmp_ring_send_buf(nmp);
    buf->transport.type_pad_id = header_initialize(type, ctx->session_id);
    buf->transport.counter = ctx->noise_counter_send;

    const u32 packet_len = sizeof(struct nmp_transport) + amt + NOISE_AEAD_MAC;
    u8 *packet = buf->data;
    u8 *ciphertext = packet + sizeof(struct nmp_transport);
    u8 *mac = ciphertext + amt;

    noise_encrypt(nmp->evp_cipher, ctx->noise_counter_send,
                  &buf->transport, sizeof(struct nmp_transport),
                  payload, amt,
                  ciphertext, mac);

    if (nmp_ring_send(nmp, buf, packet_len, &ctx->addr))
        return 1;

    ctx->noise_counter_send += 1;
    ctx->stat_tx += packet_len;
    return 0;
}


static i32 session_transport_receive(struct nmp_data *nmp, struct session *ctx,
                                     u8 *packet, const u32 packet_len,
                                     u8 plaintext[MSG_MAX_PAYLOAD])
{
    const i32 payload_len = (i32) (packet_len
                                   - sizeof(struct nmp_transport) - NOISE_AEAD_MAC);
    if (payload_len < 0 || payload_len > MSG_MAX_PAYLOAD)
    {
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
    if (block_index < 0)
    {
        log("counter rejected %xu", header->type_pad_id.session_id);
        return -1;
    }


    if (noise_decrypt(nmp->evp_cipher, counter_remote,
                      header, sizeof(struct nmp_transport),
                      ciphertext, payload_len,
                      mac, plaintext))
    {
        log("decryption failed %xu", header->type_pad_id.session_id);
        return -1;
    }


    // only after successful decryption
    if (counter_remote > ctx->noise_counter_receive)
    {
        // start from local block, walk forward
        // zeroing out blocks in front
        i32 i = (i32) (ctx->noise_counter_receive / 32) & 7;

        while (i != block_index)
        {
            i += 1;
            i &= 7;

            ctx->noise_counter_block[i] = 0;
        }

        ctx->noise_counter_receive = counter_remote;
    }

    ctx->noise_counter_block[block_index] |= (1 << (u32) (counter_remote & 31));
    return payload_len;
}


static u32 session_request(struct nmp_data *nmp, struct session *ctx)
{
    assert(ctx->state == SESSION_STATUS_NONE);
    assert(ctx->initiation);

    struct session_initiation *initiation = ctx->initiation;

    initiation->payload[0].timestamp = time_get();
    if (initiation->payload[0].timestamp == 0)
        return 1;


    initiation->send_buf.request.header = header_initialize(NMP_REQUEST, ctx->session_id);
    if (noise_initiator_write(&initiation->handshake,
                              &initiation->send_buf.request.initiator,
                              &initiation->send_buf.request, sizeof(struct nmp_header),
                              (u8 *) &initiation->payload[0]))
        return 1;

    if (nmp_ring_send(nmp, &initiation->send_buf, sizeof(struct nmp_request), &ctx->addr))
        return 1;

    ctx->state = SESSION_STATUS_RESPONSE;
    ctx->stat_tx += sizeof(struct nmp_request);
    return nmp_ring_timer_set(nmp, ctx, SESSION_TIMER_RETRY);
}


static u32 session_response(struct nmp_data *nmp, struct session *ctx)
{
    assert(ctx->state == SESSION_STATUS_NONE);
    assert(ctx->initiation);

    struct session_initiation *initiation = ctx->initiation;
    initiation->send_buf.response.header = header_initialize(NMP_RESPONSE, ctx->session_id);
    initiation->payload[1].timestamp = 0;

    if (noise_responder_write(&initiation->handshake,
                              &initiation->send_buf.response.responder,
                              &initiation->send_buf.response.header, sizeof(struct nmp_header),
                              (u8 *) &initiation->payload[1]))
        return 1;

    if (nmp_ring_send(nmp, &initiation->send_buf, sizeof(struct nmp_response), &ctx->addr))
        return 1;


    ctx->state = SESSION_STATUS_CONFIRM;
    ctx->stat_tx += sizeof(struct nmp_response);
    ctx->response_retries = 0;
    return nmp_ring_timer_set(nmp, ctx, SESSION_TIMER_RETRY);;
}


/*
 *  this is triggered by a local event
 *  or received ack (with new messages acked)
 */
static u32 session_data(struct nmp_data *nmp, struct session *ctx)
{
    // NONE, RESPONSE, CONFIRM, WINDOW
    if (ctx->state < SESSION_STATUS_ESTAB)
    {
        log("rejecting state %s", nmp_dbg_session_status[ctx->state]);
        return 0;
    }

    for (;;)
    {
        u8 payload[MSG_MAX_PAYLOAD];

        const i32 amt = msg_assemble(&ctx->transport, payload, nmp->payload);
        switch (amt)
        {
            case 0:
            {
                log("nothing to send");
                return 0;
            }

            case -1:
            {
                log("marking full window");
                ctx->state = SESSION_STATUS_WINDOW;
                return 0;
            }

            default:
            {
                // checking for zero here because if flag for full window
                // is set then flag for ack wait is guaranteed to be set too
                // but if its ack wait only, this condition is still relevant
                if (ctx->state == SESSION_STATUS_ESTAB)
                {
                    if (nmp_ring_timer_update(nmp, ctx, SESSION_TIMER_RETRY))
                        return 1;

                    ctx->state = SESSION_STATUS_ACKWAIT;
                }

                if (session_transport_send(nmp, ctx,
                                           payload, amt, NMP_DATA))
                    return 1;

                break;
            }
        }
    }

    return 0;
}


/*
 *
 */
static u32 session_data_retry(struct nmp_data *nmp, struct session *ctx)
{
    u8 payload[MSG_MAX_PAYLOAD];

    const u32 amt = msg_assemble_retry(&ctx->transport,
                                       payload, nmp->payload);
    return amt ? session_transport_send(nmp, ctx,
                                        payload, (i32) amt, NMP_DATA)
               : 0;
}


/*
 *
 */
static u32 session_data_noack(struct nmp_data *nmp, struct session *ctx,
                              const struct msg_header *message, const u16 len)
{
    // NONE, RESPONDER, CONFIRM mean that
    // this context is not ready yet
    if (ctx->state < SESSION_STATUS_WINDOW)
    {
        log("skipping noack (%s)", nmp_dbg_session_status[ctx->state]);
        return 0;
    }

    return session_transport_send(nmp, ctx, (const u8 *) message,
                                  len, NMP_DATA);
}

/*
 *
 */
static u32 session_ack(struct nmp_data *nmp, struct session *ctx)
{
    if (ctx->response_retries > SESSION_RESPONSE_RETRY)
    {
        log("maximum response retries");
        return 0;
    }

    struct msg_ack ack;
    msg_ack_assemble(&ctx->transport, &ack);

    ctx->response_retries += 1;
    return session_transport_send(nmp, ctx,
                                  (u8 *) &ack, sizeof(struct msg_ack), NMP_ACK);
}


static u32 session_keepalive(struct nmp_data *nmp, struct session *ctx)
{
    assert(ctx->state == SESSION_STATUS_ESTAB);
    return session_transport_send(nmp, ctx, NULL, 0, NMP_DATA);
}


///////////////////////////////
///     local events        ///
///////////////////////////////
#define EVENT_REQUEST_MALLOC  2048


enum event_local_type
{
    EVENT_LOCAL_DATA = 0,
    EVENT_LOCAL_DATA_NOACK = 1,
    EVENT_LOCAL_DROP = 2,
    EVENT_LOCAL_NEW = 3,
    EVENT_LOCAL_TERM = 4,
};


static i32 event_local_data(struct nmp_data *nmp,
                            struct session *ctx,
                            struct nmp_local_request *request)
{
    // try to include this message to next outgoing packet
    if (msg_queue(&ctx->transport, request->payload_data, request->len))
    {
        // let application know that the queue is full
        if (nmp->status_cb)
        {
            const union nmp_status_container container = {.msg_id = ctx->transport.tx_counter};
            nmp->status_cb(NMP_SESSION_QUEUE, &container, ctx->context_ptr);
        }

        return 0;
    }

    // note: not free()ing this request, that is done when message is acked
    return session_data(nmp, ctx) ? -1 : 0;
}


/*
 *  remember: message is preformed in nmp_send_noack()
 *  so we have a payload that is ready for sending
 */
static i32 event_local_noack(struct nmp_data *nmp,
                             struct session *ctx,
                             struct nmp_local_request *request)
{
    const u32 result = session_data_noack(nmp, ctx, request->payload_noack,
                                          request->len);
    mem_free(request);
    return result ? -1 : 0;
}


static i32 event_local_drop(struct nmp_data *nmp,
                            struct session *ctx,
                            struct nmp_local_request *request)
{
    UNUSED(request);
    // same as session_drop(), except here we are not
    // doing status callback as it does not make sense
    ctx->state = SESSION_STATUS_NONE;
    hash_table_remove(&nmp->sessions, ctx->session_id);
    return 0;
}


static i32 event_local_connect(struct nmp_data *nmp,
                               struct session *ctx_empty,
                               struct nmp_local_request *request)
{
    UNUSED(ctx_empty);
    struct session *ctx = request->payload_ctx_new;

    if (nmp->sessions.items > NMP_SESSIONS)
    {
        log("rejecting connection request: MAXCONN");

        const union nmp_status_container cancelled = {.session_id = request->session};
        if (nmp->status_cb)
            nmp->status_cb(NMP_SESSION_MAX,
                           &cancelled, ctx->context_ptr);

        session_destroy(ctx);
        return 0;
    }

    if (hash_table_insert(&nmp->sessions,
                          ctx->session_id, ctx))
        return -1;

    if (session_request(nmp, ctx))
        return -1;

    ctx->state = SESSION_STATUS_RESPONSE;
    return 0;
}


static i32 event_local_term(struct nmp_data *nmp,
                            struct session *ctx,
                            struct nmp_local_request *request)
{
    UNUSED(nmp);
    UNUSED(ctx);
    UNUSED(request);

    log("received terminate request");
    // just the indicator
    return 1;
}


static i32 event_local(struct nmp_data *nmp,
                       const struct io_uring_cqe *cqe,
                       struct session **ctx_empty)
{
    UNUSED(ctx_empty);
    const u32 bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    struct nmp_local_request *request = nmp->recv_local.base + bid;
    i32 result = 0;

    if ((cqe->flags & IORING_CQE_F_MORE) == 0)
    {
        log("updating local multishot receive");
        if (nmp_ring_recv_local(nmp))
            return 1;

        goto out;
    }

    struct session *ctx = NULL;

    // find context for types that need it,
    // and select appropriate action
    const enum event_local_type type = request->type;
    if (type < EVENT_LOCAL_NEW)
    {
        // drop, data, noack
        ctx = hash_table_lookup(&nmp->sessions, request->session);
        if (ctx == NULL)
        {
            log("dropping local request: ctx not found");
            if (request->payload_ptr)
                mem_free(request->payload_ptr);

            goto out;
        }
    }

    switch (type)
    {
        case EVENT_LOCAL_DATA:
            result = event_local_data(nmp, ctx, request);
            break;
        case EVENT_LOCAL_DATA_NOACK:
            result = event_local_noack(nmp, ctx, request);
            break;
        case EVENT_LOCAL_DROP:
            result = event_local_drop(nmp, ctx, request);
            break;
        case EVENT_LOCAL_NEW:
            result = event_local_connect(nmp, ctx, request);
            break;
        case EVENT_LOCAL_TERM:
            result = event_local_term(nmp, ctx, request);
            break;

        default:
        {
            log("unhandled event");
            return -1;
        }
    }


    out:
    {
        nmp_ring_reuse_buf(nmp->recv_local.ring, request,
                           sizeof(struct nmp_local_request), bid);
        return result;
    }
}


///////////////////////////////
///     timer events        ///
///////////////////////////////


static u32 event_timer(struct nmp_data *nmp,
                       struct session *ctx)
{
    // session has been marked for deletion
    if (ctx->state == SESSION_STATUS_NONE)
    {
        // this is safe to do here:
        // when errors occur during processing of any
        // network or local events the state is simply
        // marked with SESSION_STATUS_NONE, so it does not accept
        // any remaining events from sockets (/queues)
        session_destroy(ctx);
        return 0;
    }


    ctx->timer_retries += 1;
    log("state %s try %u/%u", nmp_dbg_session_status[ctx->state],
        ctx->timer_retries, nmp->retries[ctx->state]);

    if (ctx->timer_retries >= nmp->retries[ctx->state])
    {
        const union nmp_status_container latest = {.msg_id = msg_latest_acked(&ctx->transport)};
        session_drop(nmp, ctx, NMP_SESSION_DISCONNECTED, &latest);
        session_destroy(ctx);
        return 0;
    }

    switch (ctx->state)
    {
        case SESSION_STATUS_WINDOW:
        case SESSION_STATUS_ACKWAIT:
        {
            if (session_data_retry(nmp, ctx))
                return 1;

            break;
        }

        case SESSION_STATUS_ESTAB:
        {
            if (session_keepalive(nmp, ctx))
                return 1;

            break;
        }

        case SESSION_STATUS_RESPONSE:
        {
            assert(ctx->initiation);

            if (nmp_ring_send(nmp, &ctx->initiation->send_buf,
                              sizeof(struct nmp_request), &ctx->addr))
                return 1;

            ctx->stat_tx += sizeof(struct nmp_request);
            break;
        }

        case SESSION_STATUS_CONFIRM:
        {
            assert(ctx->initiation);

            if (nmp_ring_send(nmp, &ctx->initiation->send_buf,
                              sizeof(struct nmp_response), &ctx->addr))
                return 1;

            ctx->stat_tx += sizeof(struct nmp_response);
            break;
        }

        default:
            return 1;
    }


    if (nmp->stats_cb)
        nmp->stats_cb(ctx->stat_rx, ctx->stat_tx, ctx->context_ptr);

    // reset to a previous value
    return nmp_ring_timer_set(nmp, ctx, ctx->kts.tv_sec);
}


///////////////////////////////
///     network events      ///
///////////////////////////////


static i32 event_net_data(struct nmp_data *nmp, struct session *ctx,
                          const u8 *payload, const u32 payload_len)
{
    assert(ctx->state != SESSION_STATUS_NONE);

    if (ctx->state == SESSION_STATUS_CONFIRM)
    {
        assert(ctx->initiation);

        ctx->state = SESSION_STATUS_ESTAB;
        ctx->response_retries = 0;
        if (noise_state_del(&ctx->initiation->handshake))
            return 1;

        mem_free(ctx->initiation);

        if (nmp->status_cb)
            nmp->status_cb(NMP_SESSION_INCOMING, NULL, ctx->context_ptr);

        // there could be a custom interval set, update needed
        if (nmp_ring_timer_update(nmp, ctx, nmp->keepalive_interval))
            return -1;
    }

    // skip empty + reset the counter
    if (payload_len == 0)
    {
        ctx->timer_retries = 0;
        return 0;
    }

    const i32 new_messages = msg_read(&nmp->transport_callbacks,
                                      &ctx->transport,
                                      payload, payload_len);
    switch (new_messages)
    {
        case -1:
        {
            // mark this session with critical error but
            // do not return -1 as this is not critical
            // for entire library, just drop this connection
            session_drop(nmp, ctx, NMP_SESSION_ERR_PROTOCOL, NULL);
            return 0;
        }

        case 0:
        {
            // this is a fresh and valid packet which contains
            // payload, no new messages for us though;
            // no need to buffer these, just respond immediately
            return session_ack(nmp, ctx) ? -1 : 0;
        }

        case (MSG_WINDOW + 1):
        {
            // successful noack message
            return 0;
        }

        default:
        {
            return new_messages;
        }
    }
}


static u32 event_net_ack(struct nmp_data *nmp, struct session *ctx,
                         const u8 *payload, const u32 payload_len)
{
    assert(ctx->state != SESSION_STATUS_NONE);
    if (payload_len != sizeof(struct msg_ack))
    {
        // this ack did not fail authentication,
        // but we cant read it, something is going on
        log("payload != sizeof(ack)");

        session_drop(nmp, ctx, NMP_SESSION_ERR_PROTOCOL, NULL);
        return 1;
    }

    // we only want WINDOW, ESTAB & ACKWAIT here
    if (ctx->state < SESSION_STATUS_WINDOW)
    {
        log("rejecting state %s", nmp_dbg_session_status[ctx->state]);
        return 0;
    }

    const struct msg_ack *ack = (struct msg_ack *) payload;
    const i32 acks = msg_ack_read(&ctx->transport, ack);
    if (acks < 0)
    {
        session_drop(nmp, ctx, NMP_SESSION_ERR_PROTOCOL, NULL);
        return 0;
    }

    return (u32) acks;
}


static i32 event_net_request(struct nmp_data *nmp,
                             const u32 id, const union nmp_sa *addr,
                             struct nmp_request *request, const u32 len)
{
    if (nmp->request_cb == NULL)
    {
        log("callback not set, skipping request");
        return 0;
    }

    if (len != sizeof(struct nmp_request))
    {
        log("rejecting request size %u (%xu)", len, id);
        return 0;
    }

    if (nmp->sessions.items >= HASH_TABLE_SIZE)
    {
        log("cannot accept new connection");
        return 0;
    }

    struct noise_handshake handshake = nmp->responder_precomp;
    struct
    {
        u64 timestamp;
        u8 data[NMP_INITIATION_PAYLOAD];

    } request_payload = {0};

    struct session *ctx = hash_table_lookup(&nmp->sessions, id);
    if (ctx && ctx->state != SESSION_STATUS_CONFIRM)
    {
        log("dropping request for %xu", id);
        return 0;
    }

    if (noise_initiator_read(&handshake, &request->initiator,
                             &request->header, sizeof(struct nmp_header),
                             (u8 *) &request_payload))
    {
        log("failed to read request for %xu", id);
        return 0;
    }

    const u64 timestamp = time_get();
    if (timestamp == 0)
    {
        return -1;
    }

    if (timestamp + 500 > request_payload.timestamp + SESSION_REQUEST_TTL)
    {
        log("request expired %xu", id);
        return 0;
    }

    struct nmp_request_container request_container = {0};
    request_container.addr = *addr;
    request_container.id = id;
    request_container.request_payload = request_payload.data;

    // ask application what we do next
    switch (nmp->request_cb(handshake.rs, &request_container,
                            nmp->request_context))
    {
        case NMP_CMD_ACCEPT:
        {
            break;
        }

        case NMP_CMD_RESPOND:
        {
            log("application rejected request %xu", id);

            // there is no session and no resources,
            // allocated so do everything by hand
            // note: no owner of this buffer is specified
            // which means we won't notify application if
            // this send fails
            struct nmp_buf_send *buf = nmp_ring_send_buf(nmp);
            if (buf == NULL)
                return -1;

            buf->response.header = header_initialize(NMP_RESPONSE, id);
            if (noise_responder_write(&handshake, &buf->response.responder,
                                      &buf->response.header, sizeof(struct nmp_header),
                                      request_container.response_payload))
                return -1;

            return nmp_ring_send(nmp, buf, sizeof(struct nmp_response), addr) ? -1 : 0;
        }

        case NMP_CMD_DROP:
        default:
        {
            log("application dropped request %xu", id);
            return 0;
        }
    }


    ctx = session_new();
    if (ctx == NULL)
        return -1;

    ctx->context_ptr = request_container.context_ptr;
    ctx->addr = *addr;
    ctx->session_id = id;
    ctx->stat_rx += sizeof(struct nmp_request);

    struct session_initiation *initiation = ctx->initiation;

    mem_copy(initiation->payload[1].data,
             request_container.response_payload, NMP_INITIATION_PAYLOAD);
    initiation->handshake = handshake;

    if (session_response(nmp, ctx))
    {
        log("failed to generate response");
        return -1;
    }

    if (hash_table_insert(&nmp->sessions, id, ctx))
        return -1;

    u8 k_recv[NOISE_KEYLEN];
    u8 k_send[NOISE_KEYLEN];

    noise_split(&initiation->handshake,
                k_recv,
                k_send);


    if (EVP_DecryptInit_ex(ctx->noise_key_receive, EVP_chacha20_poly1305(),
                           NULL, k_recv, NULL) != 1)
        return -1;

    if (EVP_EncryptInit_ex(ctx->noise_key_send, EVP_chacha20_poly1305(),
                           NULL, k_send, NULL) != 1)
        return -1;

    ctx->noise_counter_receive = 0;
    ctx->noise_counter_send = 0;
    return 0;
}


static u32 event_net_response(struct nmp_data *nmp, const u32 session_id,
                              struct nmp_response *response, const u32 amt)
{
    if (nmp->status_cb == NULL)
    {
        log("callback not set, skipping response.");
        return 0;
    }

    if (amt != sizeof(struct nmp_response))
    {
        log("rejecting net_buf.amt != sizeof(nmp_response)");
        return 0;
    }

    struct session *ctx = hash_table_lookup(&nmp->sessions, session_id);
    if (ctx == NULL)
    {
        return 0;
    }

    if (ctx->state != SESSION_STATUS_RESPONSE)
    {
        // this also protects against duplicate responders
        log("state != SESSION_STATUS_RESPONSE");
        return 0;
    }

    struct session_initiation *initiation = ctx->initiation;
    if (noise_responder_read(&initiation->handshake,
                             &response->responder,
                             &response->header, sizeof(struct nmp_header),
                             (u8 *) &initiation->payload[1]))
    {
        log("failed to read response for %xu", ctx->session_id);
        return 0;
    }

    switch (nmp->status_cb(NMP_SESSION_RESPONSE,
                           (const union nmp_status_container *) &initiation->payload[1].data,
                           ctx->context_ptr))
    {
        case NMP_CMD_ACCEPT:
        {
            u8 k_recv[NOISE_KEYLEN];
            u8 k_send[NOISE_KEYLEN];

            ctx->noise_counter_send = 0;
            ctx->noise_counter_receive = 0;
            noise_split(&initiation->handshake,
                        k_send,
                        k_recv);

            if (EVP_EncryptInit_ex(ctx->noise_key_send, EVP_chacha20_poly1305(),
                                   NULL, k_send, NULL) != 1)
                return 1;

            if (EVP_DecryptInit_ex(ctx->noise_key_receive, EVP_chacha20_poly1305(),
                                   NULL, k_recv, NULL) != 1)
                return 1;

            mem_zero(ctx->initiation, sizeof(struct session_initiation));
            mem_free(ctx->initiation);

            break;
        }

        case NMP_CMD_DROP:
        {
            // no point having this session anymore
            hash_table_remove(&nmp->sessions, ctx->session_id);
            ctx->state = SESSION_STATUS_NONE;
            return 0;
        }

        default:
        {
            log("application did not accept response %xu", ctx->session_id);
            return 0;
        }
    }


    // checks completed
    ctx->state = SESSION_STATUS_ESTAB;

    // try to send early data
    switch (session_data(nmp, ctx))
    {
        case 0:
        {
            // if data has been sent
            if (ctx->state == SESSION_STATUS_ACKWAIT)
                return 0;

            break;
        }

        case 1:
            return 1;
    }

    // no data => keepalive
    if (session_keepalive(nmp, ctx))
        return 1;

    return nmp_ring_timer_update(nmp, ctx, nmp->keepalive_interval);
}


/*
 *  collect network events, distributing received
 *  packets into their contexts
 *
 *  return number of peers that received events
 *  -1 indicating error
 */
static struct session *event_net_collect(struct nmp_data *nmp,
                                         struct nmp_header *packet, const u32 packet_len,
                                         const union nmp_sa *addr)
{
    const struct nmp_header header = *packet;
    if (header.type & 0xfc // 0b11111100
        || (header.pad[0] | header.pad[1] | header.pad[2]))
    {
        log("rejecting: header format");
        return NULL;
    }

    if (header.session_id == 0)
    {
        log("rejecting reserved id value");
        return NULL;
    }

    if (header.type < NMP_DATA)
    {
        switch (header.type)
        {
            case NMP_REQUEST:
            {
                event_net_request(nmp, header.session_id, addr,
                                  (struct nmp_request *) packet, packet_len);
                return NULL;
            }

            case NMP_RESPONSE:
            {
                event_net_response(nmp, header.session_id,
                                   (struct nmp_response *) packet, packet_len);
                return NULL;
            }
        }
    }

    struct session *ctx = hash_table_lookup(&nmp->sessions, header.session_id);
    if (ctx == NULL)
    {
        log("rejecting %s for %xu: no context",
            nmp_dbg_packet_types[header.type], header.session_id);
        return NULL;
    }

    if (nmp->options & NMP_ADDR_VERIFY)
    {
        if (mem_cmp(&ctx->addr.sa, &addr->sa, sizeof(union nmp_sa)) != 0)
        {
            log("rejecting addr != recvfrom().addr");
            return NULL;
        }
    }

    if (packet_len % 16)
    {
        log("rejecting amt %% 16");
        return NULL;
    }

    u8 payload[MSG_MAX_PAYLOAD];
    const i32 payload_len = session_transport_receive(nmp, ctx,
                                                      (u8 *) packet, packet_len,
                                                      payload);
    if (payload_len < 0)
        return NULL;


    // process ready packets
    switch (header.type)
    {
        case NMP_DATA:
        {
            const i32 result = event_net_data(nmp, ctx, payload, payload_len);
            if (result <= 0)
                return NULL;

            ctx->events |= SESSION_EVENT_DATA;
            break;
        }

        case NMP_ACK:
        {
            if (!event_net_ack(nmp, ctx, payload, payload_len))
                return NULL;

            ctx->events |= SESSION_EVENT_ACK;
            break;
        }
    }

    ctx->stat_rx += packet_len;

    // if there are new events && not queued yet
    if (ctx->events && !(ctx->events & SESSION_EVENT_QUEUED))
    {
        ctx->events |= SESSION_EVENT_QUEUED;
        return ctx;
    }

    return NULL;
}


static u32 event_net_deliver(struct nmp_data *nmp,
                             struct session *ctx)
{
    if (ctx->state == SESSION_STATUS_NONE)
    {
        // one (possibly out of many) received packets triggered an error
        // that led to session_drop(), this context is not in hash table
        // anymore so no more data after 'fatal packet' but it can still
        // end up here in this queue => ignore
        return 0;
    }

    // if there are new messages
    if (ctx->events & SESSION_EVENT_DATA)
    {
        msg_deliver_data(&nmp->transport_callbacks,
                         &ctx->transport);

        // new data has been received, so it is irrelevant if those
        // messages were delivered or not, we must send out ack here
        if (session_ack(nmp, ctx))
            return 1;

        ctx->response_retries = 0;
    }

    // if there are new acks
    if (ctx->events & SESSION_EVENT_ACK)
    {
        switch (msg_deliver_ack(&nmp->transport_callbacks,
                                &ctx->transport))
        {
            case 0:
                break;

            case -1:
            {
                // everything has been acked
                ctx->state = SESSION_STATUS_ESTAB;
                if (nmp_ring_timer_update(nmp, ctx, nmp->keepalive_interval))
                    return 1;

                break;
            }

            default:
            {
                // if this ack contained any new messages, trigger
                // data transmission to fill the window back up
                ctx->state = SESSION_STATUS_ACKWAIT;
                if (session_data(nmp, ctx))
                    return 1;

                break;
            }
        }
    }

    // mark as processed
    ctx->events = 0;

    // also, if this context managed to get here
    // it is guaranteed that valid data has been
    // received, so it makes sense to reset counter
    ctx->timer_retries = 0;

    return 0;
}


static i32 event_network(struct nmp_data *nmp,
                         const struct io_uring_cqe *cqe,
                         struct session **ctx_ptr)
{
    const u32 bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
    struct nmp_recv_buf *buf = nmp->recv_net.base + bid;

    if ((cqe->flags & IORING_CQE_F_MORE) == 0)
    {
        log("updating multishot recvmsg");
        if (nmp_ring_recv_net(nmp))
            return 1;

        return 0;
    }

    struct io_uring_recvmsg_out *o = io_uring_recvmsg_validate(
            buf, cqe->res, &nmp->recv_hdr);
    if (o == NULL)
    {
        log("failed to validate recvmsg");
        goto out;
    }

    if (o->namelen > sizeof(union nmp_sa))
    {
        log("rejecting namelen");
        goto out;
    }

    struct nmp_header *packet = io_uring_recvmsg_payload(o, &nmp->recv_hdr);
    const u32 packet_len = io_uring_recvmsg_payload_length(o, cqe->res, &nmp->recv_hdr);

    log("received %u to buf %u (%s)", packet_len, bid,
        packet->type <= NMP_ACK ? nmp_dbg_packet_types[packet->type] : "unknown");

    if (packet_len >= NET_PACKET_MIN && packet_len <= NET_PACKET_MAX)
    {
        *ctx_ptr = event_net_collect(nmp, packet, packet_len,
                                     io_uring_recvmsg_name(o));
    }


    out:
    {
        nmp_ring_reuse_buf(nmp->recv_net.ring, buf,
                           sizeof(struct nmp_recv_buf), bid);
        return 0;
    }
}



///////////////////////////
///     public api      ///
///////////////////////////


static u32 nmp_destroy(struct nmp_data *nmp)
{
    errno = 0;

    if (hash_table_wipe(&nmp->sessions, (void *) session_destroy))
        return 1;

    if (nmp->recv_net.ring)
        munmap(nmp->recv_net.ring, nmp->recv_net.size);

    if (nmp->recv_local.ring)
        munmap(nmp->recv_local.ring, nmp->recv_local.size);

    if (nmp->ring.enter_ring_fd != -1)
        io_uring_queue_exit(&nmp->ring);

    if (nmp->evp_md_ctx)
        EVP_MD_CTX_free(nmp->evp_md_ctx);

    const i32 descriptors[] =
            {
                    nmp->net_udp,
                    nmp->local_rx,
                    nmp->local_tx,
            };

    for (u32 i = 0; i < sizeof(descriptors) / sizeof(u32); i++)
    {
        if (descriptors[i] == -1)
            continue;

        if (close(descriptors[i]))
        {
            log("failed to close() at index %xu", i);
            return 1;
        }
    }

    mem_zero(nmp, sizeof(struct nmp_data));
    mem_free(nmp);
    assert(errno == 0);

    return 0;
}


/*
 *  main type constructor:
 *  validate necessary values, create kernel structures,
 *  allocate memory and copy everything in
 */
struct nmp_data *nmp_new(const struct nmp_conf *conf)
{
    nmp_t *tmp = mem_alloc(sizeof(struct nmp_data));
    if (tmp == NULL)
    {
        return NULL;
    }

    // temporarily set descriptor values so that
    // destructor can figure out which ones to
    // close in case we have to call it
    mem_zero(tmp, sizeof(struct nmp_data));
    tmp->ring.enter_ring_fd = -1;
    tmp->local_tx = -1;
    tmp->local_rx = -1;
    tmp->net_udp = -1;

    const sa_family_t sa_family = conf->addr.sa.sa_family ? : AF_INET;
    if (sa_family != AF_INET && sa_family != AF_INET6)
    {
        log("sa_family");
        goto fail;
    }

    if (conf->payload &&
        (conf->payload < 492 || conf->payload > NMP_PAYLOAD_MAX))
    {
        goto fail;
    }

    const u16 ka = conf->keepalive_interval ? : SESSION_TIMER_KEEPALIVE;

    // if selected value is greater than default inactivity timeout, perform
    // 3 retries; otherwise perform enough retries to reach timeout naturally
    const u16 ka_max = conf->keepalive_interval >= SESSION_TIMER_TTL ?
                       SESSION_TIMER_RETRIES_TTL : SESSION_TIMER_TTL / ka;


    tmp->keepalive_interval = ka;
    tmp->sa_family = sa_family;
    tmp->recv_hdr.msg_namelen = sizeof(struct sockaddr_storage);

    tmp->retries[SESSION_STATUS_NONE] = 0;
    tmp->retries[SESSION_STATUS_RESPONSE] = SESSION_TIMER_RETRIES_MAX;
    tmp->retries[SESSION_STATUS_CONFIRM] = SESSION_TIMER_RETRIES_MAX;
    tmp->retries[SESSION_STATUS_WINDOW] = SESSION_TIMER_RETRIES_MAX;
    tmp->retries[SESSION_STATUS_ESTAB] = ka_max;
    tmp->retries[SESSION_STATUS_ACKWAIT] = SESSION_TIMER_RETRIES_MAX;

    tmp->options = conf->options;
    tmp->payload = conf->payload ? : NMP_PAYLOAD_MAX;
    tmp->payload += sizeof(struct msg_header); // we store 'real' payload limit

    tmp->request_context = conf->request_ctx;
    tmp->request_cb = conf->request_cb;
    tmp->status_cb = conf->status_cb;
    tmp->stats_cb = conf->stats_cb;

    tmp->transport_callbacks.data = conf->data_cb;
    tmp->transport_callbacks.data = conf->data_noack_cb;
    tmp->transport_callbacks.ack = conf->ack_cb;

    tmp->evp_hmac = HMAC_CTX_new();
    if (tmp->evp_hmac == NULL)
        goto fail;

    tmp->evp_md_ctx = EVP_MD_CTX_new();
    if (tmp->evp_md_ctx == NULL)
        goto fail;

    tmp->evp_cipher = EVP_CIPHER_CTX_new();
    if (tmp->evp_cipher == NULL)
        goto fail;

    noise_keypair_initialize(&tmp->static_keys, conf->key);
    noise_responder_init(&tmp->responder_precomp,
                         tmp->evp_hmac,
                         tmp->evp_md_ctx,
                         tmp->evp_cipher,
                         &tmp->static_keys);


    struct io_uring_params params = {0};
    params.cq_entries = RING_CQ;
    params.flags = 0
                   | IORING_SETUP_SUBMIT_ALL
                   | IORING_SETUP_COOP_TASKRUN
                   | IORING_SETUP_CQSIZE;

    if (io_uring_queue_init_params(RING_SQ, &tmp->ring, &params))
        goto fail;


    i32 socpair[2] = {0};
    if (socketpair(AF_UNIX, SOCK_DGRAM,
                   IPPROTO_IP, socpair) == -1)
        goto fail;

    tmp->local_rx = socpair[0];
    tmp->local_tx = socpair[1];

    tmp->net_udp = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (tmp->net_udp == -1)
        goto fail;

    if (bind(tmp->net_udp, &conf->addr.sa, sizeof(union nmp_sa)) == -1)
        goto fail;

    if (rnd_get(tmp->sessions.key, SIPHASH_KEY))
        goto fail;

    if (nmp_ring_setup_net(&tmp->ring, &tmp->recv_net))
        goto fail;

    if (nmp_ring_setup_local(&tmp->ring, &tmp->recv_local))
        goto fail;

    if (nmp_ring_recv_net(tmp))
        goto fail;

    if (nmp_ring_recv_local(tmp))
        goto fail;


    return tmp;
    fail:
    {
        log_errno();
        nmp_destroy(tmp);
        return NULL;
    }
}


u32 nmp_connect(struct nmp_data *nmp, const u8 *pub, const union nmp_sa *addr,
                const void *payload, const u32 payload_len, void *ctx)
{
    if (!pub || !addr || payload_len > NMP_INITIATION_PAYLOAD)
    {
        log("invalid args");
        return 0;
    }

    if (nmp->sa_family != addr->sa.sa_family)
    {
        log("sa_family");
        return 0;
    }

    const u32 id = rnd_get32();
    if (id == 0)
    {
        return 0;
    }

    struct session *ctx_new = session_new();
    if (ctx_new == NULL)
    {
        log_errno();
        return 0;
    }

    ctx_new->context_ptr = ctx;
    ctx_new->session_id = id;
    ctx_new->addr = *addr;
    noise_initiator_init(&ctx_new->initiation->handshake,
                         nmp->evp_hmac,
                         nmp->evp_md_ctx,
                         nmp->evp_cipher,
                         &nmp->static_keys, pub);

    if (payload)
    {
        mem_copy(ctx_new->initiation->payload[0].data,
                 payload, payload_len);
    }

    struct nmp_local_request request =
            {
                    .type = EVENT_LOCAL_NEW,
                    .len = 0,
                    .session = id,
                    .payload_ctx_new = ctx_new,
            };

    if (write(nmp->local_tx, &request,
              sizeof(struct nmp_local_request)) == -1)
    {
        session_destroy(ctx_new);
        return 0;
    }

    return id;
}


u32 nmp_send(struct nmp_data *nmp, const u32 session,
             const u8 *buf, const u16 len)
{
    if (!nmp || !session || !buf || !len)
    {
        log("invalid args");
        return 1;
    }

    // stored payload includes msg_header size
    if (len + sizeof(struct msg_header) > nmp->payload)
    {
        return 1;
    }

    u8 *data = mem_alloc(EVENT_REQUEST_MALLOC);
    if (data == NULL)
    {
        log_errno();
        return 1;
    }

    struct nmp_local_request request =
            {
                    .type = EVENT_LOCAL_DATA,
                    .len = len,
                    .session = session,
                    .payload_data = data,
            };

    mem_copy(data, buf, len);
    if (write(nmp->local_tx, &request,
              sizeof(struct nmp_local_request)) == -1)
    {
        mem_free(data);
        return 1;
    }

    return 0;
}


u32 nmp_send_noack(struct nmp_data *nmp, const u32 session,
                   const u8 *buf, const u16 len)
{
    if (!nmp || !session || !buf || !len)
    {
        log("invalid args");
        return 1;
    }

    // stored payload includes msg_header size
    if (len + sizeof(struct msg_header) > nmp->payload)
    {
        return 1;
    }

    // noack messages are not buffered so let's avoid
    // extra copying and assemble them in-place:
    struct msg_header *data = mem_alloc(EVENT_REQUEST_MALLOC);
    if (data == NULL)
    {
        log_errno();
        return 1;
    }

    msg_assemble_noack(data, buf, len);

    struct nmp_local_request request =
            {
                    .type = EVENT_LOCAL_DATA_NOACK,
                    .len = len,
                    .session = session,
                    .payload_noack  = data,
            };

    if (write(nmp->local_tx, &request,
              sizeof(struct nmp_local_request)) == -1)
    {
        mem_free(data);
        return 1;
    }

    return 0;
}


/*
 *  get local key_public key; always safe to access
 *  since it won't be modified by anything after returns
 */
void nmp_pubkey(const nmp_t *nmp, u8 buf[NMP_KEYLEN])
{
    mem_copy(buf, nmp->static_keys.public, NMP_KEYLEN);
}


u32 nmp_drop(struct nmp_data *nmp, const u32 session)
{
    if (session == 0)
    {
        log("cannot drop session 0");
        return 1;
    }

    const struct nmp_local_request request =
            {
                    .type = EVENT_LOCAL_DROP,
                    .len = 0,
                    .session = session,
                    .payload_ptr = NULL
            };

    return (write(nmp->local_tx, &request,
                  sizeof(struct nmp_local_request)) == -1);
}


u32 nmp_terminate(struct nmp_data *nmp)
{
    const struct nmp_local_request request =
            {
                    .type = EVENT_LOCAL_TERM,
                    .len = 0,
                    .session = 0,
                    .payload_ptr = NULL,
            };

    return (write(nmp->local_tx, &request,
                  sizeof(struct nmp_local_request)) == -1);
}


/*
 *  main event loop
 *  block on epoll_wait() and distribute
 *  events to appropriate handlers
 */
u32 nmp_run(struct nmp_data *nmp, const i32 timeout)
{
    UNUSED(timeout); // fixme

    for (;;)
    {
        const i32 submitted = io_uring_submit_and_wait(&nmp->ring, 1);
        if (submitted < 0)
        {
            log("wait interrupted: %s", strerrorname_np(-submitted));

            // -errno
            switch (-submitted)
            {
                case EINTR: // interrupted by a signal
                    continue;

                default:
                    return 1;
            }
        }

        struct io_uring_cqe *cqes[RING_BATCH] = {0};
        u32 batch = io_uring_peek_batch_cqe(&nmp->ring, cqes, RING_BATCH);
        if (batch == 0)
        {
            log("empty batch");
            continue;
        }

        struct session *events_queue[RING_BATCH] = {0};
        u32 queued = 0;


        for (u32 i = 0; i < batch; i++)
        {
            if (cqes[i]->res < 0)
            {
                log("cqe status %s (%p)",
                    strerrorname_np(-cqes[i]->res),
                    io_uring_cqe_get_data(cqes[i]));
                u32 crit = 0;

                switch (-cqes[i]->res)
                {
                    case ETIME:
                        crit = event_timer(nmp, io_uring_cqe_get_data(cqes[i]));
                        break;

                    case ENOENT:
                    {
                        struct session *ctx = io_uring_cqe_get_data(cqes[i]);
                        crit = nmp_ring_timer_set(nmp, ctx, ctx->kts.tv_sec);
                        break;
                    }

                    case EPERM: // todo
                        break;

                    case ENOBUFS:
                    {
                        if (cqes[i]->user_data > RING_LOCAL_GROUP)
                            return 1;

                        crit = (cqes[i]->user_data == RING_NET_GROUP) ?
                               nmp_ring_recv_net(nmp) : nmp_ring_recv_local(nmp);
                        break;
                    }

                    default:
                        return 1;
                }

                if (crit)
                    return 1;

                continue;
            }

            // no errors and not a buffer, probably successful timer update
            if ((cqes[i]->flags & IORING_CQE_F_BUFFER) == 0)
                continue;

            i32 result = 0;
            struct session *ctx = NULL;

            switch (io_uring_cqe_get_data64(cqes[i]))
            {
                case RING_CQ_NET:
                    result = event_network(nmp, cqes[i], &ctx);
                    break;

                case RING_CQ_LOCAL:
                    result = event_local(nmp, cqes[i], &ctx);
                    break;
            }

            switch (result)
            {
                case 0:
                    break;
                case 1:
                    return nmp_destroy(nmp);
                default:
                    return 1;
            }

            if (ctx)
            {
                events_queue[queued] = ctx;
                queued += 1;
            }
        }

        io_uring_cq_advance(&nmp->ring, batch);

        for (u32 i = 0; i < queued; i++)
        {
            if (event_net_deliver(nmp, events_queue[i]))
                return 1;
        }
    }
}
