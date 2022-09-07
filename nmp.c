/*
 *
 */
#include "nmp.h"

#include "chacha20_poly1305.h" // https://github.com/phgm-d3ab/chacha20_poly1305
#include "curve25519-donna.h"  // https://github.com/phgm-d3ab/curve25519-donna
#include "blake2s.h"           // https://github.com/phgm-d3ab/blake2

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>

#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/random.h>


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


#   define log(fmt_, ...)  __log(fmt_, ##__VA_ARGS__)
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


// http://man7.org/linux/man-pages/man2/epoll_create.2.html#NOTES
#define EPOLL_CREATE        1
#define EPOLL_QUEUELEN      64

// minimum: header + tag
// maximum: header + msg_header + payload + tag
#define PACKET_MIN          32
#define PACKET_MAX          (NMP_PAYLOAD_MAX + 36)

// if we receive more data than protocol supports, this
// is a good indicator to discard that datagram immediately
#define NET_BUFSIZE         (PACKET_MAX + 8)



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
 *  timerfd
 */
#define TIMER_BUF (2 * sizeof(u64))

#ifdef NMP_DEBUG_TIMERS

static inline i32 timerfd_interval(const i32 timer, const i32 interval)
{
    UNUSED(timer);
    UNUSED(interval);

    return 0;
}

#else

static inline u32 timerfd_interval(const i32 timer, const u32 interval)
{
    struct itimerspec its = {0};

    // modify initial delay too,
    // zero disarms the timer
    its.it_value.tv_sec = interval;
    its.it_interval.tv_sec = interval;

    if (timerfd_settime(timer, 0, &its, NULL))
    {
        log_errno();
        return 1;
    }

    log("tfd %u %u s", timer, interval);
    return 0;
}

#endif // NMP_DEBUG_TIMERS


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
            {
                continue;
            }

            default:
            {
                return 1;
            }
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
 *  network io
 */
// http://man7.org/linux/man-pages/man3/sendto.3p.html#DESCRIPTION
#define SENDTO_OPT      0
#define RECVFROM_OPT    0


// return zero for success
static inline u32 network_send(const i32 soc,
                               const void *data,
                               const u32 amt,
                               const nmp_sa *addr)
{
    const isize sent = sendto(soc, data, amt,
                              SENDTO_OPT,
                              &addr->sa, sizeof(nmp_sa));

    log("%s %zi", nmp_dbg_packet_types[*((u8 *) data)], sent);

    if (sent != (isize) amt)
    {
        log_errno();
        return 1;
    }

    return 0;
}

// return size of full packet or zero for discard
static inline u32 network_receive(const i32 soc,
                                  u8 *buf,
                                  nmp_sa *addr)
{
    // important to initialize this
    // http://man7.org/linux/man-pages/man3/recvfrom.3p.html#DESCRIPTION
    socklen_t addr_len = sizeof(nmp_sa);
    const isize amt = recvfrom(soc, buf, NET_BUFSIZE,
                               RECVFROM_OPT,
                               &addr->sa, &addr_len);

    log("%s %zi (%s)",
        (amt > 0 && *buf < 4) ? nmp_dbg_packet_types[*buf] : "",
        amt, strerrorname_np(errno));

    if (amt < PACKET_MIN || amt > PACKET_MAX)
    {
        return 0;
    }

    return (u32) amt;
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

typedef struct
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

} hash_table;


static u64 hash_table_hash(hash_table *ht, const u32 key)
{
    const u32 index = key & (HASH_TABLE_CACHE - 1);
    if (ht->cache[index].id == key)
    {
        return ht->cache[index].hash;
    }

    const u64 hash = siphash(ht->key, (const u8 *) &key, sizeof(u32));
    ht->cache[index].id = key;
    ht->cache[index].hash = hash;

    return hash;
}


static u32 hash_table_slot(hash_table *ht, const u64 hash, const u32 item)
{
    const u32 natural_slot = (u32) hash & (HASH_TABLE_RS - 1);

    u32 index = HASH_TABLE_NF;
    u32 index_swap = HASH_TABLE_NF;

    for (u32 i = 0; i < HASH_TABLE_RS; i++)
    {
        index = (natural_slot + i) & (HASH_TABLE_RS - 1);
        if (ht->entry[index].id == item)
        {
            break;
        }

        if (ht->entry[index].status == entry_deleted)
        {
            if (index_swap == HASH_TABLE_NF)
            {
                index_swap = index;
            }

            continue;
        }

        if (ht->entry[index].status == entry_empty)
        {
            break;
        }
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


static void *hash_table_lookup(hash_table *ht, const u32 id)
{
    const u64 hash = hash_table_hash(ht, id);
    const u32 slot = hash_table_slot(ht, hash, id);

    if (slot == HASH_TABLE_NF || ht->entry[slot].id != id)
    {
        return NULL;
    }

    return ht->entry[slot].ptr;
}


static u32 hash_table_insert(hash_table *ht, const u32 id, void *ptr)
{
    if (ht->items >= HASH_TABLE_SIZE)
    {
        return 1;
    }

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


static void hash_table_remove(hash_table *ht, const u32 id)
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


static i32 hash_table_wipe(hash_table *ht, u32 (*destructor)(void *))
{
    for (u32 i = 0; ht->items && i < HASH_TABLE_RS; i++)
    {
        if (ht->entry[i].ptr)
        {
            if (destructor(ht->entry[i].ptr))
            {
                log("destructor failed (%p)", ht->entry[i].ptr);
                return 1;
            }

            ht->items -= 1;
        }
    }

    return 0;
}

/*
 *  socket pair wrappers
 */
#define LOCAL_PAYLOAD_MAX   32

// serves as a header for local messages
typedef struct
{
    u16 type;
    u16 len;
    u32 id;

//    u8 payload[];

} local_event;


static isize local_receive(const i32 soc,
                           local_event *output)
{
    return read(soc, output, sizeof(local_event) + LOCAL_PAYLOAD_MAX);
}


static u32 local_send(const i32 soc,
                      const local_event *event,
                      const void *payload,
                      const u32 payload_len)
{
    struct
    {
        local_event ev;
        u8 payload[LOCAL_PAYLOAD_MAX];

    } buf = {0};

    buf.ev = *event;
    if (payload)
    {
        mem_copy(buf.payload, payload, payload_len);
    }

    const u32 amt = sizeof(local_event) + payload_len;
    if (write(soc, &buf, amt) != amt)
    {
        log_errno();
        return 1;
    }

    return 0;
}


/*
 *
 */
#define MSG_ALLOC_BLOCK 2048
#define MSG_MASK_BITS   64
#define MSG_MASK_INIT   UINT64_MAX
#define MSG_WINDOW      64
#define MSG_TXQUEUE     NMP_QUEUE
#define MSG_RXQUEUE     MSG_MASK_BITS
#define MSG_PAYLOAD     (NMP_PAYLOAD_MAX + 16)

// these are the flags for message header length field
#define MSG_NOACK       ((u16)(1 << 15))
#define MSG_RESERVED    ((u16)(1 << 14))


// payload message
typedef struct
{
    u16 sequence;
    u16 len;

    u8 data[];

} msg_header;


// acknowledgement packet
typedef struct
{
    u16 ack;
    u16 pad[3];
    u64 ack_mask;

} msg_ack;


// outgoing queue
typedef struct
{
    enum
    {
        MSG_TX_EMPTY = 0,
        MSG_TX_SENT = 1,
        MSG_TX_QUEUED = 2,
        MSG_TX_ACKED = 3,

    } status;

    u16 seq;
    u16 len;
    u64 id;

    u8 *msg;

} msg_tx;


// receive buffer
typedef struct
{
    enum
    {
        MSG_RX_EMPTY = 0,
        MSG_RX_RECEIVED = 1,

    } status;

    u16 seq;
    u16 len;

    u8 data[NMP_PAYLOAD_MAX];

} msg_rx;


typedef struct
{
    void (*data)(const u8 *, u32, void *);
    void (*data_noack)(const u8 *, u32, void *);
    void (*ack)(u64, void *);

} msg_routines;


typedef struct
{
    void *context_ptr;

    u16 tx_seq;
    u16 tx_sent;
    u16 tx_ack;
    u64 tx_counter;

    u16 rx_seq;
    u16 rx_delivered;

    msg_tx tx_queue[MSG_TXQUEUE];
    msg_rx rx_buffer[MSG_RXQUEUE];

} msg_state;


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

    assert(payload_len <= MSG_PAYLOAD);
    return payload_len;
}


static inline void msg_tx_include(const msg_tx *tx, msg_header *msg)
{
    msg->sequence = tx->seq;
    msg->len = tx->len;

    mem_copy(msg->data, tx->msg, tx->len);
    log("seq %u %s", msg->sequence, nmp_dbg_msg_status[tx->status]);
}


static inline void msg_rx_copy(msg_rx *entry, const msg_header *msg)
{
    entry->status = MSG_RX_RECEIVED;
    entry->seq = msg->sequence;
    entry->len = msg->len;

    mem_copy(entry->data, msg->data, msg->len);
    log("seq %u len %u", msg->sequence, msg->len);
}


static inline u64 msg_get_latest(const msg_state *ctx)
{
    return tx_get(ctx, ctx->tx_ack)->id;
}


/*
 *  simply free() remaining messages
 *  that were not acknowledged yet
 */
static void msg_context_wipe(msg_state *ctx)
{
    for (u16 i = ctx->tx_ack;; i++)
    {
        msg_tx *entry = tx_get(ctx, i);
        if (entry->status != MSG_TX_EMPTY)
        {
            mem_free(entry->msg);
        }

        if (i == ctx->tx_seq)
        {
            break;
        }
    }
}


/*
 *
 */
static u32 msg_queue(msg_state *ctx, const u8 *msg, const u16 len)
{
    assert(msg);

    // pre-increment: check one ahead
    const u32 index = (ctx->tx_seq + 1) & (MSG_TXQUEUE - 1);
    msg_tx *entry = ctx->tx_queue + index;

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
static i32 msg_assemble(msg_state *ctx,
                        u8 *output, const u32 payload_limit)
{
    msg_tx *resend_queue[MSG_WINDOW] = {0};
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
        msg_tx *msg = tx_get(ctx, i);
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
            const u32 offset = msg->len + sizeof(msg_header);
            if (bytes + offset > payload_limit)
            {
                break;
            }

            msg_tx_include(msg, (msg_header *) (output + bytes));

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
        const u16 offset = resend_queue[i]->len + sizeof(msg_header);
        if (bytes + offset > payload_limit)
        {
            break;
        }

        msg_tx_include(resend_queue[i], (msg_header *) (output + bytes));
        bytes += offset;
    }

    return msg_payload_zeropad(output, (i32) bytes);
}


static u32 msg_assemble_retry(msg_state *ctx,
                              u8 *output, const u32 payload_limit)
{
    u32 bytes = 0;

    for (u16 i = ctx->tx_ack + 1;; i++)
    {
        msg_tx *msg = tx_get(ctx, i);
        if (msg->status == MSG_TX_SENT)
        {
            const u16 offset = msg->len + sizeof(msg_header);
            if (bytes + offset > payload_limit)
            {
                break;
            }

            msg_tx_include(msg, (msg_header *) (output + bytes));
            bytes += offset;
        }

        if (i == ctx->tx_sent)
        {
            break;
        }
    }

    return (u32) msg_payload_zeropad(output, (i32) bytes);
}

/*
 *  build a noack message in-place
 */
u32 msg_assemble_noack(msg_header *header, const u8 *payload, const u16 len)
{
    header->sequence = 0;
    header->len = len;
    header->len |= MSG_NOACK;

    mem_copy(header->data, payload, len);
    return msg_payload_zeropad(header->data, (i32) (len + sizeof(msg_header)));
}


/*
 *  return number of new messages
 */
static i32 msg_read(const msg_routines *cb, msg_state *ctx,
                    const u8 *payload, const u32 len)
{
    u32 iterator = 0;
    i32 new_messages = 0;
    u32 discovered = 0;

    const u16 seq_low = ctx->rx_delivered;
    const u16 seq_high = (u16) (seq_low + MSG_WINDOW);

    for (;; discovered++)
    {
        const msg_header *msg = (const msg_header *) (payload + iterator);
        if ((len - iterator) <= sizeof(msg_header))
        {
            break;
        }

        if (msg->len == 0)
        {
            break;
        }

        const u16 msg_len = msg->len & ~(MSG_NOACK | MSG_RESERVED);
        // example: msg->len == 1000 but there are 100 bytes left
        // to read in the packet; lets have a protection against this
        const u16 msg_maxlen = (u16) (len - iterator - sizeof(msg_header));
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
            {
                cb->data_noack(msg->data, msg->len, ctx->context_ptr);
            }

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

            // update rx_seq?
            if (msg_sequence_cmp(msg->sequence, ctx->rx_seq))
            {
                ctx->rx_seq = msg->sequence;
            }

            msg_rx *entry = rx_get(ctx, msg->sequence);
            if (entry->status == MSG_RX_EMPTY)
            {
                new_messages += 1;
                msg_rx_copy(entry, msg);
            }
        }

        iterator += (msg->len + sizeof(msg_header));
    }

    return new_messages;
}

/*
 *  this can be called only if there are new messages to deliver
 */
static void msg_deliver_data(const msg_routines *cb,
                             msg_state *ctx)
{
    for (u16 n = ctx->rx_delivered + 1;; n++)
    {
        msg_rx *entry = rx_get(ctx, n);
        if (entry->status == MSG_RX_EMPTY)
        {
            break;
        }

        if (cb->data)
        {
            cb->data(entry->data, entry->len, ctx->context_ptr);
        }

        ctx->rx_delivered = n;
        entry->status = MSG_RX_EMPTY;

        if (n == ctx->rx_seq)
        {
            break;
        }
    }
}

/*
 *  start with all bits set, then walk backwards
 *  clearing bits for missing messages
 */
static u32 msg_ack_assemble(const msg_state *ctx, msg_ack *ack)
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

        const msg_rx *entry = rx_get(ctx, i);
        if (entry->status == MSG_RX_EMPTY)
        {
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
static i32 msg_ack_read(msg_state *ctx, const msg_ack *ack)
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
                msg_tx *msg = tx_get(ctx, i);
                if (msg->status == MSG_TX_SENT)
                {
                    msg->status = MSG_TX_ACKED;
                    discovered += 1;
                }
            }

            if (i == ctx->tx_ack)
            {
                break;
            }

            mask >>= 1;
        }
    }

    return discovered;
}


/*
 *
 */
static i32 msg_deliver_ack(const msg_routines *cb, msg_state *ctx)
{
    i32 counter = 0;

    // plus one: tx_ack is the number of a processed
    // message, start with the next one
    for (u16 i = ctx->tx_ack + 1;; i++)
    {
        msg_tx *msg = tx_get(ctx, i);
        if (msg->status != MSG_TX_ACKED)
        {
            break;
        }

        if (cb->ack)
        {
            cb->ack(msg->id, ctx->context_ptr);
        }

        mem_free(msg->msg);
        msg->status = MSG_TX_EMPTY;

        ctx->tx_ack = msg->seq;
        counter += 1;

        if (msg->seq == ctx->tx_sent)
        {
            break;
        }
    }

    if (ctx->tx_ack == ctx->tx_seq)
    {
        return -1;
    }

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
#define NOISE_HASHLEN           32
#define NOISE_DHLEN             32
#define NOISE_BLOCKLEN          64
#define NOISE_AEAD_MAC          16
#define NOISE_NONCE_MAX         UINT64_MAX
#define NOISE_HANDSHAKE_PAYLOAD 128

#define NOISE_COUNTER_WINDOW    224


const char *noise_protocol_name = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
const u8 noise_protocol_hash[] = {0xbb, 0xea, 0x02, 0x2b, 0x94, 0x8c, 0xf3, 0xbc,
                                  0x58, 0x57, 0xd7, 0x08, 0x04, 0x22, 0x91, 0x79,
                                  0xe1, 0x11, 0x6b, 0xc4, 0x0c, 0xb8, 0xcc, 0x07,
                                  0x48, 0x35, 0x34, 0x9c, 0x46, 0x4b, 0xca, 0x36};


typedef struct
{
    u8 ephemeral[NOISE_DHLEN];
    u8 encrypted_static[NOISE_DHLEN];
    u8 mac1[NOISE_AEAD_MAC];
    u8 encrypted_payload[NOISE_HANDSHAKE_PAYLOAD];
    u8 mac2[NOISE_AEAD_MAC];

} noise_initiator;


typedef struct
{
    u8 ephemeral[NOISE_DHLEN];
    u8 encrypted_payload[NOISE_HANDSHAKE_PAYLOAD];
    u8 mac[NOISE_AEAD_MAC];

} noise_responder;


typedef struct
{
    u8 private[NOISE_DHLEN];
    u8 public[NOISE_DHLEN];

} noise_keypair;


typedef struct
{
    u8 cipher_k[NOISE_KEYLEN];
    u64 cipher_n;
    u8 symmetric_ck[NOISE_HASHLEN];
    u8 symmetric_h[NOISE_HASHLEN];

    noise_keypair *s;
    noise_keypair e;
    u8 rs[NOISE_DHLEN];
    u8 re[NOISE_DHLEN];

} noise_handshake;


static inline void noise_hash(const void *data, const u32 data_len,
                              u8 output[NOISE_HASHLEN])
{
    blake2s(output, NOISE_HASHLEN,
            NULL, 0,
            data, data_len);
}


/*
 *  https://en.wikipedia.org/wiki/HMAC
 *  but only for NOISE_KEYLEN (32) byte keys
 */
static inline void noise_hmac_hash(const u8 key[NOISE_KEYLEN],
                                   const void *data, const u32 data_len,
                                   u8 output[NOISE_HASHLEN])
{
    u8 K_opad[NOISE_BLOCKLEN] = {0};
    u8 K_ipad[NOISE_BLOCKLEN] = {0};

    for (u32 i = 0; i < NOISE_KEYLEN; i++)
    {
        K_opad[i] ^= (key[i] ^ 0x5c);
        K_opad[i + NOISE_KEYLEN] = 0x5c;

        K_ipad[i] ^= (key[i] ^ 0x36);
        K_ipad[i + NOISE_KEYLEN] = 0x36;
    }

    u8 hash_inner[NOISE_HASHLEN] = {0};
    blake2s_ctx ctx_inner = {0};
    blake2s_init(&ctx_inner, NOISE_HASHLEN, NULL, 0);
    blake2s_update(&ctx_inner, K_ipad, NOISE_BLOCKLEN);
    blake2s_update(&ctx_inner, data, data_len);
    blake2s_final(&ctx_inner, hash_inner);

    blake2s_ctx ctx_outer = {0};
    blake2s_init(&ctx_outer, NOISE_HASHLEN, NULL, 0);
    blake2s_update(&ctx_outer, K_opad, NOISE_BLOCKLEN);
    blake2s_update(&ctx_outer, hash_inner, NOISE_HASHLEN);
    blake2s_final(&ctx_outer, output);
}


// noise spec has third output, but it is not used
// in this handshake pattern so not included here
static void noise_hkdf(const u8 *ck, const u8 *ikm,
                       u8 *output1,
                       u8 *output2)
{
    const u8 byte_1 = 0x01;
    u8 temp_key[NOISE_KEYLEN] = {0};
    noise_hmac_hash(ck,
            // necessary to avoid null pointer exception
            // when passing 'zerolen' (current blake2s version)
                    ikm, ikm ? NOISE_KEYLEN : 0,
                    temp_key);

    noise_hmac_hash(temp_key,
                    &byte_1, sizeof(u8),
                    output1);

    u8 buf1[40] = {0};
    mem_copy(buf1, output1, NOISE_HASHLEN);
    buf1[NOISE_HASHLEN] = 0x02; // h || byte(0x02)
    noise_hmac_hash(temp_key,
                    buf1, NOISE_HASHLEN + sizeof(u8),
                    output2);
}


static inline void noise_dh(const noise_keypair *key_pair,
                            const u8 *public_key,
                            u8 *shared_secret)
{
    u8 temp[NOISE_DHLEN] = {0};
    curve25519_donna(temp,
                     key_pair->private,
                     public_key);
    noise_hash(temp, NOISE_DHLEN, shared_secret);
}


static inline void noise_keypair_initialize(noise_keypair *pair)
{
    const u8 basepoint[32] = {9};

    pair->private[0] &= 248;
    pair->private[31] &= 127;
    pair->private[31] |= 64;

    curve25519_donna(pair->public,
                     pair->private,
                     basepoint);
}


static u32 noise_keypair_generate(noise_keypair *pair)
{
    u8 buf[64] = {0};
    if (rnd_get(&buf, sizeof(buf)))
    {
        return 1;
    }

    noise_hash(buf, 64, pair->private);
    noise_keypair_initialize(pair);
    return 0;
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


static inline void noise_encrypt(const u8 *k, const u64 n,
                                 const void *ad, const u32 ad_len,
                                 const void *plaintext, const u32 plaintext_len,
                                 u8 *ciphertext, u8 *mac)
{
    u8 nonce[12];
    noise_chacha20_nonce(n, nonce);

    chacha20_poly1305_encrypt(k, nonce,
                              ad, ad_len,
                              plaintext, plaintext_len,
                              ciphertext, mac);
}


static inline u32 noise_decrypt(const u8 *k, const u64 n,
                                const void *ad, const u32 ad_len,
                                const u8 *ciphertext, const u32 ciphertext_len,
                                const u8 *mac, void *plaintext)
{
    u8 nonce[12];
    noise_chacha20_nonce(n, nonce);

    return chacha20_poly1305_decrypt(k, nonce,
                                     ad, ad_len,
                                     ciphertext, ciphertext_len,
                                     mac, plaintext);
}


static void noise_mix_key(noise_handshake *state,
                          const u8 *ikm)
{
    u8 temp_ck[NOISE_KEYLEN];
    mem_copy(temp_ck, state->symmetric_ck, NOISE_KEYLEN);

    noise_hkdf(temp_ck, ikm,
               state->symmetric_ck,
               state->cipher_k);

    // one of hkdf outputs is our 'temp_k'
    // which effectively does initialize_key(temp_k)
}


static void noise_mix_hash(noise_handshake *state,
                           const void *data, const u32 data_len)
{
    blake2s_ctx ctx = {0};
    blake2s_init(&ctx, NOISE_HASHLEN, NULL, 0);
    blake2s_update(&ctx, state->symmetric_h, NOISE_HASHLEN);
    blake2s_update(&ctx, data, data_len);
    blake2s_final(&ctx, state->symmetric_h);
}


// serves as a mix_key(dh(..))
static void noise_mix_key_dh(noise_handshake *state,
                             const noise_keypair *pair, const u8 *public_key)
{
    u8 temp_dh[NOISE_DHLEN] = {0};
    noise_dh(pair, public_key, temp_dh);
    noise_mix_key(state, temp_dh);
}


static void noise_encrypt_and_hash(noise_handshake *state,
                                   const void *plaintext, const u32 plaintext_len,
                                   u8 *ciphertext, u8 *mac)
{
    noise_encrypt(state->cipher_k, state->cipher_n,
                  state->symmetric_h, NOISE_HASHLEN,
                  plaintext, plaintext_len,
                  ciphertext, mac);
    noise_mix_hash(state, ciphertext, plaintext_len);
}


static u32 noise_decrypt_and_hash(noise_handshake *state,
                                  const u8 *ciphertext, const u32 ciphertext_len,
                                  const u8 *mac, void *plaintext)
{
    if (noise_decrypt(state->cipher_k, state->cipher_n,
                      state->symmetric_h, NOISE_HASHLEN,
                      ciphertext, ciphertext_len,
                      mac, plaintext))
    {
        return 1;
    }

    noise_mix_hash(state, ciphertext, ciphertext_len);
    return 0;
}


static void noise_split(const noise_handshake *state,
                        u8 *c1, u8 *c2)
{
    noise_hkdf(state->symmetric_ck, NULL, // 'zerolen'
               c1, c2);
}


static void noise_initiator_init(noise_handshake *state,
                                 noise_keypair *s,
                                 const u8 *rs)
{
    UNUSED(noise_protocol_name);
    // instead of h = HASH(protocol_name) use precomputed value
    mem_copy(state->symmetric_h, noise_protocol_hash, NOISE_HASHLEN);
    mem_copy(state->symmetric_ck, noise_protocol_hash, NOISE_HASHLEN);

    state->s = s;
    mem_copy(state->rs, rs, NOISE_KEYLEN);
    noise_mix_hash(state, rs, NOISE_KEYLEN);
}


static u32 noise_initiator_write(noise_handshake *state,
                                 noise_initiator *initiator,
                                 const void *ad, const u32 ad_len,
                                 const u8 *payload)
{
    noise_mix_hash(state, ad, ad_len);

    // e
    if (noise_keypair_generate(&state->e))
    {
        return 1;
    }

    noise_mix_hash(state, state->e.public, NOISE_DHLEN);
    mem_copy(initiator->ephemeral, state->e.public, NOISE_KEYLEN);

    // es
    noise_mix_key_dh(state, &state->e, state->rs);

    // s
    noise_encrypt_and_hash(state,
                           state->s->public, NOISE_DHLEN,
                           initiator->encrypted_static,
                           initiator->mac1);

    // ss
    noise_mix_key_dh(state, state->s, state->rs);

    // payload: encrypt_and_hash(payload)
    noise_encrypt_and_hash(state,
                           payload, NOISE_HANDSHAKE_PAYLOAD,
                           initiator->encrypted_payload, initiator->mac2);
    return 0;
}


static u32 noise_responder_read(noise_handshake *state,
                                const noise_responder *responder,
                                const void *ad, const u32 ad_len,
                                u8 *payload)
{
    noise_mix_hash(state, ad, ad_len);

    // e
    noise_mix_hash(state, responder->ephemeral, NOISE_DHLEN);

    // ee
    noise_mix_key_dh(state, &state->e, responder->ephemeral);

    // se
    noise_mix_key_dh(state, state->s, responder->ephemeral);

    // payload
    return noise_decrypt_and_hash(state,
                                  responder->encrypted_payload, NOISE_HANDSHAKE_PAYLOAD,
                                  responder->mac, payload);
}


static void noise_responder_init(noise_handshake *state,
                                 noise_keypair *s)
{
    state->s = s;
    mem_copy(state->symmetric_h, noise_protocol_hash, NOISE_HASHLEN);
    mem_copy(state->symmetric_ck, noise_protocol_hash, NOISE_HASHLEN);
    noise_mix_hash(state, s->public, NOISE_DHLEN);
}


static u32 noise_initiator_read(noise_handshake *state,
                                const noise_initiator *initiator,
                                const void *ad, const u32 ad_len,
                                u8 *payload)
{
    noise_mix_hash(state, ad, ad_len);

    // e
    mem_copy(state->re, initiator->ephemeral, NOISE_DHLEN);
    noise_mix_hash(state, state->re, NOISE_DHLEN);

    // es
    noise_mix_key_dh(state, state->s, state->re);

    // s
    if (noise_decrypt_and_hash(state, initiator->encrypted_static, NOISE_DHLEN,
                               initiator->mac1, state->rs))
    {
        return 1;
    }

    // ss
    noise_mix_key_dh(state, state->s, state->rs);

    // payload
    return noise_decrypt_and_hash(state,
                                  initiator->encrypted_payload, NOISE_HANDSHAKE_PAYLOAD,
                                  initiator->mac2, payload);
}


static u32 noise_responder_write(noise_handshake *state,
                                 noise_responder *responder,
                                 const void *ad, const u32 ad_len,
                                 const void *payload)
{
    noise_mix_hash(state, ad, ad_len);

    // e
    if (noise_keypair_generate(&state->e))
    {
        return 1;
    }

    noise_mix_hash(state, state->e.public, NOISE_DHLEN);
    mem_copy(responder->ephemeral, state->e.public, NOISE_DHLEN);

    // ee
    noise_mix_key_dh(state, &state->e, state->re);

    // se
    noise_mix_key_dh(state, &state->e, state->rs);

    // payload
    noise_encrypt_and_hash(state,
                           payload, NOISE_HANDSHAKE_PAYLOAD,
                           responder->encrypted_payload, responder->mac);
    return 0;
}


static i32 noise_counter_validate(const u32 block[8],
                                  const u64 local,
                                  const u64 remote)
{
    // if too old
    if (remote + NOISE_COUNTER_WINDOW < local)
    {
        return -1;
    }

    if (remote > (local + NOISE_COUNTER_WINDOW) || remote == NOISE_NONCE_MAX)
    {
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


#define callback(call_, ...) ({ if (call_) { call_(__VA_ARGS__); } \
                            else { log("skipping empty %s", #call_); }})

#define header_initialize(type_, id_) (nmp_header) { \
                        .type = (type_),             \
                        .pad[0] = 0,                 \
                        .pad[1] = 0,                 \
                        .pad[2] = 0,                 \
                        .session_id = (id_)}

static_assert(NMP_KEYLEN == NOISE_KEYLEN, "keylen");

typedef struct nmp_data *main_context;
typedef struct session *session_context;


enum packet_types
{
    NMP_REQUEST = 0,
    NMP_RESPONSE = 1,
    NMP_DATA = 2,
    NMP_ACK = 3,
};


typedef struct
{
    u8 type;
    u8 pad[3];
    u32 session_id;

} nmp_header;


typedef struct
{
    nmp_header header;
    noise_initiator initiator;

} nmp_request;


typedef struct
{
    nmp_header header;
    noise_responder responder;

} nmp_response;


typedef struct
{
    struct
    {
        nmp_header type_pad_id;
        u64 counter;

    } header;

    u8 payload[0];
    // u8 mac[16];

} nmp_transport;


enum session_status
{
    SESSION_STATUS_NONE = 0,     // empty or marked for deletion
    SESSION_STATUS_RESPONSE = 1, // waiting for response
    SESSION_STATUS_CONFIRM = 2,  // waiting for the first message
    SESSION_STATUS_WINDOW = 3,   // maximum number of messages in transit
    SESSION_STATUS_ESTAB = 4,    // established connection
    SESSION_STATUS_ACKWAIT = 5   // some data is in transit
};


// payload 1 for request, 2 for response
typedef struct
{
    noise_handshake handshake;
    struct
    {
        u64 timestamp;
        u8 data[NMP_INITIATION_PAYLOAD];

    } payload[2];

    nmp_request buf_request;
    nmp_response buf_response;

} session_initiation;


struct session
{
    u8 state;
    u8 events;
    u8 timer_retries;
    u8 response_retries;
    i32 timer_fd;
    u32 session_id;

    u64 noise_counter_send;
    u64 noise_counter_receive;
    u32 noise_counter_block[8];
    u8 noise_key_receive[NOISE_KEYLEN];
    u8 noise_key_send[NOISE_KEYLEN];

    nmp_sa addr;
    u64 stat_tx;
    u64 stat_rx;

    union
    {
        void *context_ptr;
        msg_state transport;
    };

    union
    {
        u8 payload[MSG_PAYLOAD];
        session_initiation initiation;
    };
};


struct nmp_data
{
    i32 epoll_fd;
    i32 net_udp;
    i32 local_rx;
    i32 local_tx;
    u16 payload;
    u16 keepalive_interval;
    u32 options;
    sa_family_t sa_family;
    u8 retries[6];

    void *request_context;
    nmp_status (*request_cb)(const u8 *, nmp_request_container *, void *);
    nmp_status (*status_cb)(const nmp_status, const nmp_status_container *, void *);
    void (*stats_cb)(const u64, const u64, void *);

    msg_routines transport_callbacks;
    noise_keypair static_keys;

    union
    {
        u8 net_buf[NET_BUFSIZE];
        nmp_header net_header;
        nmp_request net_request;
        nmp_response net_response;
        nmp_transport net_transport;
    };

    hash_table sessions;
    noise_handshake responder_precomp;
};


static session_context session_new(const i32 epoll_fd)
{
    // TFD_NONBLOCK to prevent timer from locking up
    // in case there was something wrong with that timer
    const i32 timer = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (timer < 0)
    {
        log_errno();
        return NULL;
    }

    session_context ctx = mem_alloc(sizeof(struct session));
    if (ctx == NULL)
    {
        log_errno();
        return NULL;
    }

    struct epoll_event event;
    event.events = EPOLLIN;
    event.data.ptr = ctx;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer, &event))
    {
        log_errno();

        if (close(timer))
        {
            log_errno();
        }

        mem_free(ctx);
        return NULL;
    }

    mem_zero(ctx, sizeof(struct session));

    ctx->timer_fd = timer;

    // sequence numbers start at zero but msg_sequence_cmp()
    // is a strict '>' so set state counters to 0xffff,
    // exactly one before the u16 wraps around to zero
    ctx->transport.tx_seq = 0xffff;
    ctx->transport.tx_ack = 0xffff;
    ctx->transport.rx_seq = 0xffff;
    ctx->transport.rx_delivered = 0xffff;

    return ctx;
}


static u32 session_destroy(session_context ctx)
{
    /*
     *  note: there is no need to remove it from epoll
     *  interest list; since there are no duplicates,
     *  it is handled on the kernel side
     */
    if (close(ctx->timer_fd))
    {
        log_errno();
        return 1;
    }

    msg_context_wipe(&ctx->transport);

    log("%xu", ctx->session_id);
    mem_zero(ctx, sizeof(struct session));
    mem_free(ctx);

    return 0;
}

/*
 *  remove hash table entry, notify application
 *  but do not remove it immediately, just mark
 *  this session for next timer trigger
 */
static void session_drop(main_context nmp,
                         session_context ctx,
                         const nmp_status status,
                         const nmp_status_container *container)
{
    log("%xu", ctx->session_id);
    if (nmp->status_cb)
    {
        nmp->status_cb(status, container, ctx->context_ptr);
    }

    // any new network message or local requests related to this
    // context will be simply discarded as there is no hash table
    // entry, then when its timer fires off the context is finally
    // deleted; this prevents potential use-after-free() because timers
    // (timer fd) have context pointers and do not do any lookup
    hash_table_remove(&nmp->sessions, ctx->session_id);
    ctx->state = SESSION_STATUS_NONE;
}


static u32 session_transport_send(main_context nmp, session_context ctx,
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

    const u32 packet_len = sizeof(nmp_transport) + amt + NOISE_AEAD_MAC;
    nmp_transport *packet = &nmp->net_transport;
    u8 *ciphertext = packet->payload;
    u8 *mac = ciphertext + amt;

    packet->header.type_pad_id = header_initialize(type, ctx->session_id);
    packet->header.counter = ctx->noise_counter_send;

    noise_encrypt(ctx->noise_key_send, ctx->noise_counter_send,
                  &packet->header, sizeof(nmp_transport),
                  payload, amt,
                  ciphertext, mac);

    if (network_send(nmp->net_udp, nmp->net_buf, packet_len, &ctx->addr))
    {
        return 1;
    }

    ctx->noise_counter_send += 1;
    ctx->stat_tx += packet_len;
    return 0;
}


static i32 session_transport_receive(session_context ctx,
                                     const nmp_transport *packet, const u32 packet_len)
{
    const u64 counter_remote = packet->header.counter;
    const i32 payload_len = (i32) (packet_len - sizeof(nmp_transport) - NOISE_AEAD_MAC);
    if (payload_len < 0)
    {
        log("rejecting packet size %xu", packet->header.type_pad_id.session_id);
        return -1;
    }

    const i32 block_index = noise_counter_validate(ctx->noise_counter_block,
                                                   ctx->noise_counter_receive,
                                                   counter_remote);
    if (block_index < 0)
    {
        log("counter rejected %xu", packet->header.type_pad_id.session_id);
        return -1;
    }

    const nmp_transport *header = packet;
    const u8 *ciphertext = header->payload;
    const u8 *mac = ciphertext + payload_len;

    if (noise_decrypt(ctx->noise_key_receive, counter_remote,
                      header, sizeof(nmp_transport),
                      ciphertext, payload_len,
                      mac, ctx->payload))
    {
        log("decryption failed %xu", packet->header.type_pad_id.session_id);
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


static u32 session_request(main_context nmp, session_context ctx)
{
    assert(ctx->state == SESSION_STATUS_NONE);
    session_initiation *initiation = &ctx->initiation;

    initiation->payload[0].timestamp = time_get();
    if (initiation->payload[0].timestamp == 0)
    {
        return 1;
    }

    initiation->buf_request.header = header_initialize(NMP_REQUEST, ctx->session_id);
    if (noise_initiator_write(&initiation->handshake,
                              &initiation->buf_request.initiator,
                              &initiation->buf_request, sizeof(nmp_header),
                              (u8 *) &ctx->initiation.payload[0]))
    {
        return 1;
    }

    if (network_send(nmp->net_udp,
                     &initiation->buf_request, sizeof(nmp_request),
                     &ctx->addr))
    {
        return 1;
    }

    ctx->stat_tx += sizeof(nmp_request);
    return timerfd_interval(ctx->timer_fd, SESSION_TIMER_RETRY);
}


static u32 session_response(main_context nmp, session_context ctx)
{
    assert(ctx->state == SESSION_STATUS_NONE);
    session_initiation *initiation = &ctx->initiation;
    initiation->buf_response.header = header_initialize(NMP_RESPONSE, ctx->session_id);
    initiation->payload[1].timestamp = 0;

    if (noise_responder_write(&initiation->handshake,
                              &initiation->buf_response.responder,
                              &initiation->buf_response.header, sizeof(nmp_header),
                              (u8 *) &initiation->payload[1]))
    {
        return 1;
    }


    if (network_send(nmp->net_udp, &initiation->buf_response,
                     sizeof(nmp_response), &ctx->addr))
    {
        return 1;
    }


    // wait one keepalive interval for initiator to send data
    // respond up to SESSION_RESPONSE_RETRY times to initiator requests
    if (ctx->state != SESSION_STATUS_CONFIRM)
    {
        // using default keepalive value here as this
        // wants to wait for the first data packet
        if (timerfd_interval(ctx->timer_fd, SESSION_TIMER_KEEPALIVE))
        {
            return 1;
        }
    }

    ctx->stat_tx += sizeof(nmp_response);
    return 0;
}

/*
 *  this is triggered by a local event
 *  or received ack (with new messages acked)
 */
static u32 session_data(main_context nmp, session_context ctx)
{
    // NONE, RESPONSE, CONFIRM, WINDOW
    if (ctx->state < SESSION_STATUS_ESTAB)
    {
        log("rejecting state %s", nmp_dbg_session_status[ctx->state]);
        return 0;
    }

    for (;;)
    {
        const i32 amt = msg_assemble(&ctx->transport,
                                     ctx->payload,
                                     nmp->payload);
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
                    if (timerfd_interval(ctx->timer_fd, SESSION_TIMER_RETRY))
                    {
                        return 1;
                    }

                    ctx->state = SESSION_STATUS_ACKWAIT;
                }

                if (session_transport_send(nmp, ctx,
                                           ctx->payload, amt, NMP_DATA))
                {
                    return 1;
                }

                break;
            }
        }
    }

    return 0;
}


/*
 *
 */
static u32 session_data_retry(main_context nmp, session_context ctx)
{
    const u32 amt = msg_assemble_retry(&ctx->transport,
                                       ctx->payload, nmp->payload);
    return amt ? session_transport_send(nmp, ctx,
                                        ctx->payload, (i32) amt, NMP_DATA)
               : 0;
}


/*
 *
 */
static u32 session_data_noack(main_context nmp, session_context ctx,
                              const msg_header *message, const u16 len)
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
static u32 session_ack(main_context nmp, session_context ctx)
{
    if (ctx->response_retries > SESSION_RESPONSE_RETRY)
    {
        log("maximum response retries");
        return 0;
    }

    msg_ack ack;
    msg_ack_assemble(&ctx->transport, &ack);

    ctx->response_retries += 1;
    return session_transport_send(nmp, ctx,
                                  (u8 *) &ack, sizeof(msg_ack), NMP_ACK);
}


/*
 *  send an empty packet to
 *  keep this connection alive
 */
static u32 session_keepalive(main_context nmp, session_context ctx)
{
    assert(ctx->state == SESSION_STATUS_ESTAB);
    return session_transport_send(nmp, ctx, NULL, 0, NMP_DATA);
}


///////////////////////////////
///     local events        ///
///////////////////////////////
#define EVENT_LOCAL_MALLOC  MSG_ALLOC_BLOCK


enum event_local_type
{
    EVENT_LOCAL_DATA = 0,
    EVENT_LOCAL_DATA_NOACK = 1,
    EVENT_LOCAL_DROP = 2,
    EVENT_LOCAL_NEW = 3,
    EVENT_LOCAL_TERM = 4,
};


typedef struct
{
    local_event header;
    union
    {
        session_context payload_ctx;
        msg_header *payload_noack;
        u8 *payload_data;
        void *payload_ptr;
        u8 bytes[LOCAL_PAYLOAD_MAX];
    };

} event_local_buf;


static i32 event_local_data(main_context nmp,
                            session_context ctx,
                            const event_local_buf *event)
{
    // try to include this message to next outgoing packet
    if (msg_queue(&ctx->transport, event->payload_data, event->header.len))
    {
        // let application know that the queue is full
        if (nmp->status_cb)
        {
            const nmp_status_container container = {.msg_id = ctx->transport.tx_counter};
            nmp->status_cb(NMP_SESSION_QUEUE, &container, ctx->context_ptr);
        }

        mem_free(event->payload_ptr);
        return 0;
    }

    return session_data(nmp, ctx) ? -1 : 0;
}

/*
 *  remember: message is preformed in nmp_send_noack()
 *  so we have a payload that is ready for sending
 */
static i32 event_local_noack(main_context nmp,
                             session_context ctx,
                             const event_local_buf *event)
{
    if (session_data_noack(nmp, ctx,
                           event->payload_noack, event->header.len))
    {
        mem_free(event->payload_ptr);
        return -1;
    }

    return 0;
}


static i32 event_local_drop(main_context nmp,
                            session_context ctx,
                            const event_local_buf *event)
{
    UNUSED(event);

    // same as session_drop(), except here we are not
    // doing status callback as it does not make sense
    ctx->state = SESSION_STATUS_NONE;
    hash_table_remove(&nmp->sessions, ctx->session_id);
    return 0;
}


/*
 *  note: in case of errors it safe to delete
 *  context here immediately
 */
static i32 event_local_new(main_context nmp,
                           session_context ctx,
                           const event_local_buf *event)
{
    UNUSED(ctx);
    session_context ctx_new = event->payload_ctx;
    const u32 id_new = event->header.id;

    if (ctx_new->state)
    {
        log("rejecting connection request: wrong state %s %p",
            nmp_dbg_session_status[ctx_new->state], ctx_new);

        return -1;
    }

    if (nmp->sessions.items >= NMP_SESSIONS)
    {
        log("rejecting connection request: MAXCONN");

        const nmp_status_container cancelled = {.session_id = ctx->session_id};
        session_drop(nmp, ctx_new, NMP_SESSION_MAX, &cancelled);
        session_destroy(ctx_new);
        return 0;
    }

    if (hash_table_insert(&nmp->sessions, id_new, ctx_new))
    {
        return -1;
    }

    if (session_request(nmp, ctx_new))
    {
        return -1;
    }

    ctx_new->state = SESSION_STATUS_RESPONSE;
    return 0;
}


static i32 event_local_term(main_context nmp,
                            session_context ctx,
                            const event_local_buf *event)
{
    UNUSED(nmp);
    UNUSED(ctx);
    UNUSED(event);

    // just the indicator
    return 1;
}


static i32 event_local(main_context nmp)
{
    session_context ctx = NULL;
    event_local_buf buf = {0};

    if (local_receive(nmp->local_rx, (local_event *) &buf) == -1)
    {
        log_errno();
        return -1;
    }

    // find context for types that need it,
    // and select appropriate action
    const enum event_local_type type = buf.header.type;
    if (type < EVENT_LOCAL_NEW)
    {
        ctx = hash_table_lookup(&nmp->sessions, buf.header.id);
        if (ctx == NULL)
        {
            log("dropping local request: ctx not found");
            mem_free(buf.payload_ptr);
            return 0;
        }
    }

    switch (type)
    {
        case EVENT_LOCAL_DATA:
            return event_local_data(nmp, ctx, &buf);
        case EVENT_LOCAL_DATA_NOACK:
            return event_local_noack(nmp, ctx, &buf);
        case EVENT_LOCAL_DROP:
            return event_local_drop(nmp, ctx, &buf);
        case EVENT_LOCAL_NEW:
            return event_local_new(nmp, ctx, &buf);
        case EVENT_LOCAL_TERM:
            return event_local_term(nmp, ctx, &buf);

        default:
        {
            log("unhandled event");
            return -1;
        }
    }

    return 0;
}


///////////////////////////////
///     timer events        ///
///////////////////////////////

static u32 event_timer(main_context nmp, session_context ctx)
{
    assert(ctx);

    // session has been marked for deletion
    if (ctx->state == SESSION_STATUS_NONE)
    {
        // this is safe to do here:
        // when errors occur during processing of any
        // network or local events the state is simply
        // marked with SESSION_STATUS_NONE, so it does not accept
        // any remaining events from sockets (/queues)
        return session_destroy(ctx);
    }

    // http://man7.org/linux/man-pages/man2/timerfd_create.2.html#DESCRIPTION
    u8 buf[TIMER_BUF] = {0};

    const isize amt = read(ctx->timer_fd, buf, TIMER_BUF);
    if (amt != sizeof(u64))
    {
        log_errno();
        return 1;
    }

    ctx->timer_retries += 1;
    log("state %s try %u/%u", nmp_dbg_session_status[ctx->state],
        ctx->timer_retries, nmp->retries[ctx->state]);

    if (ctx->timer_retries >= nmp->retries[ctx->state])
    {
        const nmp_status_container latest = {.msg_id = msg_get_latest(&ctx->transport)};
        session_drop(nmp, ctx, NMP_SESSION_DISCONNECTED, &latest);
        return session_destroy(ctx);
    }

    switch (ctx->state)
    {
        case SESSION_STATUS_WINDOW:
        case SESSION_STATUS_ACKWAIT:
        {
            if (session_data_retry(nmp, ctx))
            {
                return 1;
            }

            break;
        }

        case SESSION_STATUS_ESTAB:
        {
            if (session_keepalive(nmp, ctx))
            {
                return 1;
            }

            break;
        }

        case SESSION_STATUS_RESPONSE:
        {
            // retry sending initiator:
            // just take a stored copy
            if (network_send(nmp->net_udp,
                             &ctx->initiation.buf_request, sizeof(nmp_request),
                             &ctx->addr))
            {
                return 1;
            }

            ctx->stat_tx += sizeof(nmp_request);
            break;
        }

        case SESSION_STATUS_CONFIRM:
        {
            // this means connection timed out, and we didn't
            // get any data after sending response(s)
            const nmp_status_container latest = {.msg_id = msg_get_latest(&ctx->transport)};
            session_drop(nmp, ctx, NMP_SESSION_DISCONNECTED, &latest);
            return session_destroy(ctx);
        }

        default:
        {
            return 1;
        }
    }

    callback(nmp->stats_cb, ctx->stat_rx, ctx->stat_tx, ctx->context_ptr);
    return 0;
}


///////////////////////////////
///     network events      ///
///////////////////////////////

static i32 event_net_data(main_context nmp, session_context ctx, const u32 payload)
{
    assert(ctx->state != SESSION_STATUS_NONE);

    if (ctx->state == SESSION_STATUS_CONFIRM)
    {
        ctx->state = SESSION_STATUS_ESTAB;
        ctx->response_retries = 0;
        mem_zero(ctx->payload, sizeof(session_initiation));

        if (nmp->status_cb)
        {
            nmp->status_cb(NMP_SESSION_INCOMING, NULL, ctx->context_ptr);
        }

        // there could be a custom interval set, update needed
        if (timerfd_interval(ctx->timer_fd, nmp->keepalive_interval))
        {
            return -1;
        }
    }

    // skip empty + reset the counter
    if (payload == 0)
    {
        ctx->timer_retries = 0;
        return 0;
    }

    const i32 new_messages = msg_read(&nmp->transport_callbacks,
                                      &ctx->transport,
                                      ctx->payload, payload);
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


static u32 event_net_ack(main_context nmp, session_context ctx, const u32 payload)
{
    assert(ctx->state != SESSION_STATUS_NONE);
    if (payload != sizeof(msg_ack))
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

    const msg_ack *ack = (msg_ack *) ctx->payload;
    const i32 acks = msg_ack_read(&ctx->transport, ack);
    if (acks < 0)
    {
        session_drop(nmp, ctx, NMP_SESSION_ERR_PROTOCOL, NULL);
        return 0;
    }

    return (u32) acks;
}


static i32 event_net_request(main_context nmp, const u32 id, const nmp_sa *addr)
{
    if (nmp->request_cb == NULL)
    {
        log("callback not set, skipping request");
        return 0;
    }

    if (nmp->sessions.items > HASH_TABLE_SIZE)
    {
        log("cannot accept new connection");
        return 0;
    }

    noise_handshake handshake = nmp->responder_precomp;
    struct
    {
        u64 timestamp;
        u8 data[NMP_INITIATION_PAYLOAD];

    } request_payload = {0};

    session_context ctx = hash_table_lookup(&nmp->sessions, id);
    if (ctx && ctx->state != SESSION_STATUS_CONFIRM)
    {
        log("dropping request for %xu", id);
        return 0;
    }

    if (noise_initiator_read(&handshake, &nmp->net_request.initiator,
                             &nmp->net_request, sizeof(nmp_header),
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

    nmp_request_container request = {0};
    request.addr = *addr;
    request.id = id;
    request.request_payload = request_payload.data;

    // ask application what we do next
    switch (nmp->request_cb(handshake.rs, &request,
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
            nmp_response response = {.header = header_initialize(NMP_RESPONSE, id)};
            if (noise_responder_write(&handshake, &response.responder,
                                      &response.header, sizeof(nmp_header),
                                      request.response_payload))
            {
                return -1;
            }

            return network_send(nmp->net_udp, &response,
                                sizeof(nmp_response), addr) ? -1 : 0;
        }

        case NMP_CMD_DROP:
        default:
        {
            log("application dropped request %xu", id);
            return 0;
        }
    }


    ctx = session_new(nmp->epoll_fd);
    if (ctx == NULL)
    {
        return -1;
    }

    ctx->context_ptr = request.context_ptr;
    ctx->addr = *addr;
    ctx->session_id = id;
    ctx->stat_rx += sizeof(nmp_request);

    mem_copy(ctx->initiation.payload[1].data,
             request.response_payload, NMP_INITIATION_PAYLOAD);
    ctx->initiation.handshake = handshake;

    if (session_response(nmp, ctx))
    {
        return -1;
    }

    if (hash_table_insert(&nmp->sessions, id, ctx))
    {
        return -1;
    }

    ctx->state = SESSION_STATUS_CONFIRM;
    noise_split(&ctx->initiation.handshake,
                ctx->noise_key_receive,
                ctx->noise_key_send);
    ctx->noise_counter_receive = 0;
    ctx->noise_counter_send = 0;
    return 0;
}


static u32 event_net_response(main_context nmp, session_context ctx, const u32 amt)
{
    assert(ctx->state != SESSION_STATUS_NONE);
    if (nmp->status_cb == NULL)
    {
        log("callback not set, skipping response.");
        return 0;
    }

    if (ctx->state != SESSION_STATUS_RESPONSE)
    {
        // this also protects against duplicate responders
        log("state != SESSION_STATUS_RESPONSE");
        return 0;
    }

    if (amt != sizeof(nmp_response))
    {
        log("rejecting net_buf.amt != sizeof(nmp_response)");
        return 0;
    }

    if (noise_responder_read(&ctx->initiation.handshake,
                             &nmp->net_response.responder,
                             &nmp->net_response.header, sizeof(nmp_header),
                             (u8 *) &ctx->initiation.payload[1]))
    {
        log("failed to read response for %xu", ctx->session_id);
        return 0;
    }

    switch (nmp->status_cb(NMP_SESSION_RESPONSE,
                           (const nmp_status_container *) &ctx->initiation.payload[1].data,
                           ctx->context_ptr))
    {
        case NMP_CMD_ACCEPT:
        {
            ctx->noise_counter_send = 0;
            ctx->noise_counter_receive = 0;
            noise_split(&ctx->initiation.handshake,
                        ctx->noise_key_send,
                        ctx->noise_key_receive);

            mem_zero(&ctx->payload, sizeof(session_initiation));
            break;
        }

        case NMP_CMD_DROP:
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
            {
                return 0;
            }

            break;
        }

        case 1:
        {
            return 1;
        }
    }

    // no data => keepalive
    if (session_keepalive(nmp, ctx))
    {
        return 1;
    }

    return timerfd_interval(ctx->timer_fd, nmp->keepalive_interval);
}


/*
 *
 */
static i32 event_net_read(main_context nmp,
                          session_context *ctx_ptr,
                          const nmp_sa *addr, const u32 amt)
{
    nmp_header header = nmp->net_header;

    // 0b11111100
    if (header.type & 0xfc)
    {
        log("rejecting header.type");
        return 0;
    }

    if (header.pad[0] | header.pad[1] | header.pad[2])
    {
        log("rejecting header.pad");
        return 0;
    }

    if (header.session_id == 0)
    {
        log("rejecting reserved id value");
        return 0;
    }

    if (header.type == NMP_REQUEST)
    {
        if (amt != sizeof(nmp_request))
        {
            return 0;
        }

        log("received request %x", header.session_id);
        return event_net_request(nmp, header.session_id, addr);
    }

    session_context ctx = hash_table_lookup(&nmp->sessions, header.session_id);
    if (ctx == NULL)
    {
        log("discarded message for %xu", header.session_id);
        return 0;
    }

    // it is important to skip any extra processing
    if (!ctx->state)
    {
        log("discarding data for dead context");
        return 0;
    }

    if (nmp->options & NMP_ADDR_VERIFY)
    {
        if (mem_cmp(&ctx->addr.sa, &addr->sa, sizeof(nmp_sa)) != 0)
        {
            log("rejecting addr != recvfrom().addr");
            return 0;
        }
    }

    *ctx_ptr = ctx;

    // message, ack
    if (header.type > NMP_RESPONSE)
    {
        if (amt % 16)
        {
            log("rejecting amt %% 16");
            return 0;
        }

        const i32 payload = session_transport_receive(ctx,
                                                      &nmp->net_transport, amt);
        if (payload < 0)
        {
            // it is important to not let any other processing
            *ctx_ptr = NULL;
            return 0;
        }

        return payload;
    }

    return 1;
}

/*
 *  collect network events, distributing received
 *  packets into their contexts
 *
 *  return number of peers that received message
 *  -1 indicating error
 */
static i32 event_net_collect(main_context nmp, session_context *queue)
{
    i32 queue_len = 0;

    //
    for (u32 i = 0; queue_len < EPOLL_QUEUELEN; i++)
    {
        nmp_sa addr = {0};
        session_context ctx = NULL;

        // there is a non-blocking recvfrom()
        // so we need to depend on EAGAIN
        // to know that the socket is empty
        errno = 0;

        // try to read raw message from the socket
        // and verify result (errno)
        const u32 packet_total = network_receive(nmp->net_udp, nmp->net_buf, &addr);
        if (packet_total == 0)
        {
            switch (errno)
            {
                case 0:
                {
                    // message has been discarded
                    continue;
                }

                case EAGAIN:
                {
                    // socket is empty
                    errno = 0;
                    return queue_len;
                }

                default:
                {
                    // any other error code is critical
                    return -1;
                }
            }
        }

        // try to authenticate received packet
        const i32 packet_payload = event_net_read(nmp, &ctx, &addr, packet_total);
        if (packet_payload < 0)
        {
            return -1;
        }

        if (ctx == NULL)
        {
            continue;
        }

        // packet has not been discarded, context is found
        // lets collect
        ctx->stat_rx += packet_total;

        // process ready packets
        switch (nmp->net_header.type)
        {
            case NMP_DATA:
            {
                const i32 result = event_net_data(nmp, ctx, packet_payload);
                if (result < 0)
                {
                    return -1;
                }

                if (!result)
                {
                    continue;
                }

                ctx->events |= SESSION_EVENT_DATA;
                break;
            }

            case NMP_ACK:
            {
                if (!event_net_ack(nmp, ctx, packet_payload))
                {
                    continue;
                }

                ctx->events |= SESSION_EVENT_ACK;
                break;
            }

            case NMP_RESPONSE:
            {
                if (event_net_response(nmp, ctx, packet_total))
                {
                    return -1;
                }

                continue;
            }

            default:
            {
                log("unknown header.type");
                return -1;
            }
        }

        // if there are new events && not queued yet
        if (ctx->events && !(ctx->events & SESSION_EVENT_QUEUED))
        {
            queue[queue_len] = ctx;
            queue_len += 1;

            ctx->events |= SESSION_EVENT_QUEUED;
        }
    }

    return queue_len;
}

/*
 *  first collect every context that has new message arrived
 *  then process everything (this is done because packets
 *  may arrive out of order so we cannot tell if it was
 *  the last packet for a given context before processing)
 */
static u32 event_network(main_context nmp)
{
    session_context net_queue[EPOLL_QUEUELEN] = {0};

    const i32 peers = event_net_collect(nmp, net_queue);
    if (peers < 0)
    {
        return 1;
    }

    // go through connected peers that
    // have message delivered for them
    for (i32 i = 0; i < peers; i++)
    {
        session_context ctx = net_queue[i];
        if (ctx->state == SESSION_STATUS_NONE)
        {
            // one (possibly out of many) received packets triggered an error
            // that led to session_drop(), this context is not in hash table
            // anymore so no more data after 'fatal packet' but it can still
            // end up here in this queue => ignore
            continue;
        }

        // if there are new messages
        if (ctx->events & SESSION_EVENT_DATA)
        {
            msg_deliver_data(&nmp->transport_callbacks,
                             &ctx->transport);

            // new data has been received, so it is irrelevant if those
            // messages were delivered or not, we must send out ack here
            if (session_ack(nmp, ctx))
            {
                return 1;
            }

            ctx->response_retries = 0;
        }

        // if there are new acks
        if (ctx->events & SESSION_EVENT_ACK)
        {
            switch (msg_deliver_ack(&nmp->transport_callbacks,
                                    &ctx->transport))
            {
                case 0:
                {
                    break;
                }

                case -1:
                {
                    // everything has been acked
                    ctx->state = SESSION_STATUS_ESTAB;
                    if (timerfd_interval(ctx->timer_fd, nmp->keepalive_interval))
                    {
                        return 1;
                    }

                    break;
                }

                default:
                {
                    // if this ack contained any new messages, trigger
                    // data transmission to fill the window back up
                    ctx->state = SESSION_STATUS_ACKWAIT;
                    if (session_data(nmp, ctx))
                    {
                        return 1;
                    }

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
    }

    return 0;
}


///////////////////////////
///     public api      ///
///////////////////////////
/*
 *  wipe the sessions, close descriptors,
 *  free() main structure
 */
static u32 nmp_destroy(main_context nmp)
{
    errno = 0;

    if (hash_table_wipe(&nmp->sessions,
                        (u32 (*)(void *)) session_destroy))
    {
        return 1;
    }

    const i32 descriptors[] =
            {
                    nmp->epoll_fd,
                    nmp->net_udp,
                    nmp->local_rx,
                    nmp->local_tx,
            };

    for (u32 i = 0; i < sizeof(descriptors) / sizeof(u32); i++)
    {
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
struct nmp_data *nmp_new(const nmp_conf_t *conf)
{
    nmp_t *tmp = NULL;

    if (conf == NULL)
    {
        log("conf == NULL");
        return NULL;
    }

    const sa_family_t sa_family = conf->addr.sa.sa_family ? : AF_INET;
    if (sa_family != AF_INET && sa_family != AF_INET6)
    {
        log("sa_family");
        return NULL;
    }

    if (conf->payload &&
        (conf->payload < 524 || conf->payload > NMP_PAYLOAD_MAX))
    {
        log("payload");
        return NULL;
    }

    const u16 ka = conf->keepalive_interval ? : SESSION_TIMER_KEEPALIVE;

    // if selected value is greater than default inactivity timeout, perform
    // 3 retries; otherwise perform enough retries to reach timeout naturally
    const u16 ka_max = conf->keepalive_interval >= SESSION_TIMER_TTL ?
                       SESSION_TIMER_RETRIES_TTL : SESSION_TIMER_TTL / ka;


    // 0 == rx
    // 1 == tx
    i32 socpair[2] = {0};
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, socpair))
    {
        return NULL;
    }

    const i32 epoll_fd = epoll_create(EPOLL_CREATE);
    if (epoll_fd < 0)
    {
        close(socpair[0]);
        close(socpair[1]);

        return NULL;
    }

    // default to ip4 if not set explicitly
    const i32 soc_fd = socket(sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (soc_fd < 0)
    {
        close(epoll_fd);
        close(socpair[0]);
        close(socpair[1]);

        return NULL;
    }

    if (bind(soc_fd, &conf->addr.sa, sizeof(conf->addr)))
    {
        goto fail;
    }

    /*
     *
     */
    tmp = (nmp_t *) mem_alloc(sizeof(nmp_t));
    if (tmp == NULL)
    {
        goto fail;
    }

    // register main udp socket
    {
        struct epoll_event epoll_net;
        epoll_net.events = EPOLLIN;
        epoll_net.data.ptr = &tmp->net_udp;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, soc_fd, &epoll_net))
        {
            goto fail;
        }
    }

    // register descriptor for local messages
    {
        struct epoll_event epoll_local;
        epoll_local.events = EPOLLIN;
        epoll_local.data.ptr = &tmp->local_rx;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socpair[0], &epoll_local))
        {
            goto fail;
        }
    }

    /*
     *  everything is ready, copy into
     *  allocated area
     */
    mem_zero(tmp, sizeof(nmp_t));

    if (rnd_get(tmp->sessions.key, SIPHASH_KEY))
    {
        goto fail;
    }

    tmp->local_rx = socpair[0];
    tmp->local_tx = socpair[1];
    tmp->epoll_fd = epoll_fd;
    tmp->net_udp = soc_fd;
    tmp->keepalive_interval = ka;
    tmp->sa_family = sa_family;

    tmp->retries[SESSION_STATUS_NONE] = 0;
    tmp->retries[SESSION_STATUS_RESPONSE] = SESSION_TIMER_RETRIES_MAX;
    tmp->retries[SESSION_STATUS_CONFIRM] = 2;
    tmp->retries[SESSION_STATUS_WINDOW] = SESSION_TIMER_RETRIES_MAX;
    tmp->retries[SESSION_STATUS_ESTAB] = ka_max;
    tmp->retries[SESSION_STATUS_ACKWAIT] = SESSION_TIMER_RETRIES_MAX;

    tmp->options = conf->options;
    tmp->payload = conf->payload ? : NMP_PAYLOAD_MAX;
    tmp->payload += sizeof(msg_header); // we store 'real' payload limit

    tmp->request_context = conf->request_ctx;
    tmp->request_cb = conf->request_cb;
    tmp->status_cb = conf->status_cb;
    tmp->stats_cb = conf->stats_cb;

    tmp->transport_callbacks.data = conf->data_cb;
    tmp->transport_callbacks.data = conf->data_noack_cb;
    tmp->transport_callbacks.ack = conf->ack_cb;

    mem_copy(tmp->static_keys.private, conf->key, NMP_KEYLEN);
    noise_keypair_initialize(&tmp->static_keys);
    noise_responder_init(&tmp->responder_precomp, &tmp->static_keys);

    assert(tmp->payload <= 1456);
    return tmp;

    /*
     *  fail routine:
     *  just close everything
     *  and mem_free_sys() if needed
     */
    fail:
    {
        log("fail %s", strerrorname_np(errno));

        close(soc_fd);
        close(epoll_fd);
        close(socpair[0]);
        close(socpair[1]);

        if (tmp)
        {
            mem_free(tmp);
        }

        return NULL;
    }
}

/*
 *
 */
u32 nmp_connect(main_context nmp, const u8 *pub, const nmp_sa *addr,
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

    session_context ctx_new = session_new(nmp->epoll_fd);
    if (ctx_new == NULL)
    {
        log_errno();
        return 0;
    }

    ctx_new->context_ptr = ctx;
    ctx_new->session_id = id;
    ctx_new->addr = *addr;
    noise_initiator_init(&ctx_new->initiation.handshake,
                         &nmp->static_keys, pub);

    if (payload)
    {
        mem_copy(&ctx_new->initiation.payload[0].data,
                 payload, payload_len);
    }

    const local_event ev =
            {
                    .type = EVENT_LOCAL_NEW,
                    .len = 0,
                    .id = id,
            };

    if (local_send(nmp->local_tx, &ev,
                   &ctx_new, sizeof(struct session *)))
    {
        session_destroy(ctx_new);
        return 0;
    }

    return id;
}

/*
 *  allocate space, copy message and
 *  send local event via socket pair
 */
u32 nmp_send(main_context nmp, const u32 session,
             const u8 *buf, const u16 len)
{
    if (!nmp || !session || !buf || !len)
    {
        log("invalid args");
        return 1;
    }

    // stored payload includes msg_header size
    if (len + sizeof(msg_header) > nmp->payload)
    {
        return 1;
    }

    u8 *ptr = mem_alloc(EVENT_LOCAL_MALLOC);
    mem_copy(ptr, buf, len);

    const local_event ev =
            {
                    .type = EVENT_LOCAL_DATA,
                    .len = len,
                    .id = session,
            };

    if (local_send(nmp->local_tx, &ev,
                   &ptr, sizeof(u8 *)))
    {
        mem_free(ptr);
        return 1;
    }

    return 0;
}

/*
 */
u32 nmp_send_noack(main_context nmp, const u32 session,
                   const u8 *buf, const u16 len)
{
    if (!nmp || !session || !buf || !len)
    {
        log("invalid args");
        return 1;
    }

    // stored payload includes msg_header size
    if (len + sizeof(msg_header) > nmp->payload)
    {
        return 1;
    }

    // noack messages are not buffered so let's avoid
    // extra copying and assemble them in-place:
    msg_header *header = mem_alloc(EVENT_LOCAL_MALLOC);
    const u16 total_len = msg_assemble_noack(header, buf, len);
    const local_event ev =
            {
                    .type = EVENT_LOCAL_DATA_NOACK,
                    .len = total_len,
                    .id = session,
            };

    if (local_send(nmp->local_tx, &ev,
                   &header, sizeof(msg_header *)))
    {
        mem_free(header);
        return 1;
    }

    return 0;
}

/*
 *  get local key_public key; always safe to access nmp_new()
 *  since it won't be modified by anything after returns
 */
void nmp_pubkey(const nmp_t *nmp, u8 buf[NMP_KEYLEN])
{
    mem_copy(buf, nmp->static_keys.public, NMP_KEYLEN);
}

/*
 *  simply send a local message indicating
 *  which session to drop
 */
u32 nmp_drop(main_context nmp, const u32 session)
{
    if (session == 0)
    {
        log("cannot drop session 0");
        return 1;
    }

    const local_event drop =
            {
                    .type = EVENT_LOCAL_DROP,
                    .len = 0,
                    .id = session,
            };

    return local_send(nmp->local_tx, &drop, NULL, 0);
}

/*
 *  simply send a termination message
 */
u32 nmp_terminate(main_context nmp)
{
    const local_event term =
            {
                    .type = EVENT_LOCAL_TERM,
                    .len = 0,
                    .id = 0,
            };

    return local_send(nmp->local_tx, &term, NULL, 0);
}

/*
 *  main event loop
 *  block on epoll_wait() and distribute
 *  events to appropriate handlers
 */
u32 nmp_run(main_context nmp, const i32 timeout)
{
    struct epoll_event epoll_queue[EPOLL_QUEUELEN];

    for (;;)
    {
        const i32 events = epoll_wait(nmp->epoll_fd, epoll_queue,
                                      EPOLL_QUEUELEN, timeout);
        if (!events)
        {
            return 0;
        }

        // http://man7.org/linux/man-pages/man2/epoll_wait.2.html#RETURN_VALUE
        if (events < 0)
        {
            // interrupted by a signal,
            // other errors should never happen
            if (errno != EINTR)
            {
                log_errno();
                return 1;
            }

            continue;
        }

        // process epoll epoll_queue
        for (i32 i = 0; i < events; i++)
        {
            const epoll_data_t event = epoll_queue[i].data;
            if (event.ptr == NULL)
            {
                log("null event %s", strerrorname_np(errno));
                return 1;
            }

            // read packets in blocks of EPOLL_QUEUELEN
            // then process received message
            if (event.ptr == &nmp->net_udp)
            {
                if (event_network(nmp))
                {
                    log("network error");
                    return 1;
                }

                continue;
            }

            // process local event
            if (event.ptr == &nmp->local_rx)
            {
                const i32 local_event = event_local(nmp);

                switch (local_event)
                {
                    case 0: // successfully processed event
                        continue;

                    case 1: // termination request
                    {
                        return nmp_destroy(nmp);
                    }

                    case -1: // errors
                    default:
                    {
                        return 1;
                    }
                }
            }

            // a timer has expired
            if (event_timer(nmp, (session_context) event.ptr))
            {
                return 1;
            }
        }

//        assert(errno == 0);
    }
}
