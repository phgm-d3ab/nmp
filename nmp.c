/*
 *
 */
#include "nmp.h"

#include "chacha20_poly1305.h" // https://github.com/phgm-d3ab/chacha20_poly1305
#include "curve25519-donna.h"  // https://github.com/phgm-d3ab/curve25519-donna
#include "blake2s.h"           // https://github.com/phgm-d3ab/blake2

#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
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

static const char *nmp_types[] =
        {
                "initiator",
                "responder",
                "data",
                "ack",
        };


#   define UNUSED(arg_)    ((void)(arg_))
#   define static
#   define inline

#else // NMP_DEBUG

#   define log(...)
#   define log_errno()

#endif // NMP_DEBUG


// cosmetics mainly
#define mem_alloc(size_)                malloc(size_)
#define mem_free(ptr_)                  free(ptr_)
#define mem_zero(ptr_, len_)            memset(ptr_, 0, len_)
#define mem_copy(dest_, src_, len_)     memcpy(dest_, src_, len_)
#define mem_cmp(buf1_, buf2_, len_)     memcmp(buf1_, buf2_, len_)


// http://man7.org/linux/man-pages/man2/epoll_create.2.html#NOTES
#define EPOLL_CREATE        1
#define EPOLL_QUEUELEN      64

#define PACKET_MIN          32
#define PACKET_MAX          (NMP_PAYLOAD_MAX + 48)

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

typedef union
{
    struct sockaddr_in v4;
    struct sockaddr_in6 v6;
    struct sockaddr generic;

} addr_internal;


// return zero for success
static inline u32 network_send(const i32 soc,
                               const void *data,
                               const u32 amt,
                               const addr_internal *addr)
{
    const isize sent = sendto(soc, data, amt,
                              SENDTO_OPT,
                              &addr->generic,
                              sizeof(addr_internal));

    log("%s %zi", nmp_types[*((u8 *) data)], sent);

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
                                  addr_internal *addr)
{
    // important to initialize this
    // http://man7.org/linux/man-pages/man3/recvfrom.3p.html#DESCRIPTION
    socklen_t addr_len = sizeof(addr_internal);
    const isize amt = recvfrom(soc, buf, NET_BUFSIZE,
                               RECVFROM_OPT,
                               &addr->generic, &addr_len);

    log("%s %zi (%s)",
        (amt > 0 && *buf < 4) ? nmp_types[*buf] : "",
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
 *  nmp source/
 *  ├─ general definitions/
 *  │  ├─ packet types
 *  │  ├─ main instance
 *  ├─ session/
 *  │  ├─ def/
 *  │  │  ├─ general
 *  │  │  ├─ message
 *  │  │  ├─ crypto
 *  │  │  ├─ session type
 *  │  ├─ impl/
 *  │  │  ├─ message
 *  │  │  ├─ crypto
 *  │  │  ├─ session
 *  ├─ event/
 *  │  ├─ local
 *  │  ├─ timer
 *  │  ├─ network
 *  ├─ public api impl
 */
typedef struct nmp_data *main_context;
typedef struct session *session_context;

#define NMP_AEAD_TAG        16
#define NMP_PROTOCOL_BYTES  (NMP_AEAD_TAG + (u32)(sizeof(nmp_header)))
#define NMP_INITIATOR_TTL   5000 // ms

#define NMP_INITIATOR       0
#define NMP_RESPONDER       1
#define NMP_DATA            2
#define NMP_ACK             3


typedef struct
{
    struct
    {
        u8 type;
        u8 pad[3];
        u32 session_id;
        u64 counter;
        u8 ephemeral[NMP_KEYLEN];

    } header;

    struct
    {
        u64 timestamp;
        u8 key_static[NMP_KEYLEN];
        u8 hash[32];

    } encrypted;

    u8 mac[NMP_AEAD_TAG];

} nmp_initiator;


typedef struct
{
    struct
    {
        u8 type;
        u8 pad[3];
        u32 session_id;
        u8 ephemeral[NMP_KEYLEN];

    } header;

    u8 hash[32];

} nmp_responder;


typedef struct
{
    u8 type;
    u8 pad[3];
    u32 session_id;
    u64 counter;

    u8 payload[0];

} nmp_header;


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

    void *rx_context;
    void *(*auth_cb)(const u8 *, const struct sockaddr *, u32, void *);
    void (*data_cb)(const u8 *, u32, void *);
    void (*data_noack_cb)(const u8 *, u32, void *);
    void (*ack_cb)(u64, void *);
    void (*notif_cb)(u32, void *);
    void (*stats_cb)(u64, u64, void *);

    u8 key_public[NMP_KEYLEN];
    u8 key_private[NMP_KEYLEN];

    union
    {
        u8 net_buf[NET_BUFSIZE];
        nmp_initiator net_initiator;
        nmp_responder net_responder;
        nmp_header net_header;
    };

    hash_table sessions;
};



/*
 *
 *
 */
#define SESSION_STATUS_NONE         0   // empty or marked for deletion
#define SESSION_STATUS_RESPONSE     1   // initiator waits for response
#define SESSION_STATUS_CONFIRM      2   // responder waits for the first message
#define SESSION_STATUS_WINDOW       3   // maximum number of messages in transit
#define SESSION_STATUS_ESTAB        4   // established connection
#define SESSION_STATUS_ACKWAIT      5   // some data is in transit

// this covers an extremely rare case when our acks and/or responders
// do not go through: how many times we can respond to a valid
// initiator or how many acks to send if received data packet
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


#define callback(call_, ...) ({ if (call_) { call_(__VA_ARGS__); } \
                            else { log("skipping empty %s", #call_); }})

/*
 *
 */
#define MSG_ALLOC_BLOCK 2048

#define MSG_MASK_BITS   32
#define MSG_MASK_INIT   0xffffffff

#define MSG_WINDOW      32u
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
    u16 pad1;
    u32 ack_mask;
    u64 pad2;

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


/*
 *
 */
#define CRYPTO_COUNTER_WINDOW   96
#define CRYPTO_COUNTER_MAX      ((u64) 1 << 63)
#define CRYPTO_KEYLEN           NMP_KEYLEN
#define CRYPTO_HASH             32
#define CRYPTO_NONCE            12 // chacha20 ietf version
#define CRYPTO_AEAD_TAG         16 // poly1305

#define CRYPTO_STATE_0          SESSION_STATUS_NONE
#define CRYPTO_STATE_1          SESSION_STATUS_RESPONSE


typedef struct
{
    u32 id;
    u8 remote_static[32];
    u8 remote_ephemeral[32];
    u8 state[32];

    u8 key_send[32];
    u8 key_receive[32];

} crypto_initiation_request;


/*
 *
 */
struct session
{
    u8 state;
    u8 events;
    u8 timer_retries;
    u8 response_retries;
    i32 timer_fd;

    u16 tx_seq;
    u16 tx_sent;
    u16 tx_ack;
    u64 tx_counter;

    u16 rx_seq;
    u16 rx_delivered;

    u32 session_id;
    u64 counter_send;
    u64 counter_receive;
    u32 counter_block[4];

    u64 stat_tx;
    u64 stat_rx;

    u8 key_receive[32];
    u8 key_send[32];

    void *context_ptr;
    addr_internal addr;

    u8 payload[MSG_PAYLOAD];
    msg_tx tx_queue[MSG_TXQUEUE];
    msg_rx rx_buffer[MSG_RXQUEUE];

    u8 remote_static[32];
    u8 ephemeral[32];
    u8 crypto_state[32];
};


/*
 *
 *
 */

// convenience: get a pointer to entry by sequence number
#define tx_get(ctx_, n_) ((ctx_)->tx_queue + ((n_) & (MSG_TXQUEUE - 1)))
#define rx_get(ctx_, n_) ((ctx_)->rx_buffer + ((n_) & (MSG_RXQUEUE - 1)))

/*
 *  compare sequence numbers:
 *  cover for 'wraparound'
 */
static inline i32 sequence_cmp(const u16 a, const u16 b)
{
    return ((a <= b) ? ((b - a) > 0xff) : ((a - b) < 0xff));
}


/*
 *  zero pad payload, make total length multiple of 16
 */
static inline i32 payload_zeropad(u8 *payload, const i32 len)
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


static inline void tx_include(const msg_tx *tx, msg_header *msg)
{
    msg->sequence = tx->seq;
    msg->len = tx->len;

    mem_copy(msg->data, tx->msg, tx->len);
    log("seq %u status %u", msg->sequence, tx->status);
}


static void rx_copy(msg_rx *entry, const msg_header *msg)
{
    entry->status = MSG_RX_RECEIVED;
    entry->seq = msg->sequence;
    entry->len = msg->len;

    mem_copy(entry->data, msg->data, msg->len);
    log("seq %u len %u", msg->sequence, msg->len);
}


/*
 *  simply free() remaining messages
 *  that were not acknowledged yet
 */
static void msg_context_wipe(session_context ctx)
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
static u32 msg_queue(session_context ctx, const u8 *msg, const u16 len)
{
    assert(msg);

    // pre-increment: check one ahead
    const u32 index = (ctx->tx_seq + 1) % MSG_TXQUEUE;
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
static i32 msg_assemble(session_context ctx,
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

            tx_include(msg, (msg_header *) (output + bytes));

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

        tx_include(resend_queue[i], (msg_header *) (output + bytes));
        bytes += offset;
    }

    return payload_zeropad(output, (i32) bytes);
}


static u32 msg_assemble_retry(session_context ctx,
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

            tx_include(msg, (msg_header *) (output + bytes));
            bytes += offset;
        }

        if (i == ctx->tx_sent)
        {
            break;
        }
    }

    return (u32) payload_zeropad(output, (i32) bytes);
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
    return payload_zeropad(header->data, (i32) (len + sizeof(msg_header)));
}


/*
 *  return number of new messages
 */
static i32 msg_read(main_context nmp, session_context ctx,
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
        if (len - iterator <= sizeof(msg_header))
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

            callback(nmp->data_noack_cb, msg->data, msg_len, ctx->context_ptr);
            return 0;
        }

        if (msg->len & MSG_RESERVED)
        { /* not used for now */ }


        // no point processing anything below latest delivered
        if (sequence_cmp(msg->sequence, seq_low))
        {
            // detect message with sequence number higher
            // than latest acked (from our side) + MSG_WINDOW
            if (sequence_cmp(msg->sequence, seq_high))
            {
                log("rejecting sequence %u over %u",
                    msg->sequence, seq_high);

                return -1;
            }

            // update rx_seq?
            if (sequence_cmp(msg->sequence, ctx->rx_seq))
            {
                ctx->rx_seq = msg->sequence;
            }

            msg_rx *entry = rx_get(ctx, msg->sequence);
            if (entry->status == MSG_RX_EMPTY)
            {
                new_messages += 1;
                rx_copy(entry, msg);
            }
        }

        iterator += (msg->len + sizeof(msg_header));
    }

    return new_messages;
}

/*
 *  this can be called only if there are new messages to deliver
 */
static void msg_deliver_data(main_context nmp, session_context ctx)
{
    for (u16 n = ctx->rx_delivered + 1;; n++)
    {
        msg_rx *entry = rx_get(ctx, n);
        if (entry->status == MSG_RX_EMPTY)
        {
            break;
        }

        callback(nmp->data_cb, entry->data, entry->len, ctx->context_ptr);

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
static u32 msg_ack_assemble(session_context ctx, msg_ack *ack)
{
    u32 mask = MSG_MASK_INIT;
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
    ack->pad1 = 0;
    ack->ack_mask = mask;
    ack->pad2 = 0;

    return 1;
}


/*
 *
 */
static i32 msg_ack_read(session_context ctx, const msg_ack *ack)
{
    i32 discovered = 0;
    u32 mask = ack->ack_mask;


    if (sequence_cmp(ack->ack, ctx->tx_ack))
    {
        if (sequence_cmp(ack->ack, ctx->tx_sent))
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
static i32 msg_deliver_ack(main_context nmp, session_context ctx)
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

        callback(nmp->ack_cb, msg->id, ctx->context_ptr);

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
 *
 *
 */

// classic constant time comparison
static u32 cmp256(const u8 buf1[32], const u8 buf2[32])
{
    u32 diff = 0;

    for (u32 i = 0; i < 32; i++)
    {
        diff |= (buf1[i] ^ buf2[i]);
    }

    return diff;
}


// convert u32 & u64 pair into 96 bit format
static void nonce_convert(const u32 constant, const u64 iv,
                          u8 output[CRYPTO_NONCE])
{
    output[0] = (u8) (constant);
    output[1] = (u8) (constant >> 8);
    output[2] = (u8) (constant >> 16);
    output[3] = (u8) (constant >> 24);
    output[4] = (u8) (iv);
    output[5] = (u8) (iv >> 8);
    output[6] = (u8) (iv >> 16);
    output[7] = (u8) (iv >> 24);
    output[8] = (u8) (iv >> 32);
    output[9] = (u8) (iv >> 40);
    output[10] = (u8) (iv >> 48);
    output[11] = (u8) (iv >> 56);
}


// https://cr.yp.to/ecdh.html #Computing secret keys.
static inline void crypto_key_setup(u8 key[CRYPTO_KEYLEN])
{
    key[0] &= 248;
    key[31] &= 127;
    key[31] |= 64;
}

//
static inline u32 crypto_key_generate(u8 key[CRYPTO_KEYLEN])
{
    struct
    {
        u8 rnd1[32];
        u8 rnd2[32];

    } buf = {0};

    if (rnd_get(&buf, sizeof(buf)))
    {
        return 1;
    }

    blake2s(key, CRYPTO_HASH,
            buf.rnd1, 32,
            buf.rnd2, 32);

    crypto_key_setup(key);
    return 0;
}

// https://cr.yp.to/ecdh.html #Computing key_public keys.
static inline void crypto_pubkey(const u8 private[CRYPTO_KEYLEN],
                                 u8 public[CRYPTO_KEYLEN])
{
    const u8 basepoint[32] = {9};
    curve25519_donna(public, private, basepoint);
}

// https://cr.yp.to/ecdh.html #Computing shared secrets.
static inline void crypto_dh(const u8 *key, const u32 keylen,
                             const u8 our_secret[CRYPTO_KEYLEN],
                             const u8 their_public[CRYPTO_KEYLEN],
                             u8 shared_secret[CRYPTO_HASH])
{
    u8 tmp[32] = {0};

    curve25519_donna(tmp, our_secret, their_public);
    blake2s(shared_secret, CRYPTO_HASH,
            key, keylen,
            tmp, 32);
}

// output a 32 byte hash of some input optionally using key
static inline void crypto_hash(const u8 *input, const u32 input_len,
                               const u8 *key, const u32 key_len,
                               u8 *output)
{
    blake2s(output, CRYPTO_HASH,
            key, key_len,
            input, input_len);
}


#if defined(NMP_DEBUG_AEAD)

static void crypto_aead_encrypt(const u8 key[32],
                                const u32 constant, const u64 counter,
                                const u8 *aad, const u32 aad_len,
                                const u8 *payload, const u32 payload_len,
                                u8 *output, u8 tag[16])
{
    UNUSED(key);
    UNUSED(constant);
    UNUSED(counter);
    UNUSED(aad);
    UNUSED(aad_len);

    mem_zero(tag, 16);
    mem_copy(output, payload, payload_len);
}

static u32 crypto_aead_decrypt(const u8 key[NMP_KEYLEN],
                               const u32 constant, const u64 counter,
                               const u8 *aad, const u32 aad_len,
                               const u8 *payload, const u32 payload_len,
                               const u8 tag[16], u8 *output)
{
    UNUSED(key);
    UNUSED(constant);
    UNUSED(counter);
    UNUSED(aad);
    UNUSED(aad_len);
    UNUSED(tag);

    mem_copy(output, payload, payload_len);
    return 0;
}

#else // NMP_DEBUG_AEAD

static void crypto_aead_encrypt(const u8 key[CRYPTO_KEYLEN],
                                const u32 constant, const u64 counter,
                                const u8 *aad, const u32 aad_len,
                                const u8 *payload, const u32 payload_len,
                                u8 *output, u8 tag[CRYPTO_AEAD_TAG])
{
    u8 nonce[12] = {0};
    nonce_convert(constant, counter, nonce);

    chacha20_poly1305_encrypt(key, nonce, aad, aad_len,
                              payload, payload_len,
                              output, tag);
}

static u32 crypto_aead_decrypt(const u8 key[NMP_KEYLEN],
                               const u32 constant, const u64 counter,
                               const u8 *aad, const u32 aad_len,
                               const u8 *payload, const u32 payload_len,
                               const u8 tag[CRYPTO_AEAD_TAG], u8 *output)
{
    u8 nonce[12] = {0};
    nonce_convert(constant, counter, nonce);
    return chacha20_poly1305_decrypt(key, nonce,
                                     aad, aad_len,
                                     payload, payload_len,
                                     tag, output);
}

#endif // NMP_DEBUG_AEAD

/*
 *
 */
static i32 crypto_packet_encrypt(session_context ctx,
                                 const u32 packet_type,
                                 const u8 *payload,
                                 const u32 len,
                                 nmp_header *header)
{
    assert(packet_type > NMP_RESPONDER);

    if (ctx->counter_send > CRYPTO_COUNTER_MAX)
    {
        log("out of nonces");
        return -1;
    }

    ctx->counter_send += 1;

    // make the header
    header->type = packet_type;
    header->pad[0] = 0;
    header->pad[1] = 0;
    header->pad[2] = 0;
    header->session_id = ctx->session_id;
    header->counter = ctx->counter_send;

    crypto_aead_encrypt(ctx->key_send, ctx->session_id, ctx->counter_send,
                        (u8 *) header, sizeof(nmp_header),
                        payload, len,
                        header->payload, header->payload + len);

    return (i32) (len + NMP_PROTOCOL_BYTES);
}

/*
 *  <= equal or below local -> check the bitmap
 *  > above local -> always good
 */
static i32 counter_validate(const u32 block[4], const u64 local, const u64 remote)
{
    // if too old
    if (remote + CRYPTO_COUNTER_WINDOW < local)
    {
        return -1;
    }

    if (remote > (local + CRYPTO_COUNTER_WINDOW) || remote > CRYPTO_COUNTER_MAX)
    {
        return -1;
    }

    // this cast is safe as we clear a lot of bits anyway
    const i32 block_id = (i32) (remote / 32) & 3;
    if (remote <= local)
    {
        if (block[block_id] & (1 << (remote & 31)))
        {
            log("already received [%zu]", remote);
            return -1;
        }
    }

    // at this point only sequences above local counter are left,
    // and they are within allowed forward window, so it is ok
    return block_id;
}

/*
 *
 */
static i32 crypto_packet_decrypt(session_context ctx,
                                 const nmp_header *header, const u32 full_len,
                                 u8 *output)
{
    const i32 payload_len = (i32) (full_len - NMP_PROTOCOL_BYTES);
    if (payload_len < 0)
    {
        log("rejecting packet size %x", header->session_id);
        return -1;
    }

    const i32 block_id = counter_validate(ctx->counter_block,
                                          ctx->counter_receive, header->counter);
    if (block_id < 0)
    {
        log("counter rejected %x", header->session_id);
        return -1;
    }

    if (crypto_aead_decrypt(ctx->key_receive, header->session_id, header->counter,
                            (u8 *) header, sizeof(nmp_header), header->payload,
                            payload_len, header->payload + payload_len, output))
    {
        log("decryption failed %x", header->session_id);
        return -1;
    }

    // only after successful decryption
    if (header->counter > ctx->counter_receive)
    {
        // start from local block, walk forward
        // zeroing out blocks in front
        i32 i = (i32) (ctx->counter_receive / 32) & 3;

        while (i != block_id)
        {
            i += 1;
            i &= 3;

            ctx->counter_block[i] = 0;
        }

        ctx->counter_receive = header->counter;
    }

    ctx->counter_block[block_id] |= (1 << (u32) (header->counter & 31));
    return payload_len;
}


/*
 *
 */
static u32 crypto_initiator_build(main_context nmp,
                                  session_context ctx,
                                  nmp_initiator *initiator)
{
    const u64 tai = time_get();
    if (tai == 0)
    {
        return 1;
    }

    switch (ctx->state)
    {
        case CRYPTO_STATE_0:
        {
            // if this a fresh ctx, generate state1
            if (crypto_key_generate(ctx->ephemeral))
            {
                return 1;
            }

            // ctx->key_send is used to hold temporary key
            // for building initiators
            crypto_dh(NULL, 0, ctx->ephemeral,
                      ctx->remote_static, ctx->key_send);

            crypto_dh(ctx->key_send, NMP_KEYLEN,
                      nmp->key_private, ctx->remote_static,
                      ctx->crypto_state);
            break;
        }

        case CRYPTO_STATE_1:
        {
            // state1 is already available
            break;
        }

        default:
        {
            log("ctx->state");
            return 1;
        }
    }

    nmp_initiator tmp = {0};

    // since initiators can be rebuilt
    // this nonce must be incremented
    ctx->counter_send += 1;

    // header
    tmp.header.type = NMP_INITIATOR;
    tmp.header.pad[0] = 0;
    tmp.header.pad[1] = 0;
    tmp.header.pad[2] = 0;
    tmp.header.session_id = ctx->session_id;
    tmp.header.counter = ctx->counter_send;

    crypto_pubkey(ctx->ephemeral, tmp.header.ephemeral);

    // encrypted payload:
    tmp.encrypted.timestamp = tai;
    mem_copy(tmp.encrypted.key_static, nmp->key_public, NMP_KEYLEN);

    crypto_hash(ctx->crypto_state, NMP_KEYLEN, NULL, 0, tmp.encrypted.hash);
    crypto_aead_encrypt(ctx->key_send, tmp.header.session_id, tmp.header.counter,
                        (u8 *) &tmp.header, sizeof(tmp.header),
                        (u8 *) &tmp.encrypted, sizeof(tmp.encrypted),
                        (u8 *) &initiator->encrypted, initiator->mac);

    initiator->header = tmp.header;
    return 0;
}


/*
 *  authenticate initiator and compute state1
 */
static i32 crypto_initiator_auth(main_context nmp,
                                 const nmp_initiator *initiator,
                                 crypto_initiation_request *request)
{

    u8 temp_key[32] = {0};
    u8 local_hash[32] = {0};
    u8 state1[32] = {0};
    nmp_initiator tmp = {0};

    // first we must get the decryption key our
    // received initiator packet: static+remote_ephemeral dh
    crypto_dh(NULL, 0, nmp->key_private,
              initiator->header.ephemeral, temp_key);

    if (crypto_aead_decrypt(temp_key, initiator->header.session_id, initiator->header.counter,
                            (u8 *) &initiator->header, sizeof(initiator->header),
                            (u8 *) &initiator->encrypted, sizeof(initiator->encrypted),
                            initiator->mac, (u8 *) &tmp.encrypted))
    {
        log("initiator decryption failed");
        return 0;
    }

    const u64 tai = time_get();
    if (tai == 0)
    {
        return -1;
    }

    if (tai + 500 > tmp.encrypted.timestamp + NMP_INITIATOR_TTL)
    {
        log("initiator expired");
        return 0;
    }

    // now, that key is available: verify identity of the sender;
    // make a static+remote_static dh,
    // generate state by keyed hashing static+remote_static
    // using temporary decryption key
    crypto_dh(temp_key, NMP_KEYLEN,
              nmp->key_private, tmp.encrypted.key_static, state1);


    // generate hash of the state and compare it
    // to contents of initiator packet
    crypto_hash(state1, NMP_KEYLEN, NULL, 0, local_hash);
    if (cmp256(local_hash, tmp.encrypted.hash))
    {
        log("initiator verification failed");
        return 0;
    }

    request->id = initiator->header.session_id;
    mem_copy(request->remote_static, tmp.encrypted.key_static, 32);
    mem_copy(request->remote_ephemeral, initiator->header.ephemeral, 32);
    mem_copy(request->state, state1, 32);

    return 1;
}

/*
 *  upgrade state1 to state2 and derive session keys
 */
static u32 crypto_complete_request(session_context ctx,
                                   const crypto_initiation_request *request)
{
    u8 state2[32] = {0};
    u8 ephemeral[32] = {0};
    if (crypto_key_generate(ephemeral))
    {
        return 1;
    }

    crypto_dh(request->state, 32,
              ephemeral, request->remote_static, state2);

    // keys
    crypto_dh(state2, 32, ephemeral,
              request->remote_ephemeral, ctx->key_send);

    crypto_hash(ctx->key_send, 32,
                state2, 32,
                ctx->key_receive);

    mem_copy(ctx->ephemeral, ephemeral, 32);
    mem_copy(ctx->crypto_state, state2, 32);

    return 0;
}

/*
 *
 */
static void crypto_responder_build(const struct session *ctx,
                                   nmp_responder *responder)
{
    responder->header.type = NMP_RESPONDER;
    responder->header.pad[0] = 0;
    responder->header.pad[1] = 0;
    responder->header.pad[2] = 0;
    responder->header.session_id = ctx->session_id;

    crypto_pubkey(ctx->ephemeral, responder->header.ephemeral);
    crypto_hash((u8 *) &responder->header, sizeof(responder->header),
                ctx->crypto_state, 32, responder->hash);
}


/*
 *
 */
static u32 crypto_responder_auth(main_context nmp,
                                 session_context ctx,
                                 nmp_responder *responder)
{
    u8 state2[32] = {0};

    // get the final state by static+remote_ephemeral dh
    // then keyed hash current state using this dh
    crypto_dh(ctx->crypto_state, NMP_KEYLEN,
              nmp->key_private, responder->header.ephemeral, state2);

    // authenticate responder:
    // generate hash of the state and compare it
    // with the hash received in this response
    {
        u8 local_hash[32] = {0};

        crypto_hash((u8 *) &responder->header, sizeof(responder->header),
                    state2, NMP_KEYLEN, local_hash);

        if (cmp256(local_hash, responder->hash))
        {
            log("responder verification failed");
            return 1;
        }
    }

    // final key derivation
    crypto_dh(state2, NMP_KEYLEN, ctx->ephemeral,
              responder->header.ephemeral, ctx->key_receive);

    crypto_hash(ctx->key_receive, NMP_KEYLEN,
                state2, NMP_KEYLEN,
                ctx->key_send);


    mem_copy(ctx->crypto_state, state2, NMP_KEYLEN);
    ctx->counter_send = 0;
    ctx->counter_receive = 0;

    return 0;
}


/*
 *
 *
 */

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

    // sequence numbers start at zero but sequence_cmp()
    // is a strict '>' so set state counters to 0xffff,
    // exactly one before the u16 wraps around to zero
    ctx->tx_seq = 0xffff;
    ctx->tx_ack = 0xffff;
    ctx->rx_seq = 0xffff;
    ctx->rx_delivered = 0xffff;

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

    msg_context_wipe(ctx);

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
                         const nmp_notification status)
{
    log("%xu", ctx->session_id);
    callback(nmp->notif_cb, status, ctx->context_ptr);

    // any new network message or local requests related to this
    // context will be simply discarded as there is no hash table
    // entry, then when its timer fires off the context is finally
    // deleted; this prevents potential use-after-free() because timers
    // (timer fd) have context pointers and do not do any lookup
    hash_table_remove(&nmp->sessions, ctx->session_id);
    ctx->state = SESSION_STATUS_NONE;
}


static u32 session_send(main_context nmp, session_context ctx,
                        const u8 *payload, const i32 amt, const u8 type)
{
    const u32 bytes = crypto_packet_encrypt(ctx, type,
                                            payload, amt,
                                            &nmp->net_header);

    if (network_send(nmp->net_udp, nmp->net_buf, bytes, &ctx->addr))
    {
        return 1;
    }

    ctx->stat_tx += bytes;
    return 0;
}


static u32 session_initiator(main_context nmp, session_context ctx)
{
    nmp_initiator initiator = {0};
    if (crypto_initiator_build(nmp, ctx, &initiator))
    {
        return 1;
    }

    if (network_send(nmp->net_udp, &initiator, sizeof(nmp_initiator), &ctx->addr))
    {
        return 1;
    }

    ctx->stat_tx += sizeof(nmp_initiator);

    return (ctx->state == SESSION_STATUS_RESPONSE) ? 0 :
           timerfd_interval(ctx->timer_fd, SESSION_TIMER_RETRY);
}


static u32 session_responder(main_context nmp, session_context ctx)
{
    nmp_responder responder = {0};
    crypto_responder_build(ctx, &responder);

    if (network_send(nmp->net_udp, &responder,
                     sizeof(nmp_responder), &ctx->addr))
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

    ctx->stat_tx += sizeof(nmp_responder);
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
        return 0;
    }

    for (;;)
    {
        const i32 amt = msg_assemble(ctx, ctx->payload, nmp->payload);
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

                if (session_send(nmp, ctx, ctx->payload, amt, NMP_DATA))
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
    const u32 amt = msg_assemble_retry(ctx, ctx->payload, nmp->payload);
    if (amt)
    {
        return session_send(nmp, ctx, ctx->payload, (i32) amt, NMP_DATA);
    }

    return 0;
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
        log("skipping noack");
        return 0;
    }

    return session_send(nmp, ctx, (const u8 *) message,
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
        session_drop(nmp, ctx, NMP_SESSION_ERR);
        return 0;
    }

    msg_ack ack;

    msg_ack_assemble(ctx, &ack);
    ctx->response_retries += 1;

    return session_send(nmp, ctx, (u8 *) &ack, sizeof(msg_ack), NMP_ACK);
}

/*
 *  send an empty packet to
 *  keep this connection alive
 */
static u32 session_keepalive(main_context nmp, session_context ctx)
{
    assert(ctx->state == SESSION_STATUS_ESTAB);
    return session_send(nmp, ctx, NULL, 0, NMP_DATA);
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
    if (msg_queue(ctx, event->payload_data, event->header.len))
    {
        // let application know that the queue is full
        callback(nmp->notif_cb, NMP_SESSION_QUEUE, ctx->context_ptr);
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
    session_drop(nmp, ctx, NMP_SESSION_DC);
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
        log("rejecting connection request: wrong state %u %p",
            ctx_new->state, ctx_new);
        goto fail;
    }

    if (nmp->sessions.items >= NMP_SESSIONS)
    {
        log("rejecting connection request: MAXCONN");

        session_drop(nmp, ctx_new, NMP_SESSION_MAX);
        session_destroy(ctx_new);
        return 0;
    }

    if (hash_table_insert(&nmp->sessions, id_new, ctx_new))
    {
        goto fail;
    }

    if (session_initiator(nmp, ctx_new))
    {
        goto fail;
    }

    ctx_new->state = SESSION_STATUS_RESPONSE;
    return 0;


    fail:
    {
        session_drop(nmp, ctx_new, NMP_SESSION_ERR);
        session_destroy(ctx_new);
        return -1;
    }
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

    if (local_receive(nmp->local_rx, &buf.header) == -1)
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
        // marked with SESSION_STATUS_NONE so it does not accept
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
    log("state %u retry %u", ctx->state, nmp->retries[ctx->state]);

    if (ctx->timer_retries >= nmp->retries[ctx->state])
    {
        session_drop(nmp, ctx, NMP_SESSION_DC);
        return 0;
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
            // retry sending initiator
            if (session_initiator(nmp, ctx))
            {
                return 1;
            }

            break;
        }

        case SESSION_STATUS_CONFIRM:
        {
            // this means connection timed out, and we didn't
            // get any data after sending responder(s)
            session_drop(nmp, ctx, NMP_SESSION_DC);
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
        ctx->counter_send = 0;
        ctx->counter_receive = 0;

        callback(nmp->notif_cb, NMP_SESSION_RX, ctx->context_ptr);

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

    const i32 new_messages = msg_read(nmp, ctx, ctx->payload, payload);
    switch (new_messages)
    {
        case -1:
        {
            // mark this session with critical error but
            // do not return -1 as this is not critical
            // for entire library, just drop this connection
            session_drop(nmp, ctx, NMP_SESSION_ERR);
            return 0;
        }

        case 0:
        {
            // this is a fresh and valid packet which contains
            // payload, no new messages for us though;
            // no need to buffer these, just respond immediately
            return session_ack(nmp, ctx) ? -1 : 0;
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
        // this ack did not fail authentication
        // but we cant read it, something is going on
        log("payload != sizeof(ack)");

        session_drop(nmp, ctx, NMP_SESSION_ERR);
        return 1;
    }

    // we only want WINDOW, ESTAB & ACKWAIT here
    if (ctx->state < SESSION_STATUS_WINDOW)
    {
        log("rejecting new_context.state < SESSION_STATUS_ESTAB");
        return 0;
    }

    const msg_ack *ack = (msg_ack *) ctx->payload;
    const i32 acks = msg_ack_read(ctx, ack);
    if (acks < 0)
    {
        session_drop(nmp, ctx, NMP_SESSION_ERR);
        return 0;
    }

    return (u32) acks;
}


static i32 event_net_initiator(main_context nmp, const u32 id, const addr_internal *addr)
{
    if (nmp->auth_cb == NULL)
    {
        log("auth callback not set, skipping");
        return 0;
    }

    session_context ctx = hash_table_lookup(&nmp->sessions, id);
    if (ctx)
    {
        if (ctx->state == SESSION_STATUS_CONFIRM)
        {
            // here we already received a valid initiator from
            // this host, so we "trust enough" to skip verification;
            // even if these initiators are not valid, resending up to
            // SESSION_RESPONSE_RETRY responders doesn't do a lot of harm
            if (ctx->response_retries < SESSION_RESPONSE_RETRY)
            {
                ctx->response_retries += 1;
                return session_responder(nmp, ctx) ? -1 : 0;
            }
        }

        log("dropping initiator for %u", id);
        return 0;
    }

    if (nmp->sessions.items > HASH_TABLE_SIZE)
    {
        log("cannot accept new connection");
        return 0;
    }

    crypto_initiation_request request = {0};
    switch (crypto_initiator_auth(nmp, &nmp->net_initiator, &request))
    {
        case 0: // invalid initiation request
        {
            return 0;
        }

        case -1: // critical error
        {
            return -1;
        }

        case 1: // valid initiation request
        {
            break;
        }
    }

    // ask application to allow this session
    void *context_ptr = nmp->auth_cb(request.remote_static, &addr->generic,
                                     request.id, nmp->rx_context);
    if (context_ptr == NULL)
    {
        log("rejecting: application denied new session");
        return 0;
    }

    ctx = session_new(nmp->epoll_fd);
    if (ctx == NULL)
    {
        return -1;
    }

    ctx->context_ptr = context_ptr;
    ctx->addr = *addr;
    ctx->session_id = request.id;
    // fresh context, authenticated initiator
    ctx->stat_rx = sizeof(nmp_initiator);

    if (hash_table_insert(&nmp->sessions, request.id, ctx))
    {
        return -1;
    }

    crypto_complete_request(ctx, &request);
    if (session_responder(nmp, ctx))
    {
        return -1;
    }

    ctx->state = SESSION_STATUS_CONFIRM;
    return 0;
}

static u32 event_net_responder(main_context nmp, session_context ctx, const u32 amt)
{
    assert(ctx->state != SESSION_STATUS_NONE);

    if (ctx->state != SESSION_STATUS_RESPONSE)
    {
        // this also protects against duplicate responders
        log("state != SESSION_STATUS_RESPONSE");
        return 0;
    }

    if (amt != sizeof(nmp_responder))
    {
        log("rejecting net_buf.amt != sizeof(nmp_responder)");
        return 0;
    }

    if (crypto_responder_auth(nmp, ctx, &nmp->net_responder))
    {
        log("dropping responder for %u", ctx->session_id);
        return 0;
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

    // notify application of successful connection
    callback(nmp->notif_cb, NMP_SESSION_TX, ctx->context_ptr);

    if (timerfd_interval(ctx->timer_fd, nmp->keepalive_interval))
    {
        return 1;
    }

    return 0;
}

/*
 *
 */
static i32 event_net_read(main_context nmp,
                          session_context *ctx_ptr,
                          const addr_internal *addr,
                          const u32 amt)
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

    if (header.type == NMP_INITIATOR)
    {
        if (amt != sizeof(nmp_initiator))
        {
            return 0;
        }

        log("received initiator %x, counter %zu",
            header.session_id, header.counter);

        return event_net_initiator(nmp, header.session_id, addr);
    }

    session_context ctx = hash_table_lookup(&nmp->sessions, header.session_id);
    if (ctx == NULL)
    {
        log("discarded message for %u", header.session_id);
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
        if (mem_cmp(&ctx->addr.generic, &addr->generic,
                    sizeof(addr_internal)) != 0)
        {
            log("rejecting addr != recvfrom().addr");
            return 0;
        }
    }

    *ctx_ptr = ctx;

    // message, ack
    if (header.type > NMP_RESPONDER)
    {
        if (amt % 16)
        {
            log("rejecting amt %% 16");
            return 0;
        }

        const i32 payload = crypto_packet_decrypt(ctx, &nmp->net_header, amt,
                                                  ctx->payload);
        if (payload < 0)
        {
            log("payload < 0");

            // it is important to not let any other processing
            *ctx_ptr = NULL;
            return 0;
        }

        log("received data %x, counter %zu",
            header.session_id, header.counter);

        return payload;
    }

    log("received responder %x", header.session_id);
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
        addr_internal addr = {0};
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

            case NMP_RESPONDER:
            {
                if (event_net_responder(nmp, ctx, packet_total))
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
            // one (possible out of many) received packets triggered an error
            // that led to session_drop(), this context is not in hash table
            // anymore so no more data after 'fatal packet' but it can still
            // end up here in this queue => ignore
            continue;
        }

        // if there are new messages
        if (ctx->events & SESSION_EVENT_DATA)
        {
            msg_deliver_data(nmp, ctx);

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
            switch (msg_deliver_ack(nmp, ctx))
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
            log("failed to close() at index %u", i);
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

    const sa_family_t sa_family = conf->addr.sa.sa_family ?: AF_INET;
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

    const u16 ka = conf->keepalive_interval ?: SESSION_TIMER_KEEPALIVE;

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
    tmp->payload = conf->payload ?: NMP_PAYLOAD_MAX;
    tmp->payload += sizeof(msg_header); // we store 'real' payload limit

    tmp->rx_context = conf->auth_ctx;
    tmp->auth_cb = conf->auth_cb;
    tmp->notif_cb = conf->notification_cb;
    tmp->stats_cb = conf->stats_cb;

    tmp->data_cb = conf->data_cb;
    tmp->data_noack_cb = conf->data_noack_cb;
    tmp->ack_cb = conf->ack_cb;

    mem_copy(tmp->key_private, conf->key, NMP_KEYLEN);
    crypto_key_setup(tmp->key_private);
    crypto_pubkey(tmp->key_private, tmp->key_public);

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
u32 nmp_connect(main_context nmp,
                const u8 pub[NMP_KEYLEN],
                const struct sockaddr *addr,
                void *ctx)
{
    if (!pub || !addr)
    {
        log("invalid args");
        return 0;
    }

    if (nmp->sa_family != addr->sa_family)
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
    mem_copy(ctx_new->remote_static, pub, NMP_KEYLEN);
    mem_copy(&ctx_new->addr.generic, addr, nmp->sa_family == AF_INET ?
                                           sizeof(struct sockaddr_in) :
                                           sizeof(struct sockaddr_in6));

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
    msg_assemble_noack(header, buf, len);

    const local_event ev =
            {
                    .type = EVENT_LOCAL_DATA_NOACK,
                    .len = len,
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
    mem_copy(buf, nmp->key_public, NMP_KEYLEN);
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
