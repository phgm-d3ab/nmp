#ifndef NMP_H
#define NMP_H

/* sockaddr */
#include <arpa/inet.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct nmp_instance nmp_t;


/* verify that the address we send to matches address we receive from */
#define NMP_ADDR_VERIFY         (1u << 0)


enum
{
    /* byte length of keys (both private and public) */
    NMP_KEYLEN = 56,

    /* how many messages can we queue for sending (per session) */
    NMP_QUEUE = 256,

    /* how many active sessions can we have simultaneously */
    NMP_SESSIONS = 512,

    /* default interval for keepalive packets (in seconds) */
    NMP_KEEPALIVE_DEFAULT = 10,

    /* maximum amount of data sent in a single message */
    NMP_PAYLOAD_MAX = 1404,

    /*
     * maximum size of application defined payload
     * included with requests and responses
     */
    NMP_INITIATION_PAYLOAD = 96,

    /* maximum amount of ops nmp_op_submit() can read per call */
    NMP_OPS_BATCH = 32,
};


enum nmp_op_types
{
    /* send data to some session, .entry_arg must point at data to be sent */
    NMP_OP_SEND = 0,

    /*
     *  sends a 'no acknowledgement' message. these are unique (no duplicates), sent
     *  immediately without any buffering, not reliable and the order is not preserved
     */
    NMP_OP_SEND_NOACK = 1,

    /* drop some session by id */
    NMP_OP_DROP = 2,

    /*
     *  connect to a remote peer using information provided in current op entry,
     *  .entry_arg must point to a valid nmp_op_connect structure. after this
     *  entry is consumed, id of created session is put into .session_id member
     */
    NMP_OP_CONNECT = 3,

    /* gracefully exit */
    NMP_OP_TERMINATE = 4,
};


enum nmp_status
{
    /* useful when returning empty command from callbacks that discard result */
    NMP_CMD_EMPTY = 0,

    NMP_CMD_ACCEPT,
    NMP_CMD_RESPOND,
    NMP_CMD_DROP,

    /*
     * session stopped receiving any data from remote peer, and is no longer active
     * message id of latest acknowledged message is stored in nmp_cb_status
     */
    NMP_SESSION_DISCONNECTED,

    /*
     * outgoing connection request received a valid response.
     * nmp_cb_status holds a payload sent by a remote peer.
     * return ACCEPT or DROP command to indicate action
     */
    NMP_SESSION_RESPONSE,

    /* incoming connection has been established */
    NMP_SESSION_INCOMING,

    /*
     * queue is full: outgoing message was not queued for sending.
     * nmp_cb_status holds a msg id for latest queued message
     */
    NMP_SESSION_QUEUE,

    /*
     * limit on the maximum amount of sessions has been reached,
     * could not start requested newly requested one
     * id of cancelled session is stored in nmp_cb_status
     */
    NMP_SESSION_MAX,

    /*
     * no more data can be sent over this session, and it is dropped immediately
     * note: this happens only when running out of nonces, in a very
     * unlikely event when 2^64 - 1 packets were sent over network
     */
    NMP_SESSION_EXPIRED,

    /* remote peer violates protocol, session terminated */
    NMP_SESSION_ERR_PROTOCOL,
};


/* convenience */
union nmp_sa
{
    struct sockaddr sa;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
};


/*
 *  argument for request callback:
 *  members .addr, .id, .request_payload are set by the library,
 *  .context_ptr and .response_payload are set by application
 */
struct nmp_cb_request
{
    union nmp_sa addr;
    uint32_t id;
    uint8_t *request_payload;

    void *context_ptr;
    uint8_t response_payload[NMP_INITIATION_PAYLOAD];
};


/*
 *  argument for status callback:
 *  delivers additional information about events set in status callback
 */
union nmp_cb_status
{
    uint8_t payload[NMP_INITIATION_PAYLOAD];
    uint64_t msg_id;
    uint32_t session_id;
    union nmp_sa addr;
};


struct nmp_op_connect
{
    uint8_t pubkey[NMP_KEYLEN];
    uint8_t payload[NMP_INITIATION_PAYLOAD];
    uint32_t payload_len;
    union nmp_sa addr;
    void *context_ptr;
};


/*
 *  describes a local request to instance of nmp_t
 *  note: once nmp_ops_submit() returns, whatever entry_arg points to
 *  is 'consumed' and is no longer needed
 */
struct nmp_op
{
    uint8_t type;
    uint8_t flags;
    uint16_t len;
    uint32_t session_id;
    uint64_t user_data;
    void *entry_arg;
};


struct nmp_conf
{
    /* address to bind to */
    union nmp_sa addr;

    /* x448 private key to use */
    uint8_t key[NMP_KEYLEN];

    /*
     * set the maximum payload size to be included in a data packet; values
     * between 492 and NMP_PAYLOAD_MAX (1404) are supported; this can be
     * used to control MTU as typical data packet is made of 16 byte header,
     * payload padded to be multiple of 16 and a poly1305 authentication tag
     * set to zero to leave at a default value of NMP_PAYLOAD_MAX
     */
    uint16_t payload;

    /*
     * controls how often to send keepalive packet
     * zero sets a default value of NMP_KEEPALIVE_DEFAULT (10)
     */
    uint16_t keepalive_interval;

    /* mask for options */
    uint32_t options;


    /*
     * this pointer is passed to request_cb so that application
     * can have its context for processing connection requests
     */
    void *request_ctx;

    /*
     * incoming request has arrived: make a decision, optionally populate
     * response_payload member and return one of NMP_CMD_* values
     */
    enum nmp_status (*request_cb)(const uint8_t *pubkey,
                                  struct nmp_cb_request *,
                                  void *request_ctx);


    /* new message has arrived */
    void (*data_cb)(const uint8_t *data,
                    const uint32_t len,
                    void *session_ctx);

    /* noack message */
    void (*data_noack_cb)(const uint8_t *data,
                          const uint32_t len,
                          void *session_ctx);

    /* acknowledgement arrived, .user_data u64 given at submission time is provided */
    void (*ack_cb)(const uint64_t,
                   void *session_ctx);

    /* shows the amount of transferred data in this session */
    void (*stats_cb)(const uint64_t rx,
                     const uint64_t tx,
                     void *session_ctx);

    /* deliver various session related events: errors, status changes */
    enum nmp_status (*status_cb)(const enum nmp_status,
                                 const union nmp_cb_status *,
                                 void *session_ctx);
};


/*
 *  creates new instance of nmp_t and returns pointer to it
 *  NULL indicates an error
 */
nmp_t *nmp_new(const struct nmp_conf *);


/*
 *  copies public key of nmp_t into u8 buf
 */
void nmp_pubkey(const nmp_t *, uint8_t output[NMP_KEYLEN]);


/*
 *  submit up to NMP_OP_BATCH (32) requests to instance of nmp_t; returns
 *  number of accepted ops, or index of request that failed validation
 */
int nmp_submit(nmp_t *, struct nmp_op *ops, int num_ops);


/*
 *  'runs' instance of nmp_t, timeout in milliseconds
 *  set to -1 for no timeout
 *  returns zero on success
 */
int nmp_run(nmp_t *, int32_t timeout);


#ifdef __cplusplus
}
#endif

#endif /* NMP_H */
