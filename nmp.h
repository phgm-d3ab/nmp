#ifndef NMP_H
#define NMP_H

/* sockaddr */
#include <arpa/inet.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct nmp_instance nmp_t;


/* verify that the address we send to matches address we receive from */
#define NMP_F_ADDR_VERIFY   (1u << 0)

/*
 * tells the library to not allocate buffer for current message. application is
 * responsible for keeping this data intact until acknowledgement is received
 */
#define NMP_F_MSG_NOALLOC   (1u << 2)

/*
 * do not require acknowledgement for this message. this also means message
 * is sent immediately without any buffering, order is not preserved
 */
#define NMP_F_MSG_NOACK     (1u << 3)


enum {
        /* byte length of keys (both private and public) */
        NMP_KEYLEN = 56,

        /* how many messages can we queue for sending (per session) */
        NMP_QUEUELEN = 256,

        /* how many active sessions can we have simultaneously */
        NMP_SESSIONS_MAX = 512,

        /*
         * default inactivity timeout. if no data has been
         * received during this period, session is dropped
         */
        NMP_KEEPALIVE_TIMEOUT = 30,

        /* how many keepalive messages to send during NMP_KEEPALIVE_TIMEOUT */
        NMP_KEEPALIVE_MESSAGES = 3,

        /* maximum amount of data sent in a single message */
        NMP_PAYLOAD_MAX = 1404,

        /* maximum size of application defined payload included with requests and responses */
        NMP_INITIATION_PAYLOAD = 224,

        /* maximum amount of ops nmp_submit() can read per call */
        NMP_RQ_BATCH = 32,
};


enum nmp_rq_ops {
        /* send data to some session, .entry_arg must point at data to be sent */
        NMP_OP_SEND = 0,

        /* drop some session by id */
        NMP_OP_DROP = 1,

        /*
         *  connect to a remote peer using information provided in current op entry,
         *  .entry_arg must point to a valid nmp_op_connect structure. after this
         *  entry is consumed, id of created session is put into .session_id member
         */
        NMP_OP_CONNECT = 2,

        /* gracefully exit */
        NMP_OP_TERMINATE = 3,
};


enum nmp_status {
        /* useful when returning empty command from callbacks that discard result */
        NMP_STATUS_ZERO = 0,

        /* accept received initiation/response and proceed with this session */
        NMP_CMD_ACCEPT,

        /*
         * instructs request callback to send a valid response
         * but not to establish a full session
         */
        NMP_CMD_RESPOND,

        /* instructs to drop this session immediately and not send any data */
        NMP_CMD_DROP,

        /*
         * session stopped receiving any data from remote peer, and is no longer active
         * user_data of latest acknowledged message is stored in nmp_cb_status
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
         * no more data can be sent over this session, and it is dropped immediately
         * note: this happens only when running out of nonces, in a very
         * unlikely event when 2^64 - 1 packets were sent over network
         */
        NMP_SESSION_EXPIRED,

        /*
         * queue is full: outgoing message was not queued for sending.
         * nmp_cb_status holds .user_data of message failed to queue
         */
        NMP_ERR_QUEUE,

        /*
         * limit on the maximum amount of sessions has been reached,
         * could not start newly requested one.
         * id of cancelled session is stored in nmp_cb_status
         */
        NMP_ERR_MAXCONN,

        /* remote peer violates protocol, session terminated */
        NMP_ERR_PROTOCOL,

        /* op supplied in nmp_submit() contained errors and was rejected */
        NMP_ERR_INVAL,

        /*
         * sending data failed, nmp_cb_status holds address of remote peer; errno is
         * set appropriately. return DROP/ZERO to drop this session or discard error
         */
        NMP_ERR_SEND,


        /* critical errors */
        NMP_ERR_IORING,
        NMP_ERR_CRYPTO,
        NMP_ERR_RND,    /* getrandom() */
        NMP_ERR_TIME,   /* clock_gettime() */

        NMP_ERR_SOCKET,
        NMP_ERR_BIND,
        NMP_ERR_SOCKPAIR,
        NMP_ERR_WRITE,
        NMP_ERR_GETSOCKNAME,
        NMP_ERR_MALLOC,

        NMP_STATUS_LAST,
};


/* convenience */
union nmp_sa {
        struct sockaddr sa;
        struct sockaddr_in ip4;
        struct sockaddr_in6 ip6;
};


/*
 *  describes connection request. this is used both
 *  for incoming and outgoing requests
 */
struct nmp_rq_connect {
        /* handle for created session */
        uint32_t id;

        /* remote peer's network address */
        union nmp_sa addr;

        /* remote peer's x448 public key */
        uint8_t pubkey[NMP_KEYLEN];

        /* session specific flags */
        uint8_t flags;

        /* session specific tunable for NMP_KEEPALIVE_MESSAGES */
        uint8_t keepalive_messages;

        /* session specific tunable for NMP_KEEPALIVE_TIMEOUT */
        uint8_t keepalive_timeout;

        /* session specific tunable for NMP_PAYLOAD_MAX */
        uint16_t transport_payload;

        /* pointer that will be passed to callbacks */
        void *context_ptr;

        /* include application defined data to request/response packets  */
        uint8_t init_payload[NMP_INITIATION_PAYLOAD];
};


/*
 *  describes a local request to instance of nmp_t
 *  note: once nmp_submit() returns, whatever entry_arg points to
 *  is 'consumed' and is no longer needed
 */
struct nmp_rq {
        /* type of request, one of nmp_rq_ops */
        uint8_t op;

        /* message specific flags */
        uint8_t msg_flags;

        /* length of message to be sent */
        uint16_t len;

        /* id of session this request addressed to */
        uint32_t session_id;

        /* application defined data */
        uint64_t user_data;

        /* holds pointer to various objects required by requested op */
        void *entry_arg;
};


/*
 *  argument for status callback:
 *  delivers additional information about events set in status callback
 */
union nmp_cb_status {
        uint8_t payload[NMP_INITIATION_PAYLOAD];
        uint64_t user_data;
        uint32_t session_id;
        union nmp_sa addr;
};


struct nmp_conf {
        /* if nmp_new() fails, it sets an error code */
        enum nmp_status err;

        /* address to bind to */
        union nmp_sa addr;

        /* public key of created instance will be available here after nmp_new() returns */
        uint8_t pubkey[NMP_KEYLEN];

        /* x448 private key to use */
        uint8_t key[NMP_KEYLEN];

        /* mask for options */
        uint32_t options;

        /*
         * udp socket created for use with new instance will be available here
         * after nmp_new() returns; if set, library will call application defined
         * socket_data() with its context pointer when received packet was not recognized.
         */
        int socket;
        void *socket_ctx;
        void (*socket_data)(const uint8_t *data, const uint32_t len,
                            const union nmp_sa *addr, void *soc_ctx);

        /*
         *
         */
        void *request_ctx;
        int (*request_cb)(struct nmp_rq_connect *request,
                          const uint8_t request_payload[NMP_INITIATION_PAYLOAD],
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
        int (*status_cb)(const enum nmp_status,
                         const union nmp_cb_status *,
                         void *session_ctx);
};


/*
 *  creates new instance of nmp_t and returns pointer to it
 *  NULL indicates an error
 */
nmp_t *nmp_new(struct nmp_conf *);


/*
 *  submit up to NMP_RQ_BATCH (32) requests to instance of nmp_t; returns
 *  number of accepted ops, or index of request that failed validation
 */
int nmp_submit(nmp_t *, struct nmp_rq *, int num_requests);


/*
 *  'runs' instance of nmp_t, timeout in milliseconds
 *  set to 0 for no timeout. returns zero on success
 */
int nmp_run(nmp_t *, uint32_t timeout);


#ifdef __cplusplus
}
#endif

#endif /* NMP_H */
