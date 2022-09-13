#ifndef NMP_H
#define NMP_H

// sockaddr
#include <arpa/inet.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct nmp_data nmp_t;


// byte length of keys (both private and public)
#define NMP_KEYLEN              56

// how many messages can we queue for sending (per session)
#define NMP_QUEUE               256

// how many active sessions can we have simultaneously
#define NMP_SESSIONS            512

// default interval for keepalive packets (in seconds)
#define NMP_KEEPALIVE_DEFAULT   10

// maximum amount of data sent in a single message
#define NMP_PAYLOAD_MAX         1404

// maximum size of application defined payload
// included with requests and responses
#define NMP_INITIATION_PAYLOAD  120

// verify that the address we send to matches
// address we receive from
#define NMP_ADDR_VERIFY         1


enum nmp_status
{
    // useful when returning empty command
    // from callbacks that discard result
    NMP_CMD_EMPTY = 0,

    NMP_CMD_ACCEPT,
    NMP_CMD_RESPOND,
    NMP_CMD_DROP,


    // session stopped receiving any data
    // from remote peer, and is no longer active
    // message id of latest acknowledged message
    // is stored in nmp_status_container
    NMP_SESSION_DISCONNECTED,

    // outgoing connection started with nmp_connect()
    // received a valid response. nmp_status_container
    // holds a payload sent by a remote peer.
    // return ACCEPT or DROP command to indicate action
    NMP_SESSION_RESPONSE,

    // incoming connection has been established
    NMP_SESSION_INCOMING,

    // queue is full: outgoing message was not queued
    // for sending. nmp_status_container holds a msg
    // id for latest queued message
    NMP_SESSION_QUEUE,

    // could not start a new (outgoing) session;
    // id of cancelled session is stored in
    // nmp_status_container
    NMP_SESSION_MAX,

    // no more data can be sent over this session,
    // and it is dropped immediately
    // note: this happens only when running out of
    // nonces, so, in a very unlikely event when
    // 2^64 - 1 packets were sent over network
    NMP_SESSION_EXPIRED,

    // remote peer violates protocol,
    // session terminated
    NMP_SESSION_ERR_PROTOCOL,

};


// convenience
union nmp_sa
{
    struct sockaddr sa;
    struct sockaddr_in ip4;
    struct sockaddr_in6 ip6;
};


// members .addr, .id, .request_payload are
// set by the library; .context_ptr and
// .response_payload are set by application
struct nmp_request_container
{
    union nmp_sa addr;
    uint32_t id;
    uint8_t *request_payload;

    void *context_ptr;
    uint8_t response_payload[NMP_INITIATION_PAYLOAD];
};


union nmp_status_container
{
    uint8_t payload[NMP_INITIATION_PAYLOAD];
    uint64_t msg_id;
    uint32_t session_id;
    union nmp_sa addr;
};


struct nmp_conf
{
    // address to bind to
    union nmp_sa addr;

    // x448 private key to use
    uint8_t key[NMP_KEYLEN];

    // set the maximum payload size to be included in a data packet;
    // values between 492 and NMP_PAYLOAD_MAX (1404) are supported;
    // this can be used to control MTU as typical data packet is made
    // of 16 byte header, payload padded to be multiple of 16 and
    // a poly1305 authentication tag
    // set to zero to leave at a default value of NMP_PAYLOAD_MAX
    uint16_t payload;

    // controls how often to send keepalive packet
    // zero sets a default value of NMP_KEEPALIVE_DEFAULT (10)
    uint16_t keepalive_interval;

    // mask for options
    uint32_t options;


    // this pointer is passed to request_cb so that application
    // can have its context for processing connection requests
    void *request_ctx;

    // incoming request has arrived: make a decision,
    // optionally populate response_payload member
    // and return one of NMP_CMD_* values
    enum nmp_status (*request_cb)(const uint8_t *pubkey,
                                  struct nmp_request_container *,
                                  void *request_ctx);


    // new message has arrived
    void (*data_cb)(const uint8_t *data,
                    const uint32_t len,
                    void *session_ctx);

    // noack message
    void (*data_noack_cb)(const uint8_t *data,
                          const uint32_t len,
                          void *session_ctx);

    // acknowledgement for message id has arrived
    // when sending messages using nmp_send(),
    // this id starts from zero
    void (*ack_cb)(const uint64_t,
                   void *session_ctx);

    // shows the amount of valid data delivered to context
    // from recvfrom() and the amount of data fed to sendto()
    void (*stats_cb)(const uint64_t rx,
                     const uint64_t tx,
                     void *session_ctx);

    // deliver various session events:
    // errors, connection status changes
    enum nmp_status (*status_cb)(const enum nmp_status,
                                 const union nmp_status_container *,
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
 *  'runs' instance of nmp_t, timeout in milliseconds
 *  set to -1 for no timeout
 *  returns zero on success
 */
uint32_t nmp_run(nmp_t *, int32_t timeout);


/*
 *  connect to some host using public key and address,
 *  this will trigger a notification to show the result.
 *  optionally include a payload as part of this request,
 *  sizes up to NMP_INITIATION_PAYLOAD (120) are accepted
 *
 *  returns zero on success
 */
uint32_t nmp_connect(nmp_t *, const uint8_t *pub, const union nmp_sa *addr,
                     const void *payload, uint32_t payload_len, void *ctx);


/*
 *  drop some session by id; triggers a notification
 *  returns zero on success
 */
uint32_t nmp_drop(nmp_t *, uint32_t session);


/*
 *  send some data over network; maximum value
 *  for length argument corresponds to selected
 *  maximum during nmp_t initialization
 *  returns zero on success
 */
uint32_t nmp_send(nmp_t *, uint32_t session,
                  const uint8_t *data, uint16_t len);


/*
 *  sends a 'no acknowledgement' message;
 *  these messages are unique (no dupes), sent immediately
 *  without any buffering, they are not reliable and
 *  order is not preserved
 *  returns zero on success
 */
uint32_t nmp_send_noack(nmp_t *, uint32_t session,
                        const uint8_t *data, uint16_t len);

/*
 *  exit gracefully, terminate all existing sessions,
 *  release all related resources
 */
uint32_t nmp_terminate(nmp_t *);


#ifdef __cplusplus
}
#endif

#endif // NMP_H
