#ifndef NMP_H
#define NMP_H

// sockaddr
#include <arpa/inet.h>


#ifdef __cplusplus
extern "C" {
#endif

typedef struct nmp_data nmp_t;


// byte length of keys (both private and public)
#define NMP_KEYLEN              32

// how many messages can we queue for sending
#define NMP_QUEUE               256

// how many active sessions can we have simultaneously
#define NMP_SESSIONS            512

// default interval for keepalive packets (in seconds)
#define NMP_KEEPALIVE_DEFAULT   10

// maximum amount of data sent in a single message
#define NMP_PAYLOAD_MAX         1452

// verify that the address we send to matches
// address we receive from
#define NMP_ADDR_VERIFY         1


typedef enum
{
    NMP_SESSION_ERR,
    NMP_SESSION_DC,         // session disconnected
    NMP_SESSION_TX,         // outgoing connection
    NMP_SESSION_RX,         // incoming connection
    NMP_SESSION_QUEUE,      // queue is full
    NMP_SESSION_MAX,        // maximum number of connections

} nmp_notification;


typedef struct
{
    // address to bind to
    union
    {
        struct sockaddr_in v4;
        struct sockaddr_in6 v6;
        struct sockaddr sa;

    } addr;

    // secret (private) key to use
    // public key is derived using curve25519
    // and can be retrieved later using nmp_pubkey()
    uint8_t key[NMP_KEYLEN];

    // set the maximum payload size to be included in a data packet;
    // values between 524 and NMP_PAYLOAD_MAX (1452) are supported;
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

    // this pointer is passed to auth_cb so that application
    // can have its context for processing connection requests
    void *auth_ctx;

    // initiator packet has been received: remote public
    // key, remote network address and would-be session id
    // is provided; application should return NULL to deny
    // or pointer to session context to accept this connection
    void *(*auth_cb)(const uint8_t *pubkey,
                     const struct sockaddr *,
                     uint32_t session,
                     void *auth_ctx);


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

    // deliver various session events:
    // errors, connection status changes
    void (*notification_cb)(const nmp_notification,
                            void *session_ctx);

    // shows the amount of valid data delivered to context
    // from recvfrom() and the amount of data fed to sendto()
    void (*stats_cb)(const uint64_t rx,
                     const uint64_t tx,
                     void *session_ctx);

} nmp_conf_t;


/*
 *  creates new instance of nmp_t and returns pointer to it
 *  NULL indicates an error
 */
nmp_t *nmp_new(const nmp_conf_t *);


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
 *  connect to some host using public key and address
 *  this will trigger a notification to show the result
 *  note: length of buffer pointed to by address argument
 *  is assumed sufficient to hold an address of a
 *  family specified in sa_family member
 *
 *  returns zero on success
 */
uint32_t nmp_connect(nmp_t *, const uint8_t pub[NMP_KEYLEN],
                     const struct sockaddr *, void *ctx);


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
 *  exit gracefully terminating all existing sessions
 */
uint32_t nmp_terminate(nmp_t *);


#ifdef __cplusplus
}
#endif

#endif // NMP_H
