#include "nmp.c"
#include "test_drv.h"


#define get_random(ptr_, len_) do { \
        if (getrandom(ptr_, len_, 0) != len_) test_panic(); } while (0)


static struct noise_handshake base_state(struct rnd_pool *rnd)
{
        struct noise_handshake temp = {0};
        if (blake2b_hmac_init(&temp.hmac))
                test_panic();

        if (blake2b_init(&temp.hash))
                test_panic();

        if (chacha20poly1305_init(&temp.aead, NULL))
                test_panic();

        memcpy(temp.symmetric_ck, noise_protocol_name, NOISE_HASHLEN);
        memcpy(temp.symmetric_h, noise_protocol_name, NOISE_HASHLEN);
        temp.rnd = rnd;

        return temp;
}


void damage_initiator(const struct noise_handshake *ctx,
                      const u8 *header,
                      const struct noise_initiator *initiator)
{
        u8 _payload[NOISE_HANDSHAKE_PAYLOAD] = {0};
        struct {
                u8 header[sizeof(struct nmp_header)];
                struct noise_initiator initiator;

        } msg;

        memcpy(msg.header, header, sizeof(msg.header));
        memcpy(&msg.initiator, initiator, sizeof(struct noise_initiator));
        u8 *ptr = (u8 *) &msg;

        for (u32 i = 0; i < (sizeof(struct nmp_request) * 8); i++) {
                struct noise_handshake temp = *ctx;
                ptr[(i / 8) % sizeof(msg)] ^= (1u << (i & 7));

                i32 res = noise_initiator_read(&temp, &msg.initiator,
                                               msg.header, sizeof(msg.header),
                                               _payload);
                if (res == 0)
                        test_panic();

                ptr[(i / 8) % sizeof(msg)] ^= (1u << (i & 7));
        }
}


void damage_responder(const struct noise_handshake *ctx,
                      const u8 *header,
                      const struct noise_responder *responder)
{
        u8 _payload[NOISE_HANDSHAKE_PAYLOAD] = {0};
        struct {
                u8 header[sizeof(struct nmp_header)];
                struct noise_responder responder;

        } msg;

        memcpy(msg.header, header, sizeof(struct nmp_header));
        memcpy(&msg.responder, responder, sizeof(struct noise_responder));
        u8 *ptr = (u8 *) &msg;

        for (u32 i = 0; i < (sizeof(struct nmp_response) * 8); i++) {
                struct noise_handshake temp = *ctx;
                ptr[(i / 8) % sizeof(msg)] ^= (1u << (i & 7));

                i32 res = noise_responder_read(&temp, &msg.responder,
                                               msg.header, sizeof(msg.header),
                                               _payload);
                if (res == 0)
                        test_panic();

                ptr[(i / 8) % sizeof(msg)] ^= (1u << (i & 7));
        }
}


int split(struct noise_handshake *alice,
          struct noise_handshake *bob)
{
        u8 alice_temp_k1[NOISE_HASHLEN] = {0};
        u8 alice_temp_k2[NOISE_HASHLEN] = {0};
        if (noise_hkdf(&alice->hmac, alice->symmetric_ck,
                       NULL, 0,
                       alice_temp_k1, alice_temp_k2))
                test_panic();

        u8 bob_temp_k1[NOISE_HASHLEN] = {0};
        u8 bob_temp_k2[NOISE_HASHLEN] = {0};
        if (noise_hkdf(&bob->hmac, bob->symmetric_ck,
                       NULL, 0,
                       bob_temp_k1, bob_temp_k2))
                test_panic();

        if (memcmp(alice_temp_k1, bob_temp_k1, NOISE_HASHLEN) != 0)
                return 1;

        if (memcmp(alice_temp_k2, bob_temp_k2, NOISE_HASHLEN) != 0)
                return 1;

        return 0;
}


int main(void)
{
        u8 payload[NOISE_HANDSHAKE_PAYLOAD] = {0};
        u8 header1[sizeof(struct nmp_header)] = {0};
        u8 header2[sizeof(struct nmp_header)] = {0};
        get_random(header1, sizeof(header1));
        get_random(header2, sizeof(header2));

        struct blake2b_ctx blake2b = {0};
        if (blake2b_init(&blake2b))
                test_panic();

        struct rnd_pool rnd = {0};
        if (rnd_reset_pool(&rnd))
                test_panic();

        struct noise_handshake alice = base_state(&rnd);
        struct noise_keypair alice_key = {0};

        struct noise_handshake bob = base_state(&rnd);
        struct noise_keypair bob_key = {0};

        if (noise_keypair_generate(blake2b, &rnd, &alice_key))
                test_panic();

        if (noise_keypair_generate(blake2b, &rnd, &bob_key))
                test_panic();

        alice.s = &alice_key;
        memcpy(alice.rs, bob_key.pub_raw, NOISE_DHLEN);

        bob.s = &bob_key;
        memcpy(bob.rs, bob_key.pub_raw, NOISE_DHLEN);


        if (noise_state_init(&alice) || noise_state_init(&bob))
                test_panic();

        struct noise_initiator initiator = {0};
        if (noise_initiator_write(&alice, &initiator,
                                  header1, sizeof(header1), payload))
                test_panic();

        damage_initiator(&bob, header1, &initiator);


        u8 bob_payload[NOISE_HANDSHAKE_PAYLOAD] = {0};
        if (noise_initiator_read(&bob, &initiator,
                                 header1, sizeof(header1), bob_payload))
                test_panic();

        struct noise_responder responder = {0};
        if (noise_responder_write(&bob, &responder,
                                  header2, sizeof(header2), bob_payload))
                test_panic();


        damage_responder(&alice, header2, &responder);

        u8 alice_payload[NOISE_HANDSHAKE_PAYLOAD] = {0};
        if (noise_responder_read(&alice, &responder,
                                 header2, sizeof(header2), alice_payload))
                test_panic();


        return split(&alice, &bob);
}
