#include "test_drv.h"

#include <string.h>
#include <assert.h>
#include <unistd.h>


enum {
        MESSAGES = 30,
};

static_assert((int) MESSAGES <= (int) NMP_RQ_BATCH, "");


struct message {
        u32 num;
        u8 bytes[1000];
};


struct packet {
        u32 len;
        u8 buf[1500];
};


struct bob_ctx {
        u64 expected_ack;
        u32 session_id;
};


static void pkt_fwd(const int soc, const union nmp_sa *a,
                    const union nmp_sa *b, const u32 count)
{
        union nmp_sa ret_addr[2] = {
                [false] = *a,
                [true] = *b,
        };

        for (u32 i = 0; i < count; i++) {
                struct packet pkt = {0};
                union nmp_sa addr = {0};
                socklen_t addrlen = sizeof(addr);
                isize amt = recvfrom(soc, pkt.buf, sizeof(pkt.buf),
                                     0, &addr.sa, &addrlen);
                if (amt == -1)
                        test_panic();

                bool ret_dir = (memcmp(&addr.sa, &ret_addr[0].sa,
                                       sizeof(union nmp_sa)) == 0);

                amt = sendto(soc, pkt.buf, amt, 0,
                             &ret_addr[ret_dir].sa, addrlen);
                if (amt == -1)
                        test_panic();
        }
}


static u32 pkt_read(const int soc, struct packet *pkt[MESSAGES])
{
        u32 i = 0;

        for (; i < MESSAGES; i++) {
                struct packet *in = malloc(sizeof(struct packet));
                if (!in)
                        test_panic();

                isize sz = read(soc, in->buf, 1500);
                if (sz == -1)
                        break;

                in->len = (u32) sz;
                pkt[i] = in;
        }

        return i;
}


static void pkt_shuffle(struct packet *pkt[MESSAGES], const u32 amt)
{
        u8 shuffle_idx[MESSAGES] = {0};
        random_bytes(shuffle_idx, sizeof(shuffle_idx));

        for (u32 i = 0; i < amt; i++) {
                struct packet *temp = pkt[i];
                const u32 swap_idx = shuffle_idx[i] % amt;

                pkt[i] = pkt[swap_idx];
                pkt[swap_idx] = temp;
        }
}


void test_run(const int soc,
              const struct test_peer *alice,
              const struct test_peer *bob)
{
        /* handshake */
        pkt_fwd(soc, &alice->addr, &bob->addr, 3);

        struct packet *bob_data[MESSAGES] = {0};
        u32 pkts = pkt_read(soc, bob_data);
        if (pkts != MESSAGES)
                test_panic();

        pkt_shuffle(bob_data, MESSAGES);

        struct packet *alice_acks[MESSAGES] = {0};
        for (u32 i = 0; i < MESSAGES; i++) {
                struct packet *data = bob_data[i];
                struct packet *ack = malloc(sizeof(struct packet));
                if (!ack)
                        test_panic();

                isize res = sendto(soc, data->buf, data->len,
                                   0, &alice->addr.sa, sizeof(alice->addr));
                if (res == -1)
                        test_panic();

                memset(ack, 0, sizeof(struct packet));
                res = read(soc, ack->buf, sizeof(ack->buf));
                if (res == -1)
                        test_panic();

                ack->len = (u32) res;
                alice_acks[i] = ack;
        }

        pkt_shuffle(alice_acks, MESSAGES);

        for (u32 i = 0; i < MESSAGES; i++) {
                struct packet *pkt = alice_acks[i];
                isize res = sendto(soc, pkt->buf, pkt->len,
                                   0, &bob->addr.sa, sizeof(bob->addr));
                if (res == -1)
                        test_panic();
        }
}


void alice_init(struct test_drv *drv, struct test_peer *bob,
                const union nmp_sa *ctl)
{
        struct nmp_rq_connect c = {0};
        memcpy(c.pubkey, bob->pubkey, NMP_KEYLEN);
        c.addr = *ctl;
        c.context_ptr = drv;

        struct nmp_rq rq = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &c,
        };

        nmp_submit(test_instance(drv), &rq, 1);
}


int bob_request(struct nmp_rq_connect *request, const uint8_t *p, void *drv)
{
        UNUSED(p);
        request->context_ptr = drv;

        struct bob_ctx *ctx = malloc(sizeof(struct bob_ctx));
        if (!ctx)
                test_panic();

        ctx->expected_ack = 0;
        ctx->session_id = request->id;

        test_set_ctx(drv, ctx);
        return NMP_CMD_ACCEPT;
}


int alice_status(enum nmp_status s,
                 const union nmp_cb_status *cb, void *drv)
{
        UNUSED(cb);
        UNUSED(s);

        u32 *ord = malloc(sizeof(u32));
        if (!ord)
                test_panic();

        *ord = 0;
        test_set_ctx(drv, ord);
        return NMP_CMD_ACCEPT;
}


int bob_status(enum nmp_status s,
               const union nmp_cb_status *d, void *drv)
{
        UNUSED(s);
        UNUSED(d);
        struct bob_ctx *ctx = test_get_ctx(drv);
        struct nmp_rq rqs[MESSAGES] = {0};
        struct message *msg = malloc(sizeof(struct message) * MESSAGES);
        if (!msg)
                test_panic();

        for (u32 i = 0; i < MESSAGES; i++) {
                msg[i] = (struct message) {
                        .num = i,
                        .bytes = {0},
                };

                rqs[i] = (struct nmp_rq) {
                        .op = NMP_OP_SEND,
                        .len = sizeof(struct message),
                        .session_id = ctx->session_id,
                        .user_data = i,
                        .entry_arg = (msg + i),
                };
        }

        nmp_submit(test_instance(drv), rqs, MESSAGES);
        free(msg);

        return NMP_STATUS_ZERO;
}


void alice_data(const u8 *data, const u16 len, void *drv)
{
        if (len != sizeof(struct message))
                test_panic();

        struct message *msg = (struct message *) data;
        u32 *expected_num = test_get_ctx(drv);

        if (msg->num != *expected_num)
                test_fail();

        *expected_num += 1;
        if (*expected_num == MESSAGES) {
                free(expected_num);
                test_complete(drv);
        }
}


void bob_ack(const u64 ack, void *drv)
{
        struct bob_ctx *ctx = test_get_ctx(drv);
        if (ack != ctx->expected_ack)
                test_fail();

        ctx->expected_ack += 1;
        if (ctx->expected_ack == MESSAGES) {
                free(ctx);
                test_complete(drv);
        }
}
