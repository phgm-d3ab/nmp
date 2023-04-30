#include "test_drv.h"

#include <string.h>


enum {
        PACKETS = 7,
};


struct alice_ctx {
        u32 id;
        u8 map[PACKETS];
};


void test_run(const int soc,
              const struct test_peer *alice,
              const struct test_peer *bob)
{
        union nmp_sa dest[2] = {
                [false] = alice->addr,
                [true] = bob->addr,
        };

        bool alice_drops[PACKETS] = {0};

        alice_drops[3] = true;
        alice_drops[4] = true;


        for (u32 i = 0; i < PACKETS; i++) {
                u8 buf[1500] = {0};
                union nmp_sa addr = {0};
                socklen_t addrlen = sizeof(addr);

                isize res = recvfrom(soc, buf, sizeof(buf),
                                     0, &addr.sa, &addrlen);
                if (res == -1)
                        test_panic();

                bool dest_idx = (memcmp(&addr.sa, &dest[0].sa,
                                        sizeof(union nmp_sa)) == 0);
                if (dest_idx && alice_drops[i])
                        continue;

                res = sendto(soc, buf, res, 0,
                             &dest[dest_idx].sa, addrlen);
                if (res == -1)
                        test_panic();
        }
}


void alice_init(struct test_drv *drv, struct test_peer *bob,
                const union nmp_sa *ctl)
{
        struct alice_ctx *ctx = malloc(sizeof(struct alice_ctx));
        if (!ctx)
                test_panic();

        struct nmp_rq_connect c = {0};
        memcpy(c.pubkey, bob->pubkey, NMP_KEYLEN);
        c.addr = *ctl;
        c.context_ptr = drv;

        struct nmp_rq rq = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &c,
        };

        nmp_submit(test_instance(drv), &rq, 1);

        u8 empty[NMP_PAYLOAD_MAX] = {0};
        struct nmp_rq msg[2] = {0};

        msg[0] = (struct nmp_rq) {
                .op = NMP_OP_SEND,
                .len = NMP_PAYLOAD_MAX,
                .session_id = c.id,
                .user_data = 1,
                .entry_arg = empty,
        };

        msg[1] = (struct nmp_rq) {
                .op = NMP_OP_SEND,
                .len = 16,
                .session_id = c.id,
                .user_data = 2,
                .entry_arg = empty,
        };

        nmp_submit(test_instance(drv), msg, 2);
        test_set_ctx(drv, ctx);

        ctx->id = c.id;
        ctx->map[0] = 0;
        ctx->map[1] = 0;
        ctx->map[2] = 0;
}


int alice_status(enum nmp_status s,
                 const union nmp_cb_status *d, void *drv)
{
        UNUSED(s);
        UNUSED(d);
        UNUSED(drv);

        return NMP_CMD_ACCEPT;
}


int bob_status(enum nmp_status status,
               const union nmp_cb_status *cb, void *drv)
{
        UNUSED(status);
        UNUSED(cb);

        test_complete(drv);
        return NMP_STATUS_ZERO;
}


void alice_ack(const u64 user_data, void *drv)
{
        struct alice_ctx *ctx = test_get_ctx(drv);
        if (user_data == 1) {
                u8 empty[16] = {0};
                struct nmp_rq msg = {
                        .op = NMP_OP_SEND,
                        .len = sizeof(empty),
                        .session_id = ctx->id,
                        .user_data = 3,
                        .entry_arg = empty,
                };

                nmp_submit(test_instance(drv), &msg, 1);
        }

        ctx->map[user_data] = 1;
        if (user_data != 3)
                return;

        for (u32 i = 1; i <= 3; i++) {
                if (ctx->map[i] == 0)
                        test_fail();
        }

        test_complete(drv);
        free(ctx);
}
