#include "test_drv.h"

#include <string.h>
#include <assert.h>


struct bob_ctx {
        u32 sum;
        u32 session_id;
};


void alice_init(struct test_drv *drv, struct test_peer *bob,
                const union nmp_sa *ctl)
{
        UNUSED(ctl);

        struct nmp_rq_connect c = {0};
        memcpy(c.pubkey, bob->pubkey, NMP_KEYLEN);
        c.addr = bob->addr;
        c.context_ptr = drv;

        struct nmp_rq rq = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &c,
        };

        nmp_submit(test_instance(drv), &rq, 1);
}


int alice_status(enum nmp_status status,
                 const union nmp_cb_status *cb, void *drv)
{
        UNUSED(cb);
        UNUSED(drv);

        if (status != NMP_SESSION_RESPONSE)
                test_panic();

        test_complete(drv);
        return NMP_CMD_ACCEPT;
}


int bob_request(struct nmp_rq_connect *request, const uint8_t *p, void *drv)
{
        UNUSED(p);

        struct bob_ctx *ctx = malloc(sizeof(struct bob_ctx));
        if (!ctx)
                test_panic();

        test_set_ctx(drv, ctx);
        ctx->session_id = request->id;
        ctx->sum = 0;
        request->context_ptr = drv;

        return NMP_CMD_ACCEPT;
}


static void bob_submit(nmp_t *nmp, const u32 id)
{
        static_assert(NMP_QUEUELEN == 256, "");

        u8 empty[NMP_PAYLOAD_MAX] = {0};
        u8 len_rnd[NMP_QUEUELEN] = {0};
        random_bytes(len_rnd, sizeof(len_rnd));

        for (u32 i = 0; i < NMP_QUEUELEN;) {
                struct nmp_rq rq[NMP_RQ_BATCH] = {0};
                u32 j = 0;

                for (; j < NMP_RQ_BATCH; j++) {
                        if (i + j >= NMP_QUEUELEN)
                                break;

                        rq[j] = (struct nmp_rq) {
                                .op = NMP_OP_SEND,
                                .len = (500 + len_rnd[i]),
                                .session_id = id,
                                .user_data = 1,
                                .entry_arg = empty,
                        };

                        i += 1;
                }

                nmp_submit(nmp, rq, j);
        }

        /* because this is on the same thread as nmp_run(),
         * (NMP_QUEUELEN + 1)th send request is guaranteed
         * to overflow the queue */
        struct nmp_rq overflowed = {
                .op = NMP_OP_SEND,
                .len = 1000,
                .session_id = id,
                .user_data = (NMP_QUEUELEN + 1),
                .entry_arg = empty,
        };

        nmp_submit(nmp, &overflowed, 1);
}


int bob_status(enum nmp_status status,
               const union nmp_cb_status *cb, void *drv)
{
        struct bob_ctx *ctx = test_get_ctx(drv);

        switch (status) {
        case NMP_SESSION_INCOMING:
                bob_submit(test_instance(drv), ctx->session_id);
                break;

        case NMP_ERR_QUEUE:
                if (!cb || cb->user_data != (NMP_QUEUELEN + 1))
                        test_fail();

                break;

        default:
                test_panic();
        }

        return NMP_STATUS_ZERO;
}


void bob_ack(const u64 ack, void *drv)
{
        if (ack == (NMP_QUEUELEN + 1))
                test_fail();

        struct bob_ctx *ctx = test_get_ctx(drv);

        ctx->sum += (u32) ack;
        if (ctx->sum == NMP_QUEUELEN)
                test_complete(drv);
}
