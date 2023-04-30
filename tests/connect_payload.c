#include "test_drv.h"

#include <string.h>


struct connect_ctx {
        struct test_drv *drv;
        u8 payload[NMP_INITIATION_PAYLOAD];
};


void alice_init(struct test_drv *drv, struct test_peer *bob,
                const union nmp_sa *control)
{
        UNUSED(control);

        struct connect_ctx *ctx = malloc(sizeof(struct connect_ctx));
        if (!ctx)
                test_panic();

        random_bytes(ctx->payload, NMP_INITIATION_PAYLOAD);

        ctx->drv = drv;
        test_set_ctx(drv, ctx);

        struct nmp_rq_connect c = {0};

        memcpy(c.init_payload, ctx->payload, NMP_INITIATION_PAYLOAD);
        memcpy(c.pubkey, bob->pubkey, NMP_KEYLEN);
        c.addr = bob->addr;
        c.context_ptr = ctx;

        struct nmp_rq rq = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &c,
        };

        nmp_submit(test_instance(drv), &rq, 1);
}


int bob_request(struct nmp_rq_connect *request,
                const uint8_t *payload, void *drv)
{
        memcpy(request->init_payload, payload, NMP_INITIATION_PAYLOAD);
        request->context_ptr = drv;
        return NMP_CMD_ACCEPT;
}


int alice_status(enum nmp_status status,
                 const union nmp_cb_status *cb, void *ptr)
{
        if (status != NMP_SESSION_RESPONSE)
                test_fail();

        struct connect_ctx *ctx = ptr;
        if (memcmp(ctx->payload, cb->payload, NMP_INITIATION_PAYLOAD) != 0)
                test_fail();

        test_complete(ctx->drv);
        free(ctx);
        return NMP_CMD_ACCEPT;
}


int bob_status(enum nmp_status status,
               const union nmp_cb_status *cb, void *drv)
{
        UNUSED(cb);
        if (status != NMP_SESSION_INCOMING)
                test_fail();

        test_complete(drv);
        return NMP_STATUS_ZERO;
}
