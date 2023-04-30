#include "test_drv.h"

#include <string.h>


struct send_ctx {
        struct test_drv *drv;
        u64 user_data;
        u32 session;
};


void alice_init(struct test_drv *drv, struct test_peer *bob,
                const union nmp_sa *control)
{
        UNUSED(control);
        struct send_ctx *ctx = malloc(sizeof(struct send_ctx));
        ctx->drv = drv;

        random_bytes(&ctx->user_data, sizeof(u64));

        struct nmp_rq_connect c = {0};
        memcpy(c.pubkey, bob->pubkey, NMP_KEYLEN);
        c.addr = bob->addr;
        c.context_ptr = ctx;

        struct nmp_rq rq = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &c,
        };

        nmp_submit(test_instance(drv), &rq, 1);
        ctx->session = c.id;
}


int alice_status(enum nmp_status status, const union nmp_cb_status *cb, void *ptr)
{
        UNUSED(cb);
        if (status != NMP_SESSION_RESPONSE)
                test_panic();

        char buf[16] = {0};
        const i32 amt = sprintf(buf, "hello world");

        struct send_ctx *ctx = ptr;
        struct nmp_rq send = {
                .op = NMP_OP_SEND,
                .len = (u16) amt,
                .session_id = ctx->session,
                .user_data = ctx->user_data,
                .entry_arg = buf,
        };

        nmp_submit(test_instance(ctx->drv), &send, 1);
        return NMP_CMD_ACCEPT;
}


void bob_data(const u8 *data, const u16 len, void *drv)
{
        if (len != 11)
                test_fail();

        const char *control = "hello world";
        if (memcmp(data, control, len) != 0)
                test_fail();

        test_complete(drv);
}


void alice_ack(const u64 user_data, void *ptr)
{
        struct send_ctx *ctx = ptr;
        if (user_data != ctx->user_data)
                test_fail();

        test_complete(ctx->drv);
}
