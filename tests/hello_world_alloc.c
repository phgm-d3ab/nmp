#include "test_drv.h"

#include <string.h>


static const char *msg = "hello world";


void alice_init(struct test_drv *drv, struct test_peer *bob,
                const union nmp_sa *control)
{
        UNUSED(control);

        u32 *ctx = malloc(sizeof(u32));
        if (!ctx)
                test_panic();

        struct nmp_rq_connect c = {0};
        memcpy(c.pubkey, bob->pubkey, NMP_KEYLEN);
        c.addr = bob->addr;
        c.context_ptr = drv;

        struct nmp_rq rq = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &c,
        };

        nmp_submit(test_instance(drv), &rq, 1);

        *ctx = c.id;
        test_set_ctx(drv, ctx);
}


int alice_status(enum nmp_status status, const union nmp_cb_status *cb, void *drv)
{
        UNUSED(cb);

        if (status != NMP_SESSION_RESPONSE)
                test_panic();

        struct nmp_rq send = {
                .op = NMP_OP_SEND,
                .msg_flags = NMP_F_MSG_NOALLOC,
                .len = 11,
                .session_id = *(u32 *) test_get_ctx(drv),
                .entry_arg = (void *) msg,
        };

        nmp_submit(test_instance(drv), &send, 1);
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


void alice_ack(const u64 ack, void *drv)
{
        UNUSED(ack);
        test_complete(drv);
}
