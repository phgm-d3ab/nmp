#include "test_drv.h"

#include <string.h>


static const char *msg = "a long enough hello world message";


void test_run(const int soc,
              const struct test_peer *alice,
              const struct test_peer *bob)
{
        union nmp_sa ret_addr[2] = {
                [false] = alice->addr,
                [true] = bob->addr,
        };

        isize pkt_len[4] = {0};

        for (u32 i = 0; i < 4; i++) {
                u8 buf[1500] = {0};
                union nmp_sa addr = {0};
                socklen_t addrlen = sizeof(addr);

                pkt_len[i] = recvfrom(soc, buf, sizeof(buf),
                               0, &addr.sa, &addrlen);
                if (pkt_len[i] == -1)
                        test_panic();


                bool ret_dir = (memcmp(&addr.sa, &ret_addr[0].sa,
                                      sizeof(union nmp_sa)) == 0);

                sendto(soc, buf, pkt_len[i], 0,
                       &ret_addr[ret_dir].sa, addrlen);
        }

        if (pkt_len[2] != 80)
                test_fail();
}


void alice_init(struct test_drv *drv, struct test_peer *bob,
                const union nmp_sa *control)
{
        struct nmp_rq_connect c = {0};
        memcpy(c.pubkey, bob->pubkey, NMP_KEYLEN);
        c.addr = *control;
        c.context_ptr = drv;

        struct nmp_rq rq_connect = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &c,
        };

        nmp_submit(test_instance(drv), &rq_connect, 1);


        struct nmp_rq early_msg = {
                .op = NMP_OP_SEND,
                .len = (u16) strlen(msg),
                .session_id = c.id,
                .user_data = 1,
                .entry_arg = (void *) msg,
        };

        nmp_submit(test_instance(drv), &early_msg, 1);
}


int alice_status(enum nmp_status s, const union nmp_cb_status *d, void *c)
{
        UNUSED(s);
        UNUSED(d);
        UNUSED(c);

        return NMP_CMD_ACCEPT;
}


void bob_data(const u8 *data, const u16 len, void *drv)
{
        if (len != (u16) strlen(msg))
                test_fail();

        if (memcmp(data, msg, len) != 0)
                test_fail();

        test_complete(drv);
}


void alice_ack(const u64 ack, void *drv)
{
        if (ack != 1)
                test_fail();

        test_complete(drv);
}
