#include "test_drv.h"

#include <unistd.h>
#include <string.h>


void pkt_fwd(const int soc, union nmp_sa dest)
{
        u8 buf[1500] = {0};
        const isize amt = read(soc, buf, sizeof(buf));
        if (amt == -1)
                test_panic();

        if (sendto(soc, buf, amt, 0,
                   &dest.sa, sizeof(dest)) == -1)
                test_panic();
}


void test_run(const int soc,
              const struct test_peer *alice,
              const struct test_peer *bob)
{
        pkt_fwd(soc, bob->addr);

        u8 buf[1500] = {0};
        const isize amt = read(soc, buf, sizeof(buf));
        if (amt == -1)
                test_panic();

        const u8 save = buf[32];
        buf[32] = 0;

        if (sendto(soc, buf, amt, 0,
                   &alice->addr.sa, sizeof(alice->addr)) == -1)
                test_panic();

        buf[32] = save;

        if (sendto(soc, buf, amt, 0,
                   &alice->addr.sa, sizeof(alice->addr)) == -1)
                test_panic();

        pkt_fwd(soc, bob->addr);
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


int alice_status(const enum nmp_status status,
                 const union nmp_cb_status *cb, void *drv)
{
        UNUSED(status);
        UNUSED(cb);

        test_complete(drv);
        return NMP_CMD_ACCEPT;
}


int bob_status(const enum nmp_status status,
               const union nmp_cb_status *cb, void *drv)
{
        UNUSED(status);
        UNUSED(cb);
        test_complete(drv);
        return NMP_STATUS_ZERO;
}

