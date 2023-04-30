#include "test_drv.h"

#include <string.h>
#include <unistd.h>
#include <pthread.h>


enum {
        WORKERS = 32,
        PACKETS = 5000,
};


void *worker(void *ptr)
{
        union nmp_sa *addr = ptr;
        const int soc = socket(addr->sa.sa_family, SOCK_DGRAM, 0);
        if (soc == -1)
                test_panic();

        u8 buf[1400] = {0};
        random_bytes(buf, sizeof(buf));

        for (u32 i = 0; i < PACKETS; i++) {
                isize res = sendto(soc, buf, sizeof(buf),
                                   0, &addr->sa, sizeof(union nmp_sa));
                if (res == -1)
                        test_panic();
        }

        close(soc);
        return NULL;
}


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


        pthread_t tid[WORKERS] = {0};
        for (u32 i = 0; i < WORKERS; i++) {
                if (pthread_create(&tid[i], NULL,
                                   worker, &bob->addr))
                        test_panic();
        }

        for (u32 i = 0; i < WORKERS; i++)
                pthread_join(tid[i], NULL);


        nmp_submit(test_instance(drv), &rq, 1);
}


int alice_status(enum nmp_status status,
                 const union nmp_cb_status *cb, void *drv)
{
        UNUSED(cb);
        if (status != NMP_SESSION_RESPONSE)
                test_fail();

        test_complete(drv);
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
