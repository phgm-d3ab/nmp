#include "test_drv.h"

#include <string.h>
#include <pthread.h>
#include <errno.h>

#include <sys/random.h>
#include <assert.h>


bool __random_bytes(void *ptr, const ssize_t len)
{
        assert(len > 0);
        return (getrandom(ptr, len, 0) != len);
}


static union nmp_sa addr_localhost(void)
{
        struct sockaddr_in temp = {0};
        temp.sin_family = AF_INET;
        temp.sin_port = 0;

        if (!inet_aton("127.0.0.1", &temp.sin_addr))
                test_panic();

        return (union nmp_sa) {.ip4 = temp,};
}


extern int alice_request(struct nmp_rq_connect *, const uint8_t *, void *);
extern void alice_data(const u8 *, u32, void *);
extern void alice_noack(const u8 *, u32, void *);
extern void alice_ack(u64, void *);
extern void alice_stats(u64, u64, void *);
extern int alice_status(enum nmp_status, const union nmp_cb_status *, void *);

static const struct nmp_conf alice_conf = {
        .err = 0,
        .addr = {{0}},
        .pubkey = {0},
        .key = {0},
        .options = 0,
        .request_ctx = 0,
        .request_cb = alice_request,
        .data_cb = alice_data,
        .data_noack_cb = alice_noack,
        .ack_cb = alice_ack,
        .stats_cb = alice_stats,
        .status_cb = alice_status,
};


extern int bob_request(struct nmp_rq_connect *, const uint8_t *, void *);
extern void bob_data(const u8 *, u32, void *);
extern void bob_noack(const u8 *, u32, void *);
extern void bob_ack(u64, void *);
extern void bob_stats(u64, u64, void *);
extern int bob_status(enum nmp_status, const union nmp_cb_status *, void *);

static const struct nmp_conf bob_conf = {
        .err = 0,
        .addr = {{0}},
        .pubkey = {0},
        .key = {0},
        .options = 0,
        .request_ctx = 0,
        .request_cb = bob_request,
        .data_cb = bob_data,
        .data_noack_cb = bob_noack,
        .ack_cb = bob_ack,
        .stats_cb = bob_stats,
        .status_cb = bob_status,
};


enum {
        TEST_WORKERS = 2,
};


struct test_sync {
        pthread_t tid[TEST_WORKERS];
        pthread_barrier_t barrier;
        pthread_cond_t cond;
        pthread_mutex_t comp_lk;
        u32 comp_cnt;
        nmp_t *instance[TEST_WORKERS];
};


struct test_drv {
        void *tctx;
        nmp_t *nmp;
        struct test_sync *sync;
};


void test_set_ctx(struct test_drv *drv, void *ctx)
{
        drv->tctx = ctx;
}


void *test_get_ctx(struct test_drv *drv)
{
        return drv->tctx;
}


nmp_t *test_instance(struct test_drv *drv)
{
        return drv->nmp;
}


void test_complete(struct test_drv *drv)
{
        struct test_sync *sync = drv->sync;
        pthread_mutex_lock(&sync->comp_lk);

        sync->instance[sync->comp_cnt] = drv->nmp;
        sync->comp_cnt += 1;

        if (sync->comp_cnt == TEST_WORKERS)
                pthread_cond_signal(&sync->cond);

        pthread_mutex_unlock(&sync->comp_lk);
}


void __test_fail(const char *file)
{
        printf("%s [FAIL]\n", file);

        /* obviously we don't care of any implications here */
        _Exit(EXIT_FAILURE);
}


struct peer_args {
        struct test_sync *sync;
        struct test_peer *info;
        struct test_peer *info_other;
        const union nmp_sa *control;
        const struct nmp_conf *conf_base;
        u32 tick_interval;
        void (*peer_init)(struct test_drv *,
                          struct test_peer *,
                          const union nmp_sa *);
};


void *peer_worker(void *args_ptr)
{
        struct peer_args *args = args_ptr;
        struct nmp_conf cfg = *args->conf_base;
        struct test_drv drv = {0};

        if (getrandom(cfg.key, NMP_KEYLEN, 0) != NMP_KEYLEN)
                test_panic();

        cfg.addr = addr_localhost();
        cfg.request_ctx = &drv;

        drv.sync = args->sync;
        drv.nmp = nmp_new(&cfg);
        if (cfg.err)
                test_panic();

        memcpy(args->info->pubkey, cfg.pubkey, NMP_KEYLEN);
        args->info->addr = cfg.addr;

        pthread_barrier_wait(&args->sync->barrier);
        args->peer_init(&drv, args->info_other, args->control);

        for (;;) {
                i32 res = nmp_run(drv.nmp, args->tick_interval);
                switch (res) {
                case 0:
                        continue;

                case NMP_STATUS_LAST:
                        pthread_exit(NULL);

                default:
                        printf("instance exited with error (%i)", res);
                        _Exit(1);
                }
        }
}


int main(void)
{
        union nmp_sa ctl_sa = addr_localhost();
        const int ctl_soc = socket(AF_INET, SOCK_DGRAM, 0);
        if (ctl_soc == -1)
                test_panic();

        socklen_t ctl_sz = sizeof(ctl_sa);
        if (bind(ctl_soc, &ctl_sa.sa, ctl_sz))
                test_panic();

        if (getsockname(ctl_soc, &ctl_sa.sa, &ctl_sz))
                test_panic();


        struct test_sync sync = {
                .tid = {0},
                .barrier = {{0}},
                .cond = PTHREAD_COND_INITIALIZER,
                .comp_lk = PTHREAD_MUTEX_INITIALIZER,
                .comp_cnt = 0,
        };

        if (pthread_barrier_init(&sync.barrier, NULL, 3))
                test_panic();

        struct test_peer alice = {0};
        struct test_peer bob = {0};

        struct peer_args args[TEST_WORKERS] = {
                {
                        .sync = &sync,
                        .info = &alice,
                        .info_other = &bob,
                        .control = &ctl_sa,
                        .conf_base = &alice_conf,
                        .tick_interval= 0,
                        .peer_init = alice_init,
                },

                {
                        .sync = &sync,
                        .info = &bob,
                        .info_other = &alice,
                        .control = &ctl_sa,
                        .conf_base = &bob_conf,
                        .tick_interval = 0,
                        .peer_init = bob_init,
                },
        };


        for (u32 i = 0; i < TEST_WORKERS; i++) {
                if (pthread_create(&sync.tid[i], NULL,
                                   peer_worker, &args[i]))
                        test_panic();
        }

        pthread_barrier_wait(&sync.barrier);
        test_run(ctl_soc, &alice, &bob);

        /* wait till threads post completions */
        pthread_mutex_lock(&sync.comp_lk);
        while (sync.comp_cnt != TEST_WORKERS) {
                struct timespec ts = {0};
                clock_gettime(CLOCK_REALTIME, &ts);

                ts.tv_sec += 5;
                i32 res = pthread_cond_timedwait(&sync.cond, &sync.comp_lk, &ts);
                switch (res) {
                case 0:
                        continue;

                case ETIMEDOUT:
                        printf("test timed out\n");
                        return EXIT_FAILURE;

                default:
                        test_panic();
                }
        }


        for (u32 i = 0; i < TEST_WORKERS; i++) {
                struct nmp_rq term = {
                        .op = NMP_OP_TERMINATE,
                };

                nmp_submit(sync.instance[i], &term, 1);
        }


        for (u32 i = 0; i < TEST_WORKERS; i++)
                pthread_join(sync.tid[i], NULL);
}
