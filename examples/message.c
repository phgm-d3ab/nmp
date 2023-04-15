#include "nmp.h"
#include "common.h"

#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>

#include <getopt.h>


enum msg_status {
        MSG_IDLE,
        MSG_ESTAB,
};


struct msg_state {
        pthread_mutex_t lock;
        enum msg_status status;
        u32 id;
        u64 counter;

        nmp_t *nmp;
};


struct msg_state *state_lock(void *ptr)
{
        struct msg_state *ctx = ptr;
        if (pthread_mutex_lock(&ctx->lock)) {
                printf("failed to lock\n");
                abort();
        }

        return ctx;
}

void state_unlock(struct msg_state *ctx)
{
        if (pthread_mutex_unlock(&ctx->lock)) {
                printf("failed to release\n");
                abort();
        }
}


i32 handle_request(struct nmp_rq_connect *req,
                   const u8 *_payload, void *ctx_ptr)
{
        (void) (_payload);
        struct msg_state *ctx = state_lock(ctx_ptr);

        if (ctx->status == MSG_ESTAB) {
                state_unlock(ctx);
                return NMP_CMD_DROP;
        }

        ctx->status = MSG_ESTAB;
        ctx->id = req->id;
        req->context_ptr = ctx;

        char addr_str[128] = {0};
        addr_sa2str(&req->addr, addr_str, sizeof(addr_str));

        char info_msg[512] = {0};
        char key_row1[56] = {0};
        char key_row2[56] = {0};

        str_bin2hex(req->pubkey, 28, key_row1);
        str_bin2hex(req->pubkey + 28, 28, key_row2);

        snprintf(info_msg, sizeof(info_msg),
                          "[peer] session %x connecting from %s\n%s\n%s\n",
                          req->id, addr_str, key_row1, key_row2);

        printf("%s", info_msg);

        state_unlock(ctx);
        return NMP_CMD_ACCEPT;
}


void handle_data(const u8 *data, const u32 len, void *_ctx)
{
        (void) (_ctx);
        printf("[peer msg] %.*s\n", len, data);
}


void handle_ack(const u64 counter, void *_ctx)
{
        (void) (_ctx);
        printf("[msg] ack %zu\n", counter);
}


i32 handle_status(const enum nmp_status status,
                  const union nmp_cb_status *_cb,
                  void *ctx_ptr)
{
        (void) (_cb);
        enum nmp_status res = NMP_STATUS_ZERO;
        struct msg_state *ctx = state_lock(ctx_ptr);

        switch (status) {
        case NMP_SESSION_DISCONNECTED:
                printf("[peer] disconnected (%xu); acked %zu message(s)\n",
                       ctx->id, ctx->counter);

                ctx->status = MSG_IDLE;
                ctx->counter = 0;
                break;

        case NMP_SESSION_RESPONSE:
                printf("[peer] connection established (%xu)\n", ctx->id);
                res = NMP_CMD_ACCEPT;
                break;

        case NMP_SESSION_INCOMING:
                printf("[peer] connected (%xu)\n", ctx->id);
                break;

        default:
                printf("[warn] unhandled status %i\n", status);
                break;
        }

        state_unlock(ctx);
        return res;
}


void *worker(void *ctx_ptr)
{
        i32 res = 0;
        struct msg_state *ctx = ctx_ptr;

        res = nmp_run(ctx->nmp, 0);
        printf("thread exited (%i)\n", res);

        return NULL;
}


i32 run(struct msg_state *ctx)
{
        for (;;) {
                char buf[NMP_PAYLOAD_MAX + 8] = {0};

                const isize amt = read(STDIN_FILENO, buf, NMP_PAYLOAD_MAX);
                if (amt == -1)
                        return 1;

                if (amt < 2)
                        continue;

                state_lock(ctx);
                if (ctx->status == MSG_IDLE) {
                        printf("[msg] not connected. skipping message\n");
                        state_unlock(ctx);
                        continue;
                }

                ctx->counter += 1;
                struct nmp_rq msg = {
                        .op = NMP_OP_SEND,
                        .len = (u16) (amt - 1),
                        .session_id = ctx->id,
                        .user_data = ctx->counter,
                        .entry_arg = buf,
                };

                if (nmp_submit(ctx->nmp, &msg, 1)) {
                        printf("[msg] failed to send msg\n");
                        return 1;
                }

                printf("[msg] sending %zu\n", ctx->counter);
                state_unlock(ctx);
        }

        return 0;
}


int main(int argc, char **argv)
{
        i32 arg = 0;
        i32 arg_idx = -1;
        const char *args[] = {
                NULL, /* -k */
                NULL, /* -b */
                NULL, /* -c */
        };

        while ((arg = getopt(argc, argv, "k:b:c:")) != -1) {
                switch (arg) {
                case 'k':
                        arg_idx = 0;
                        break;

                case 'b':
                        arg_idx = 1;
                        break;

                case 'c':
                        arg_idx = 2;
                        break;

                case '?':
                default:
                        return 1;
                }

                if (args[arg_idx])
                        return 1;

                args[arg_idx] = optarg;
        }

        if (optind != argc)
                return 1;


        i32 res = 0;
        struct msg_state ctx = {0};
        struct nmp_conf conf = {0};

        pthread_mutex_init(&ctx.lock, NULL);

        conf.request_ctx = &ctx;
        conf.request_cb = handle_request;
        conf.data_cb = handle_data;
        conf.ack_cb = handle_ack;
        conf.status_cb = handle_status;

        res = args[0] ? key_load(args[0], conf.key)
                      : key_generate(conf.key);
        if (res) {
                printf("failed to get key (%s)\n",
                       strerror(errno));
                return 1;
        }

        if (args[1]) {
                if (addr_str2sa(args[1], &conf.addr)) {
                        printf("failed to read '%s'\n", args[1]);
                        return 1;
                }
        }

        ctx.nmp = nmp_new(&conf);
        if (ctx.nmp == NULL) {
                printf("failed to create instance (%i)\n",
                       conf.err);
                return 1;
        }

        conf_info(&conf);

        if (args[2]) {
                struct nmp_rq_connect peer = {0};
                if (addr_read_full(args[2], &peer.addr, peer.pubkey)) {
                        printf("failed to read address '%s'\n", args[2]);
                        return 1;
                }

                /* no session specific states in this example */
                peer.context_ptr = &ctx;

                struct nmp_rq rq = {
                        .op = NMP_OP_CONNECT,
                        .entry_arg = &peer,
                };

                if (nmp_submit(ctx.nmp, &rq, 1)) {
                        printf("failed to submit request\n");
                        return 1;
                }

                ctx.id = peer.id;
                ctx.status = MSG_ESTAB;
                printf("[peer] %x connecting..\n", ctx.id);
        }


        pthread_t t = {0};
        if (pthread_create(&t, NULL, worker, &ctx)) {
                printf("failed to spawn thread\n");
                return 1;
        }

        return run(&ctx);
}
