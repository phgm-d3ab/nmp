#include "nmp.h"
#include "common.h"

#include <errno.h>
#include <string.h>

#include <getopt.h>
#include <sys/mman.h>


enum ft_status {
        FT_IDLE,
        FT_SEND,
        FT_RECV,
};


struct ft_metadata {
        usize size;
};


struct ft_state {
        nmp_t *nmp;
        int err;
        enum ft_status status;
        u32 id;

        i32 pending;
        usize offset;
        usize bytes_acked;
        struct file_mmap file;
        const char *path;
};


void ft_term(struct ft_state *ctx)
{
        struct nmp_rq term = {
                .op = NMP_OP_TERMINATE,
        };

        if (nmp_submit(ctx->nmp, &term, 1))
                abort();
}


i32 ft_send_batch(struct ft_state *ctx)
{
        i32 i = 0;
        struct nmp_rq msg[NMP_RQ_BATCH] = {0};

        for (; i < NMP_RQ_BATCH; i++) {
                if (ctx->offset == ctx->file.len)
                        break;

                const usize chunk = (ctx->offset + NMP_PAYLOAD_MAX > ctx->file.len) ?
                                    ctx->file.len - ctx->offset : NMP_PAYLOAD_MAX;

                msg[i] = (struct nmp_rq) {
                        .op = NMP_OP_SEND,
                        .msg_flags = NMP_F_MSG_NOALLOC,
                        .len = (u16) chunk,
                        .session_id = ctx->id,
                        .user_data = chunk,
                        .entry_arg = (ctx->file.ptr + ctx->offset),
                };

                ctx->offset += chunk;
        }

        if (i == 0)
                return -1;

        if (nmp_submit(ctx->nmp, msg, i))
                abort();

        return i;
}


i32 handle_request(struct nmp_rq_connect *req,
                   const u8 *payload, void *ctx_ptr)
{
        struct ft_state *ctx = ctx_ptr;
        if (ctx->status != FT_IDLE)
                return NMP_CMD_DROP;

        const usize len = ((struct ft_metadata *) payload)->size;
        if (mmap_rw(ctx->path, len, &ctx->file)) {
                ctx->err = errno;
                printf("failed to map file %s (%s)\n",
                       ctx->path, strerror(errno));

                ft_term(ctx);
                return NMP_CMD_DROP;
        }


        char bytes_str[32] = {0};
        char addr_str[128] = {0};
        char key_row1[56] = {0};
        char key_row2[56] = {0};

        str_bytes2str(len, bytes_str, sizeof(bytes_str));
        addr_sa2str(&req->addr, addr_str, sizeof(addr_str));
        str_bin2hex(req->pubkey, 28, key_row1);
        str_bin2hex(req->pubkey + 28, 28, key_row2);

        printf("[peer] session %x; receiving %s from %s\n%s\n%s\n",
               req->id, bytes_str, addr_str, key_row1, key_row2);

        ctx->status = FT_RECV;
        ctx->id = req->id;
        req->context_ptr = ctx;
        return NMP_CMD_ACCEPT;
}


void handle_data(const u8 *data, const u32 len, void *ctx_ptr)
{
        struct ft_state *ctx = ctx_ptr;
        if (ctx->offset + len > ctx->file.len) {
                struct nmp_rq drop = {
                        .op = NMP_OP_DROP,
                        .session_id = ctx->id,
                };

                nmp_submit(ctx->nmp, &drop, 1);
                printf("[ft] remote peer tries to send more data than expected\n");
                return;
        }

        memcpy(ctx->file.ptr + ctx->offset, data, len);
        ctx->offset += len;

        if (ctx->offset == ctx->file.len) {
                char bytes_str[32] = {0};
                str_bytes2str(ctx->file.len, bytes_str, sizeof(bytes_str));

                printf("[ft] received '%s' (%s)\n",
                       ctx->path, bytes_str);

                msync(ctx->file.ptr, ctx->file.len, MS_SYNC);
                ft_term(ctx);
        }
}


void handle_ack(const u64 bytes_acked, void *ctx_ptr)
{
        struct ft_state *ctx = ctx_ptr;
        const usize len = ctx->file.len;

        ctx->bytes_acked += bytes_acked;
        if (ctx->bytes_acked == len) {
                char bytes_str[32] = {0};
                str_bytes2str(len, bytes_str, sizeof(bytes_str));

                printf("[ft] sent '%s' (%s)\n",
                       ctx->path, bytes_str);
                ft_term(ctx);
                return;
        }

        if (ctx->offset == len)
                return;

        ctx->pending += 1;
        if (ctx->pending == NMP_RQ_BATCH) {
                ft_send_batch(ctx);
                ctx->pending = 0;
        }
}


i32 handle_status(const enum nmp_status status,
                  const union nmp_cb_status *_cb,
                  void *ctx_ptr)
{
        (void) (_cb);

        struct ft_state *ctx = ctx_ptr;
        enum nmp_status res = NMP_STATUS_ZERO;

        switch (status) {
        case NMP_SESSION_RESPONSE:
                res = NMP_CMD_ACCEPT;
                /* fallthrough */

        case NMP_SESSION_INCOMING:
                printf("[ft] starting\n");
                break;

        default:
                ctx->err = status;
                ft_term(ctx);
                break;
        }

        return res;
}


i32 init_send(struct ft_state *ctx, const u8 *pubkey,
              const union nmp_sa *sa)
{
        struct ft_metadata metadata = {.size = ctx->file.len};
        struct nmp_rq_connect peer = {0};

        peer.addr = *sa;
        peer.context_ptr = ctx;
        memcpy(peer.pubkey, pubkey, NMP_KEYLEN);
        memcpy(peer.init_payload, &metadata,
               sizeof(struct ft_metadata));

        struct nmp_rq rq = {
                .op = NMP_OP_CONNECT,
                .entry_arg = &peer,
        };

        if (nmp_submit(ctx->nmp, &rq, 1))
                return -1;

        ctx->id = peer.id;
        i32 chunks = 0;

        while (chunks < (NMP_QUEUELEN / 2)) {
                const i32 sent = ft_send_batch(ctx);
                if (sent < 0)
                        break;

                chunks += sent;
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
                NULL, /* -f */
                NULL, /* -a */
        };

        while ((arg = getopt(argc, argv, "k:b:f:a:")) != -1) {
                switch (arg) {
                case 'k':
                        arg_idx = 0;
                        break;

                case 'b':
                        arg_idx = 1;
                        break;

                case 'f':
                        arg_idx = 2;
                        break;

                case 'a':
                        arg_idx = 3;
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
        struct nmp_conf conf = {0};
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

        if (args[2] == NULL) {
                printf("missing file argument\n");
                return 1;
        }

        struct ft_state *ctx = malloc(sizeof(struct ft_state));
        if (ctx == NULL)
                return 1;

        memset(ctx, 0, sizeof(struct ft_state));
        if (args[3]) { /* if sender, else receiver */
                ctx->status = FT_SEND;
                conf.ack_cb = handle_ack;
        } else {
                conf.request_ctx = ctx;
                conf.request_cb = handle_request;
                conf.data_cb = handle_data;
                ctx->path = args[2];
        }

        ctx->nmp = nmp_new(&conf);
        if (ctx->nmp == NULL) {
                printf("failed to create instance (%i)\n",
                       conf.err);
                free(ctx);
                return 1;
        }

        if (ctx->status == FT_SEND) {
                res = mmap_ro(args[2], &ctx->file);
                if (res) {
                        printf("failed to open file (%s)\n",
                               strerror(errno));
                        goto out;
                }

                u8 pubkey[NMP_KEYLEN] = {0};
                union nmp_sa sa = {0};
                res = addr_read_full(args[3], &sa, pubkey);
                if (res) {
                        printf("failed to read remote address\n");
                        goto out;
                }

                res = init_send(ctx, pubkey, &sa);
                if (res)
                        goto out;

                ctx->path = args[2];
                printf("[ft] sending '%s'\n", args[2]);
        }

        conf_info(&conf);

        if (nmp_run(ctx->nmp, 0) != NMP_STATUS_LAST)
                abort();

        if (ctx->err) {
                printf("terminated with errors (%i)\n",
                       ctx->err);
        }


        out:
        {
                if (ctx->file.ptr)
                        munmap(ctx->file.ptr, ctx->file.len);

                free(ctx);
                return res;
        }
}
