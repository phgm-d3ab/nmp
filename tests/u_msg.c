#include "nmp.c"
#include "test_drv.h"


bool reserved_bits(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[16];

        } msg = {0};

        msg.header.sequence = u16le_set(1);

        for (u32 i = 0; i < 3; i++) {
                /* msg len 1 plus one of the reserved bits set */
                msg.header.len = u16le_set(1 | (1u << (12 + i)));

                i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));
                if (res != -1)
                        return false;
        }

        return true;
}


bool noack(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[16];

        } msg = {0};

        msg.header.len = u16le_set(1 | MSG_NOACK);
        i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));

        return (res == (MSG_WINDOW + 1));
}


bool multiple_noacks(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[32];

        } msg = {0};

        const u8 msg_payload[4] = {0};

        msg_assemble_noack((struct msg_header *) msg.bytes,
                           msg_payload, sizeof(msg_payload));

        /* this message should be ignored */
        msg_assemble_noack((struct msg_header *) (msg.bytes + 8),
                           msg_payload, sizeof(msg_payload));


        i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));

        return (res == (MSG_WINDOW + 1));
}


bool mix_reg_noack(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[32];

        } msg = {0};

        const u8 msg_payload[4] = {0};

        msg.header.sequence = u16le_set(1);
        msg.header.len = u16le_set(sizeof(msg_payload));

        msg_assemble_noack((struct msg_header *) (msg.bytes + 8),
                           msg_payload, sizeof(msg_payload));


        i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));
        return (res == -1);
}


bool msg_too_large(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[MSG_MAX_PAYLOAD];

        } msg = {0};

        msg.header.sequence = u16le_set(1);
        msg.header.len = u16le_set(MSG_MAX_MSGLEN + 10);

        i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));

        return (res == -1);
}


bool buf_overrun(struct msg_cbs *cbs, struct msg_state *ctx)
{
        u8 msg[32] = {0};
        struct msg_header *m1 = (struct msg_header *) (msg);
        struct msg_header *m2 = (struct msg_header *) (msg + 8);

        *m1 = (struct msg_header) {
                .sequence = u16le_set(1),
                .len = u16le_set(4),
        };

        *m2 = (struct msg_header) {
                .sequence = u16le_set(2),
                .len = u16le_set(40),
        };

        i32 res = msg_read(cbs, ctx, msg, sizeof(msg));

        return (res == -1);
}


bool zerolen(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[16];

        } msg = {0};

        msg.header.sequence = u16le_set(1);
        i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));

        return (res == 0);
}


bool duplicate(struct msg_cbs *cbs, struct msg_state *ctx)
{
        u8 msg[16] = {0};
        struct msg_header *m1 = (struct msg_header *) (msg);
        struct msg_header *m2 = (struct msg_header *) (msg + 8);

        *m1 = (struct msg_header) {
                .sequence = u16le_set(1),
                .len = u16le_set(4),
        };

        *m2 = (struct msg_header) {
                .sequence = u16le_set(1),
                .len = u16le_set(4),
        };

        i32 res1 = msg_read(cbs, ctx, msg, sizeof(msg));
        i32 res2 = msg_read(cbs, ctx, msg, sizeof(msg));

        return (res1 == 1 && res2 == 0);
}


bool match_single(struct msg_cbs *cbs, struct msg_state *ctx)
{
        u8 msg[MSG_MAX_PAYLOAD] = {0};
        struct msg_header *header = (struct msg_header *) msg;

        *header = (struct msg_header) {
                .sequence = u16le_set(1),
                .len = u16le_set(MSG_MAX_MSGLEN),
        };

        i32 res = msg_read(cbs, ctx, msg, sizeof(msg));
        return (res == 1);
}


bool match_multi(struct msg_cbs *cbs, struct msg_state *ctx)
{
        u8 msg[MSG_MAX_PAYLOAD] = {0};
        struct msg_header *m1 = (struct msg_header *) msg;
        struct msg_header *m2 = (struct msg_header *) (msg + 8);
        struct msg_header *m3 = (struct msg_header *) (msg + 16);

        *m1 = (struct msg_header) {
                .sequence = u16le_set(1),
                .len = u16le_set(4),
        };

        *m2 = (struct msg_header) {
                .sequence = u16le_set(2),
                .len = u16le_set(4),
        };

        *m3 = (struct msg_header) {
                .sequence = u16le_set(3),
                .len = u16le_set(MSG_MAX_MSGLEN - 16),
        };

        i32 res = msg_read(cbs, ctx, msg, sizeof(msg));
        return (res == 3);
}


bool seq_low(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[16];

        } msg = {0};

        msg.header.sequence = u16le_set(0xffff - 10);
        msg.header.len = u16le_set(1);

        i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));

        return (res == 0);
}


bool seq_low2(struct msg_cbs *cbs, struct msg_state *ctx)
{

        u8 msg[MSG_MAX_PAYLOAD] = {0};
        struct msg_header *m1 = (struct msg_header *) msg;
        struct msg_header *m2 = (struct msg_header *) (msg + 8);
        struct msg_header *m3 = (struct msg_header *) (msg + 16);

        *m1 = (struct msg_header) {
                .sequence = u16le_set(1),
                .len = u16le_set(4),
        };

        *m2 = (struct msg_header) {
                .sequence = u16le_set(0xffff - 5),
                .len = u16le_set(4),
        };

        *m3 = (struct msg_header) {
                .sequence = u16le_set(3),
                .len = u16le_set(MSG_MAX_MSGLEN - 16),
        };

        i32 res = msg_read(cbs, ctx, msg, sizeof(msg));
        return (res == 2);
}


bool seq_high(struct msg_cbs *cbs, struct msg_state *ctx)
{
        union {
                struct msg_header header;
                u8 bytes[16];

        } msg = {0};

        msg.header.sequence = u16le_set(MSG_WINDOW + 1);
        msg.header.len = u16le_set(1);

        i32 res = msg_read(cbs, ctx, msg.bytes, sizeof(msg));

        return (res == -1);
}


bool ack_first_bit(struct msg_cbs *cbs, struct msg_state *ctx)
{
        UNUSED(cbs);
        ctx->tx_sent = 1;

        struct msg_ack ack = {
                .ack = u16le_set(1),
                .pad = {0, 0, 0},
                .ack_mask = u64le_set(0),
        };

        i32 res = msg_ack_read(ctx, &ack);

        return (res == -1);
}


int main(void)
{
        bool (*test[])(struct msg_cbs *, struct msg_state *) = {
                reserved_bits,
                noack,
                multiple_noacks,
                mix_reg_noack,
                msg_too_large,
                buf_overrun,
                zerolen,
                duplicate,
                match_single,
                match_multi,
                seq_low,
                seq_low2,
                seq_high,
                ack_first_bit,
        };

        struct msg_cbs cbs = {0};
        int tests_num = sizeof(test) / sizeof(*test);

        for (int i = 0; i < tests_num; i++) {
                struct msg_state *ctx = malloc(sizeof(struct msg_state));
                if (!ctx)
                        test_panic();

                memset(ctx, 0, sizeof(struct msg_state));
                if (!test[i](&cbs, ctx)) {
                        printf("[%s] failed at index %i\n",
                               TEST_FILE, i);
                        return EXIT_FAILURE;
                }

                free(ctx);
        }
}
