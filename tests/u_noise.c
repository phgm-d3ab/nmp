#include "nmp.c"
#include "test_drv.h"
#include <stdbool.h>


#define get_random(ptr_, len_) do { \
        if (getrandom(ptr_, len_, 0) != len_) test_panic(); } while (0)


struct aead_ctx {
        struct chacha20poly1305_ctx cipher;
        u64 nonce;

        u8 aad[16];
        u8 plaintext[256];
        u8 ciphertext[256];

        u8 mac[CHACHA20POLY1305_TAGLEN];
};


static void flip_random_bit(u8 *arr, const u32 arrlen)
{
        u32 idx = 0;
        get_random(&idx, sizeof(u32));

        arr[(idx / 8) % arrlen] ^= (1u << (idx & 7));
}


bool aead(struct aead_ctx *ctx)
{
        UNUSED(ctx);
        return false;
}


bool flip_aad(struct aead_ctx *ctx)
{
        flip_random_bit(ctx->aad, sizeof(ctx->aad));
        return true;
}


bool flip_ciphertext(struct aead_ctx *ctx)
{
        flip_random_bit(ctx->ciphertext, sizeof(ctx->ciphertext));
        return true;
}


bool flip_tag(struct aead_ctx *ctx)
{
        flip_random_bit(ctx->mac, sizeof(ctx->mac));
        return true;
}


bool flip_nonce(struct aead_ctx *ctx)
{
        ctx->nonce += 1;
        return true;
}


int main(void)
{
        bool (*aead_test[])(struct aead_ctx *) = {
                aead,
                flip_aad,
                flip_ciphertext,
                flip_tag,
                flip_nonce,
        };

        for (u32 i = 0; i < sizeof(aead_test) / sizeof(*aead_test); i++) {
                struct aead_ctx ctx = {0};
                u8 key[CHACHA20POLY1305_KEYLEN] = {0};

                get_random(key, sizeof(key));
                if (chacha20poly1305_init(&ctx.cipher, key)) {
                        printf("[aead] failed to initialize cipher (%u)\n", i);
                        return EXIT_FAILURE;
                }

                get_random(&ctx.nonce, sizeof(ctx.nonce));
                get_random(ctx.aad, sizeof(ctx.aad));
                get_random(ctx.plaintext, sizeof(ctx.plaintext));

                if (noise_encrypt(ctx.cipher, ctx.nonce,
                                  ctx.aad, sizeof(ctx.aad),
                                  ctx.plaintext, sizeof(ctx.plaintext),
                                  ctx.ciphertext, ctx.mac)) {
                        printf("[aead] noise_encrypt() %u\n", i);
                        return EXIT_FAILURE;
                }

                bool should_fail = aead_test[i](&ctx);
                u8 deciphered_plaintext[sizeof(ctx.ciphertext)];

                i32 res = noise_decrypt(ctx.cipher, ctx.nonce,
                                        ctx.aad, sizeof(ctx.aad),
                                        ctx.ciphertext, sizeof(ctx.ciphertext),
                                        ctx.mac, deciphered_plaintext);
                switch (res) {
                case 0:
                        if (should_fail) {
                                printf("[aead] %u failed\n", i);
                                return EXIT_FAILURE;
                        }

                        if (memcmp(deciphered_plaintext, ctx.plaintext,
                                   sizeof(ctx.plaintext)) != 0) {
                                printf("[aead] cmp failed %u\n", i);
                                return EXIT_FAILURE;
                        }

                        break;

                case 1:
                        if (!should_fail) {
                                printf("[aead] %u failed\n", i);
                                return EXIT_FAILURE;
                        }

                        break;

                default:
                        printf("[aead] %u panicked\n", i);
                        return EXIT_FAILURE;
                }

                chacha20poly1305_free(&ctx.cipher);
        }
}
