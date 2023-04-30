#include "nmp.c"
#include "test_drv.h"


static u32 foo = 0;
static u8 fixed_key[SIPHASH_KEY] = {0};
static u32 fixed_ids[10] = {0};


#define init(ctx_, key_) do { \
        if (ht_init(ctx_, key_)) return false;} while (0)

#define insert(ctx_, key_, value_) do { \
        if (ht_insert(ctx_, key_, value_)) return false;} while (0)

#define remove(ctx_, key_) do { \
        if (ht_remove(ctx_, key_)) return false;} while (0)



bool generic1(void)
{
        struct hash_table ctx = {0};
        u8 key[SIPHASH_KEY] = {0};

        assert(getrandom(key, SIPHASH_KEY, 0) == SIPHASH_KEY);
        init(&ctx, key);

        for (u32 i = 0; i < 10; i++)
                insert(&ctx, i, &foo);

        for (u32 i = 0; i < 10; i++) {
                if (ht_find(&ctx, i) != &foo)
                        return false;
        }

        return true;
}

bool generic2(void)
{
        struct hash_table ctx = {0};
        u8 key[SIPHASH_KEY] = {0};

        assert(getrandom(key, SIPHASH_KEY, 0) == SIPHASH_KEY);
        init(&ctx, key);

        for (u32 i = 0; i < 10; i++)
                insert(&ctx, i, &foo);

        for (u32 i = 0; i < 10; i++)
                remove(&ctx, i);

        for (u32 i = 0; i < 10; i++) {
                if (ht_find(&ctx, i) != NULL)
                        return false;
        }

        return true;
}

bool collision(void)
{
        struct hash_table ctx = {0};
        init(&ctx, fixed_key);

        for (u32 i = 0; i < 10; i++)
                insert(&ctx, fixed_ids[i], &foo);

        for (u32 i = 0; i < 10; i++) {
                if (ht_find(&ctx, fixed_ids[i]) != &foo)
                        return false;
        }

        return true;
}


bool lazy1(void)
{
        struct hash_table ctx = {0};
        init(&ctx, fixed_key);

        insert(&ctx, fixed_ids[0], &foo);
        insert(&ctx, fixed_ids[1], &foo);
        insert(&ctx, fixed_ids[2], &foo);

        remove(&ctx, fixed_ids[1]);

        assert(ht_find(&ctx, fixed_ids[2]) == &foo);
        assert(ht_find(&ctx, fixed_ids[2]) == &foo);
        assert(ht_find(&ctx, fixed_ids[1]) == NULL);

        return true;
}


bool lazy2(void)
{
        struct hash_table ctx = {0};
        init(&ctx, fixed_key);

        insert(&ctx, fixed_ids[0], &foo);
        insert(&ctx, fixed_ids[1], &foo);
        insert(&ctx, fixed_ids[2], &foo);

        remove(&ctx, fixed_ids[1]);
        remove(&ctx, fixed_ids[2]);

        assert(ht_find(&ctx, fixed_ids[2]) == NULL);
        assert(ht_find(&ctx, fixed_ids[0]) == &foo);

        return true;
}

bool lazy3(void)
{
        struct hash_table ctx = {0};
        init(&ctx, fixed_key);

        insert(&ctx, fixed_ids[0], &foo);
        insert(&ctx, fixed_ids[1], &foo);
        insert(&ctx, fixed_ids[2], &foo);

        remove(&ctx, fixed_ids[0]);
        remove(&ctx, fixed_ids[1]);
        remove(&ctx, fixed_ids[2]);

        insert(&ctx, fixed_ids[3], &foo);
        assert(ht_find(&ctx, fixed_ids[3]) == &foo);

        return true;
}

bool lazy4(void)
{
        struct hash_table ctx = {0};
        init(&ctx, fixed_key);

        insert(&ctx, fixed_ids[0], &foo);
        insert(&ctx, fixed_ids[1], &foo);
        insert(&ctx, fixed_ids[2], &foo);

        remove(&ctx, fixed_ids[1]);
        insert(&ctx, fixed_ids[3], &foo);

        assert(ht_find(&ctx, fixed_ids[1]) == NULL);
        assert(ht_find(&ctx, fixed_ids[3]) == &foo);
        assert(ht_find(&ctx, fixed_ids[2]) == &foo);

        return true;
}

bool lazy5(void)
{
        struct hash_table ctx = {0};
        init(&ctx, fixed_key);

        insert(&ctx, fixed_ids[0], &foo);
        insert(&ctx, fixed_ids[1], &foo);

        remove(&ctx, fixed_ids[0]);

        assert(ht_find(&ctx, fixed_ids[1]) == &foo);
        assert(ht_find(&ctx, fixed_ids[1]) == &foo);

        return true;
}


bool rebuild(void)
{
        struct hash_table ctx = {0};
        u8 key[SIPHASH_KEY] = {0};

        assert(getrandom(key, SIPHASH_KEY, 0) == SIPHASH_KEY);
        init(&ctx, key);

        i32 cap_temp = ctx.capacity;
        for (u32 i = 0; i < HT_SIZE; i++)
                insert(&ctx, i, &foo);

        if ((cap_temp * 2) != ctx.capacity)
                return false;

        for (u32 i = 0; i < HT_SIZE; i++) {
                if (ht_find(&ctx, i) != &foo)
                        return false;
        }

        return true;
}


int main(void)
{
        if (getrandom(fixed_key, SIPHASH_KEY, 0)
            != SIPHASH_KEY)
                test_panic();

        struct siphash_ctx siphash = {0};
        if (siphash_init(&siphash, fixed_key))
                test_panic();


        u32 idx = 0;
        for (u32 i = 0; i < UINT32_MAX; i++) {
                u64 hash = 0;
                if (siphash_hash(siphash, &i,
                                 sizeof(u32), (u8 *) &hash))
                        test_panic();

                if ((hash & (HT_SIZE - 1)) == 0) {
                        fixed_ids[idx] = i;
                        idx += 1;

                        if (idx == (sizeof(fixed_ids) / sizeof(u32)))
                                break;
                }
        }

        siphash_free(&siphash);

        bool test[] = {
                generic1(),
                generic2(),
                collision(),
                lazy1(),
                lazy2(),
                lazy3(),
                lazy4(),
                lazy5(),
                rebuild(),
        };

        for (u32 i = 0; i < sizeof(test) / sizeof(*test); i++) {
                if (test[i] == false) {
                        printf("[hash_table] fail %u\n", i);
                        return EXIT_FAILURE;
                }
        }

        return 0;
}
