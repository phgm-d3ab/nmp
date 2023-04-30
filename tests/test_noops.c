/*
 * in each test an unresolved callback symbol will
 * lead the linker here, defining it as noop
 */
#include "test_drv.h"


extern void test_run(const int soc,
                     const struct test_peer *a,
                     const struct test_peer *b)
{
        UNUSED(soc);
        UNUSED(a);
        UNUSED(b);
}

extern void alice_init(struct test_drv *drv, struct test_peer *bob,
                       const union nmp_sa *c)
{
        UNUSED(drv);
        UNUSED(bob);
        UNUSED(c);
}

extern void bob_init(struct test_drv *drv, struct test_peer *alice,
                     const union nmp_sa *c)
{
        UNUSED(drv);
        UNUSED(alice);
        UNUSED(c);
}


int alice_request(struct nmp_rq_connect *r, const uint8_t *p, void *c)
{
        UNUSED(p);
        r->context_ptr = c;
        return NMP_CMD_ACCEPT;
}

void alice_data(const u8 *d, u32 l, void *c)
{
        UNUSED(d);
        UNUSED(l);
        UNUSED(c);
}

void alice_noack(const u8 *d, u32 l, void *c)
{
        UNUSED(d);
        UNUSED(l);
        UNUSED(c);
}

void alice_ack(u64 a, void *c)
{
        UNUSED(a);
        UNUSED(c);
}

void alice_stats(u64 r, u64 t, void *c)
{
        (void) (r);
        (void) (t);
        (void) (c);
}


int alice_status(enum nmp_status s, const union nmp_cb_status *d, void *c)
{
        UNUSED(s);
        UNUSED(d);
        UNUSED (c);
        return NMP_STATUS_ZERO;
}


int bob_request(struct nmp_rq_connect *r, const uint8_t *p, void *c)
{
        UNUSED(p);
        r->context_ptr = c;
        return NMP_CMD_ACCEPT;
}

void bob_data(const u8 *d, u32 l, void *c)
{
        (void) (d);
        (void) (l);
        (void) (c);
}

void bob_noack(const u8 *d, u32 l, void *c)
{
        (void) (d);
        (void) (l);
        (void) (c);
}

void bob_ack(u64 a, void *c)
{
        (void) (a);
        (void) (c);
}

void bob_stats(u64 r, u64 t, void *c)
{
        (void) (r);
        (void) (t);
        (void) (c);
}

int bob_status(enum nmp_status s, const union nmp_cb_status *d, void *c)
{
        (void) (s);
        (void) (d);
        (void) (c);
        return NMP_STATUS_ZERO;
}

