#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include "nmp.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>


typedef int8_t i8;
typedef uint8_t u8;
typedef int16_t i16;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef int64_t i64;
typedef uint64_t u64;
typedef size_t usize;
typedef ssize_t isize;
typedef float f32;
typedef double f64;


#if !defined(UNUSED)
#define UNUSED(x_) (void)(x_)
#endif

#define TEST_FILE (&__FILE__[SRC_PATH_OFFSET])


#define test_panic() \
        do { printf("[panic] %s() at %s:%u\n", \
        __func__, TEST_FILE, __LINE__); abort();} while(0)


#define nmp_submit(ptr_, rqs_, amt_) do { \
        if (nmp_submit(ptr_, rqs_, amt_)) test_panic();} while (0)


#define random_bytes(ptr_, len_) do { \
        if (__random_bytes(ptr_, len_)) test_panic();} while (0)
bool __random_bytes(void *, isize);



struct test_drv;

struct test_peer {
        union nmp_sa addr;
        u8 pubkey[NMP_KEYLEN];
};


void test_set_ctx(struct test_drv *, void *ctx);
void *test_get_ctx(struct test_drv *);
nmp_t *test_instance(struct test_drv *);


/* main thread */
extern void test_run(int soc,
                     const struct test_peer *alice,
                     const struct test_peer *bob);

/* separate threads for each */
extern void alice_init(struct test_drv *drv, struct test_peer *bob,
                       const union nmp_sa *control);
extern void bob_init(struct test_drv *drv, struct test_peer *alice,
                     const union nmp_sa *control);


void test_complete(struct test_drv *);

#define test_fail() __test_fail(TEST_FILE)
void __test_fail(const char *);

#endif
