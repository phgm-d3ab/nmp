#ifndef COMMON_H
#define COMMON_H

#include "nmp.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>


typedef uint8_t u8;
typedef uint16_t u16;
typedef int32_t i32;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t i64;
typedef size_t usize;
typedef ssize_t isize;
typedef double f64;


void str_bin2hex(const u8 *in, i32 len, char *out);
i32 str_hex2bin(const char *in, u8 *out, u32 out_len);
void str_bytes2str(u64 bytes, char *buf, u32 buf_len);

void addr_sa2str(const union nmp_sa *sa, char *out, u32 out_len);
i32 addr_str2sa(const char *str, union nmp_sa *sa);
i32 addr_read_full(const char *str, union nmp_sa *, u8 *pubkey);

i32 key_load(const char *path, u8 *out);
i32 key_generate(u8 *out);

void conf_info(const struct nmp_conf *conf);


struct file_mmap {
        u8 *ptr;
        usize len;
};

i32 mmap_ro(const char *path, struct file_mmap *file);
i32 mmap_rw(const char *path, usize len,
            struct file_mmap *file);


#endif /* COMMON_H */
