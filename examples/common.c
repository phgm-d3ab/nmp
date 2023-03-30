#include "common.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/random.h>
#include <sys/mman.h>
#include <sys/stat.h>


/* map a..f, A..F, 0..9 to bits in array */
#define is_hex(c_) (hex_whitelist[((c_) / 32) & 7] & (1u << ((c_) & 31)))
static const u32 hex_whitelist[8] = {
        0x00, 0x3ff0000, 0x7e, 0x7e,
        0x00, 0x00, 0x00, 0x00
};


void str_bin2hex(const u8 *in, const i32 len, char *out)
{
        const char hex[] = "0123456789abcdef";

        for (i32 i = 0; i < len; i++) {
                out[(u32) (i * 2)] = hex[in[i] >> 4];
                out[(u32) ((i * 2) + 1)] = hex[in[i] & 0xf];
        }

        out[(u32) (len * 2)] = 0;
}


i32 str_hex2bin(const char *in, u8 *out, const u32 len)
{
        u32 i = 0;

        while (is_hex(in[i]) && i < (len * 2))
                i += 1;

        if (i != (len * 2))
                return 1;

        errno = 0;
        for (i = 0; i < len; i++) {
                char *inval = NULL;
                char tmp[4] = {
                        in[i * 2],
                        in[(i * 2) + 1],
                        0,
                        0,
                };

                const i64 val = strtoll(tmp, &inval, 16);
                if (errno)
                        return 1;

                out[i] = (u8) val;
        }

        return 0;
}


void str_bytes2str(u64 bytes, char *buf, u32 buf_len)
{
        if (bytes < 1024) {
                snprintf(buf, buf_len, "%u byte(s)", (u32) bytes);
                return;
        }

        const char *suffix[] = {"", "KB", "MB", "GB"};
        const u32 suffix_len = sizeof(suffix) / sizeof(*suffix);

        u32 i = 0;
        f64 amt = (f64) bytes;

        for (;;) {
                if (bytes / 1024) {
                        amt = (f64) bytes / 1024.0;
                        bytes /= 1024;

                        i += 1;
                        if (i == suffix_len - 1)
                                break;

                        continue;
                }

                break;
        }

        snprintf(buf, buf_len, "%.1lf %s", amt, suffix[i]);
}


static i32 ip_port(const char *str)
{
        char port_str[16] = {0};
        i32 i = 0;

        for (; i < 16; i++) {
                if (str[i] < '0' || str[i] > '9')
                        break;

                port_str[i] = str[i];
        }

        if (i == 0 || i > 5 || str[i])
                return -1;

        errno = 0;
        char *inval = NULL;

        const i64 val = strtoll(port_str, &inval, 10);
        if (errno || val < 0 || val > 0xffff)
                return -1;

        return (i32) val;
}


static i32 ip_read4(const char *str, union nmp_sa *sa)
{
        i32 i = 0;
        i32 colon = -1;
        char ip_buf[16] = {0};

        for (; str[i] && i < 16; i++) {
                if (str[i] == ':') {
                        colon = i;
                        break;
                }

                ip_buf[i] = str[i];
        }

        if (i < 7 || i > 15)
                return -1;

        if (colon == -1)
                return -1;

        struct in_addr addr = {0};
        if (!inet_pton(AF_INET, ip_buf, &addr))
                return -1;

        str += colon;
        const i32 port = ip_port(str + 1);
        if (port < 0)
                return -1;

        sa->ip4 = (struct sockaddr_in) {
                .sin_family = AF_INET,
                .sin_addr = addr,
                .sin_port = htons((u16) port),
        };

        return 0;
}


static i32 ip_read6(const char *str, union nmp_sa *sa)
{
        i32 i = 0;
        i32 br = -1;

        char ip_buf[64] = {0};
        for (; str[i] && i < 64; i++) {
                if (str[i] == ']') {
                        br = i;
                        break;
                }

                ip_buf[i] = str[i];
        }

        if (i < 15 || i > 39)
                return -1;

        if (br == -1)
                return -1;

        ip_buf[br] = 0;
        struct in6_addr addr = {0};

        if (!inet_pton(AF_INET6, ip_buf, &addr))
                return -1;

        str += (br + 1);
        if (*str != ':')
                return -1;

        const i32 port = ip_port(str + 1);
        if (port < 0)
                return -1;

        sa->ip6 = (struct sockaddr_in6) {
                .sin6_family = AF_INET6,
                .sin6_addr = addr,
                .sin6_port = htons((u16) port),
        };

        return 0;
}


void addr_sa2str(const union nmp_sa *sa,
                 char *out, const u32 out_len)
{
        char buf[INET6_ADDRSTRLEN] = {0};
        inet_ntop(sa->sa.sa_family, &sa->ip4.sin_addr,
                  buf, INET6_ADDRSTRLEN);

        snprintf(out, out_len,
                 (sa->sa.sa_family == AF_INET) ? "%s:%u" : "[%s]:%u",
                 buf, ntohs(sa->ip4.sin_port));
}


i32 addr_str2sa(const char *str, union nmp_sa *sa)
{
        return (*str == '[') ? ip_read6(str + 1, sa)
                             : ip_read4(str, sa);
}


i32 addr_read_full(const char *str, union nmp_sa *sa, u8 *pubkey)
{
        if (str_hex2bin(str, pubkey, NMP_KEYLEN))
                return -1;

        str += (isize) (NMP_KEYLEN * 2);
        if (*str != '@')
                return -1;

        str += 1;
        return (*str == '[') ? ip_read6(str + 1, sa)
                             : ip_read4(str, sa);
}


i32 key_load(const char *path, u8 *out)
{
        const int fd = open(path, O_RDONLY);
        if (fd == -1)
                return -1;

        u8 buf[NMP_KEYLEN + 8] = {0};
        if (read(fd, buf, sizeof(buf)) != NMP_KEYLEN) {
                errno = EINVAL;
                return -1;
        }

        close(fd);
        memcpy(out, buf, NMP_KEYLEN);
        return 0;
}


i32 key_generate(u8 *out)
{
        return (getrandom(out, NMP_KEYLEN, 0) == NMP_KEYLEN) ?
               0 : -1;
}


void conf_info(const struct nmp_conf *conf)
{
        char addr_str[128] = {0};
        char key_row1[56] = {0};
        char key_row2[56] = {0};

        addr_sa2str(&conf->addr, addr_str, sizeof(addr_str));
        str_bin2hex(conf->pubkey, 28, key_row1);
        str_bin2hex(conf->pubkey + 28, 28, key_row2);

        printf("[conf] using addr: %s\n"
               "[conf] local public key:\n"
               "%s\n%s\n",
               addr_str, key_row1, key_row2);
}


i32 mmap_ro(const char *path, struct file_mmap *file)
{
        const int fd = open(path, O_RDONLY);
        if (fd == -1)
                return -1;

        struct stat st = {0};
        if (fstat(fd, &st))
                goto out_fail;

        u8 *ptr = mmap(NULL, st.st_size,
                       PROT_READ, MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED)
                goto out_fail;

        file->ptr = ptr;
        file->len = st.st_size;

        close(fd);
        return 0;

        out_fail:
        {
                close(fd);
                return -1;
        };
}


i32 mmap_rw(const char *path, const usize len,
            struct file_mmap *file)
{
        const int fd = open(path, O_RDWR | O_CREAT, 0600);
        if (fd == -1)
                return -1;

        if (ftruncate(fd, (isize) len))
                goto out_fail;

        u8 *ptr = mmap(NULL, len, PROT_READ | PROT_WRITE,
                       MAP_SHARED, fd, 0);
        if (ptr == MAP_FAILED)
                goto out_fail;

        file->ptr = ptr;
        file->len = len;

        close(fd);
        return 0;

        out_fail:
        {
                close(fd);
                return -1;
        };
}
