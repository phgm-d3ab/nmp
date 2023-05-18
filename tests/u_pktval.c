#include "nmp.c"


bool pad(void)
{
        u8 buf[3][32] = {0};

        struct nmp_header out = {0};
        for (int i = 0; i < 3; i++) {
                buf[i][i] = 1;

                if (!net_packet_validate(buf[i], 32, &out))
                        return 1;
        }

        return 0;
}

bool len(void)
{
        u8 buf[2000] = {0};
        buf[3] = NMP_DATA;

        struct nmp_header out = {0};
        u32 vals[] = {
                0, 31, 1441, sizeof(buf),
        };

        for (u32 i = 0; i < sizeof(vals) / sizeof(*vals); i++)
                if (!net_packet_validate(buf, vals[i], &out))
                        return 1;

        return 0;
}

bool len2(void)
{
        u8 buf[123] = {0};
        buf[3] = NMP_REQUEST;

        struct nmp_header out = {0};

        if (!net_packet_validate(buf, sizeof(buf), &out))
                return 1;

        return 0;
}

bool len3(void)
{
        u8 buf[123] = {0};
        buf[3] = NMP_REQUEST;

        struct nmp_header out = {0};

        if (!net_packet_validate(buf, sizeof(buf), &out))
                return 1;

        return 0;
}

bool type(void)
{
        u8 buf[32] = {0};
        buf[3] = 15;

        struct nmp_header out = {0};

        if (!net_packet_validate(buf, sizeof(buf), &out))
                return 1;

        return 0;
}

int main(void)
{
        bool tests[] = {
                pad(),
                len(),
                len2(),
                len3(),
                type(),
        };

        for (u32 i = 0; i < sizeof(tests) / sizeof(*tests); i++)
                if (tests[i]) {
                        printf("[pktval] fail at index %i\n", i);
                        return EXIT_FAILURE;
                }
}
