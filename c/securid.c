#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "aes.h"
#include "securid.h"

void usage(char *fn) {
    printf("Usage: %s <serial> <seed>\n", fn);
    exit(0);
}

int securid_token_interval(const struct securid_token *t) {
    if (((t->flags & FLD_NUMSECONDS_MASK) >> FLD_NUMSECONDS_SHIFT) == 0)
        return 30;
    else
        return 60;
}

static void bcd_write(uint8_t *out, int val, unsigned int bytes) {
    out += bytes - 1;
    for (; bytes; bytes--) {
        *out = val % 10;
        val /= 10;
        *(out--) |= (val % 10) << 4;
        val /= 10;
    }
}

static void key_from_time(const uint8_t *bcd_time, int bcd_time_bytes, const uint8_t *serial, uint8_t *key) {
    int i;

    memset(key, 0xaa, 8);
    memcpy(key, bcd_time, bcd_time_bytes);
    memset(key + 12, 0xbb, 4);

    /* write BCD-encoded partial serial number */
    key += 8;
    for (i = 4; i < 12; i += 2)
        *(key++) = ((serial[i] - '0') << 4) |
                   (serial[i + 1] - '0');
}

void securid_compute_tokencode(struct securid_token *t, time_t now, char *code_out) {
    uint8_t bcd_time[8];
    uint8_t key0[AES_KEY_SIZE], key1[AES_KEY_SIZE];
    int i, j;
    uint32_t tokencode;
    struct tm gmt;
    int pin_len = strlen(t->pin);
    int is_30 = securid_token_interval(t) == 30;

    gmtime_r(&now, &gmt);
    bcd_write(&bcd_time[0], gmt.tm_year + 1900, 2);
    bcd_write(&bcd_time[2], gmt.tm_mon + 1, 1);
    bcd_write(&bcd_time[3], gmt.tm_mday, 1);
    bcd_write(&bcd_time[4], gmt.tm_hour, 1);
    bcd_write(&bcd_time[5], gmt.tm_min & ~(is_30 ? 0x01 : 0x03), 1);
    bcd_time[6] = bcd_time[7] = 0;

    key_from_time(bcd_time, 2, t->serial, key0);
    AES128_ECB_encrypt(key0, t->dec_seed, key0);
    key_from_time(bcd_time, 3, t->serial, key1);
    AES128_ECB_encrypt(key1, key0, key1);
    key_from_time(bcd_time, 4, t->serial, key0);
    AES128_ECB_encrypt(key0, key1, key0);
    key_from_time(bcd_time, 5, t->serial, key1);
    AES128_ECB_encrypt(key1, key0, key1);
    key_from_time(bcd_time, 8, t->serial, key0);
    AES128_ECB_encrypt(key0, key1, key0);

    /* key0 now contains 4 consecutive token codes */
    if (is_30)
        i = ((gmt.tm_min & 0x01) << 3) | ((gmt.tm_sec >= 30) << 2);
    else
        i = (gmt.tm_min & 0x03) << 2;

    tokencode = (key0[i + 0] << 24) | (key0[i + 1] << 16) |
                (key0[i + 2] << 8) | (key0[i + 3] << 0);

    /* populate code_out backwards, adding PIN digits if available */
    j = ((t->flags & FLD_DIGIT_MASK) >> FLD_DIGIT_SHIFT) + 1;
    code_out[j--] = 0;
    for (i = 0; j >= 0; j--, i++) {
        uint8_t c = tokencode % 10;
        tokencode /= 10;

        if (i < pin_len)
            c += t->pin[pin_len - i - 1] - '0';
        code_out[j] = c % 10 + '0';
    }
}

int main(int argc, char **argv) {
    char code[16];
    if (argc != 3) {
        usage(argv[0]);
    }
    if (strlen(argv[1]) != 12) {
        printf("Invalid token serial: Must be 12 digits.\n");
        usage(argv[0]);
    }
    if (strlen(argv[2]) != 47) {
        printf("Invalid seed. Use format hh:hh:hh:hh(...)\n");
        usage(argv[0]);
    }
    struct securid_token *token = malloc(sizeof(struct securid_token));
    memset(token, 0, sizeof(struct securid_token));
    char *p = argv[2];
    for (int i = 0; i < 16; i++) {
        if (sscanf(p, "%hhx", (char *) (token->dec_seed + i)) == EOF) {
            printf("Invalid seed. Use format hh:hh:hh:hh(...)\n");
            usage(argv[0]);
        }
        p += 3;
    }
    strcpy(token->serial, argv[1]);
    strcpy(token->pin, "111111");
    token->flags = 17369;
    securid_compute_tokencode(token, time(NULL), code);

    puts(code + 2);

    return 0;
}