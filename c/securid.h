#ifndef RSASECURID_SECURID_H
#define RSASECURID_SECURID_H

#include <time.h>
#include <stdint.h>

#define AES_KEY_SIZE        16
#define FLD_NUMSECONDS_SHIFT    0
#define FLD_NUMSECONDS_MASK    (0x03 << FLD_NUMSECONDS_SHIFT)
#define FLD_DIGIT_SHIFT        6
#define FLD_DIGIT_MASK        (0x07 << FLD_DIGIT_SHIFT)

#define MAX_PIN            8
#define SERIAL_CHARS        12

struct securid_token {
    char serial[SERIAL_CHARS + 1];
    uint16_t flags;
    uint8_t dec_seed[AES_KEY_SIZE];
    char pin[MAX_PIN + 1];
};


void securid_compute_tokencode(struct securid_token *t, time_t now, char *code_out);

#endif //RSASECURID_SECURID_H
