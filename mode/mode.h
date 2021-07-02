//
// Created by SC 2135-047 on 7/1/21.
//

#ifndef ZEDCRYPT_MODE_H
#define ZEDCRYPT_MODE_H

#include "../types.h"

struct ctx {
    void (*fp)(byte[], byte[], const byte[]);
    byte *blk, *ciph, *key;
    uint64_t mlen, tlen;
};

typedef struct ctx *state;

// converts msg to blocks of blk_len length, pads msg.
void mode_update(state st, byte msg[], uint64_t mlen, byte blk_size);

#endif //ZEDCRYPT_MODE_H
