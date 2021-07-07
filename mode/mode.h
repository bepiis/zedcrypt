//
// Created by SC 2135-047 on 7/1/21.
//

#ifndef ZEDCRYPT_MODE_H
#define ZEDCRYPT_MODE_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../types.h"

struct ctx {
    void (*fp)(byte[], byte[], const byte[]);
    byte *blk, *ciph, *out, *key;
    lword mlen, tlen;
};

typedef struct ctx *state;

void mode_update(state st, const byte msg[], lword mlen, byte blk_size);

#endif //ZEDCRYPT_MODE_H
