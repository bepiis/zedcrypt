//
// Created by SC 2135-047 on 7/1/21.
//

#ifndef ZEDCRYPT_SHA_H
#define ZEDCRYPT_SHA_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>

#include "consts.h"
#include "../types.h"

// choice and majority functions
#define ch(t, s, d) ((t & s) ^ (~t & d))
#define maj(t, s, d) ((t & s) ^ (t & d) ^ (s & d))

// general rotate functions. sha12.c and sha35.c fill w param with 32 or 64 respecitvely
#define wrotl(t, s, w) (((t) << (s)) | ((t) >> ((w) - (s))))
#define wrotr(t, s, w) (((t) >> (s)) | ((t) << ((w) - (s))))

#define shr(t, s) ((t) >> (s))
#define shl(t, s) ((t) << (s))

// general sigma functions for sha2xx, 384, and 512xx
// used to define sig0, sig1, usig0, usig1 (see sha12.c or sha35.c for definitions)
#define uf0(t, s1, s2, s3) (rotr(t, s1) ^ rotr(t, s2) ^ rotr(t, s3))
#define uf1(t, s1, s2, s3) (rotr(t, s1) ^ rotr(t, s2) ^ rotr(t, s3))
#define f0(t, s1, s2, s3)  (rotr(t, s1) ^ rotr(t, s2) ^ shr(t, s3))
#define f1(t, s1, s2, s3)  (rotr(t, s1) ^ rotr(t, s2) ^ shr(t, s3))

// converts 4 bytes from array to a 32 bit word
#define b2w(blk, t, s, d, r) \
    ((blk[t] << 24) | (blk[s] << 16) | (blk[d] << 8) | (blk[r]))

#define wzero(w) \
    w->mlen = 0; w->tlen = 0;

// copies hval into working variables
#define hval_8cpy(hval, a, b, c, d, e, f, g, h) \
    a = hval[0]; b = hval[1]; c = hval[2]; d = hval[3]; \
    e = hval[4]; f = hval[5]; g = hval[6]; h = hval[7];

// increments hval from working variables
#define hval_8inc(hval, a, b, c, d, e, f, g, h) \
    hval[0] += a; hval[1] += b; hval[2] += c; hval[3] += d; \
    hval[4] += e; hval[5] += f; hval[6] += g; hval[7] += h;

#define hval_5cpy(hval, a, b, c, d, e) \
    a = hval[0]; b = hval[1]; c = hval[2]; \
    d = hval[3]; e = hval[4];

#define hval_5inc(hval, a, b, c, d, e) \
    hval[0] += a; hval[1] += b; hval[2] += c; \
    hval[3] += d; hval[4] += e;

#define WRD_MAX  0xffffffffUL;
#define LWRD_MAX 0xffffffffffffffffULL;

// sha1, 224 and 256 block length
#define BLK_LEN_12 64

// sha512, 384, 512/224 and 512/256 block length
#define BLK_LEN_35 128

// length of message length in block
#define MLEN_BLK_LEN_12 64 - 8
#define MLEN_BLK_LEN_35 128 - 8

#define S_1_SCHEDULE_LEN 80
#define S_2XX_SCHEDULE_LEN 64
#define S_512_SCHEDULE_LEN 80

#define S_1_DIGEST_LEN 20 //160/8
#define S_224_DIGEST_LEN 28 //224/8
#define S_256_DIGEST_LEN 32 //256/8
#define S_384_DIGEST_LEN 48 //384/8
#define S_512_DIGEST_LEN 64 //512/8
#define S_512_256_DIGEST_LEN 32 //256/8
#define S_512_224_DIGEST_LEN 28 //224/8


// sha structure for sha1, 224, and 256
struct sha12_state {
    byte blk[BLK_LEN_12];
    word mlen;
    lword tlen;
    word *hval;
};

// sha structure for sha384, 512, 512/224, and 512/256
struct sha35_state {
    byte blk[BLK_LEN_35];
    lword mlen;
    lword tlen;
    lword *hval;
};

typedef struct sha12_state *work12;
typedef struct sha35_state *work35;

void sha12_init(work12 w, word type);
void sha12_update(work12 w, const byte inp[], lword inp_len, word type);
void sha12_final(work12 w, byte digest[], word type);

#define sha1_init(w) (sha12_init(w, 160))
#define sha1_update(w, inp, inp_len) (sha12_update(w, inp, inp_len, 160))
#define sha1_final(w, digest) (sha12_final(w, digest, 160))

#define sha256_init(w) (sha12_init(w, 256))
#define sha256_update(w, inp, inp_len) (sha12_update(w, inp, inp_len, 256))
#define sha256_final(w, digest) (sha12_final(w, digest, 256))

#define sha224_init(w) (sha12_init(w, 224))
#define sha224_update(w, inp, inp_len) (sha12_update(w, inp, inp_len, 224))
#define sha224_final(w, digest) (sha12_final(w, digest, 224))

void sha35_init(work35 w, word type);
void sha35_update(work35 w, const byte inp[], lword inp_len);
void sha35_final(work35 w, byte digest[], word digest_len);

#define sha512_init(w) (sha35_init(w, 512))
#define sha512_update(w, inp, inp_len) (sha35_update(w, inp, inp_len))
#define sha512_final(w, digest) (sha35_final(w, digest, S_512_DIGEST_LEN))

#define sha384_init(w) (sha35_init(w, 384))
#define sha384_update(w, inp, inp_len) (sha35_update(w, inp, inp_len))
#define sha384_final(w, digest) (sha35_final(w, digest, S_384_DIGEST_LEN))

#define sha512_256_init(w) (sha35_init(w, 256))
#define sha512_256_update(w, inp, inp_len) (sha35_update(w, inp, inp_len))
#define sha512_256_final(w, digest) (sha35_final(w, digest, S_512_256_LEN))

#define sha512_224_init(w) (sha35_init(w, 224))
#define sha512_224_update(w, inp, inp_len) (sha35_update(w, inp, inp_len))
#define sha512_224_final(w, digest) (sha35_final(w, digest, S_512_224_LEN))

#endif //ZEDCRYPT_SHA_H
