//
// Created by SC 2135-047 on 7/1/21.
//

#include "mode.h"

// ECB and CBC, total bits in plaintext must be multiple of block size b ie. n*b
// For AES block size is 128 bits, so bits_total mod 16 must be 0

// CFB, total bits in plaintext must be multiple of parameter s, where s does not exceed the block size

/*
    OFB, CTR plaintext doesnt need to be multiple of block size. Instead if n and u are a pair of unique
    unsigned integers s.t. the total number of bits of plaintext is (n-1)b + u where 1 <= u <= b.
    Plaintext conists of n bit strings with a bit length of the block size and the last bit string u is
    not and thus may not complete a block
*/

// CFB, CBC and OFB use an initialization vector (IV) as a cipher block. Used in initial step of
// encryption and decryption
// For CBC and CFB, IV must be unpredictable
// For OFB, unique IVs are needed for each execution of encryption process

// ECB encryption: C_j = CIPH_k(P_j)
// ECB decryption: P_j = CIPH^-1_k(C_j)
// both for j = 1 to n

void mode_init(state st, byte blk_size, byte key_size, uint64_t mlen, void (*fp)(byte[], byte[], const byte[])){
    st->mlen = 0;
    st->tlen = 0;

    st->fp = fp;

    st->ciph = malloc(blk_size);
    st->blk = malloc(blk_size);

}

void mode_update(state st, byte msg[], uint64_t mlen, byte blk_size){
    for(unsigned i=0; i < mlen; i++){
        st->blk[st->mlen++] = msg[i];

        if(st->mlen == blk_size){
            st->fp(st->blk, st->ciph, st->key);

            st->tlen += blk_size * 8;
            st->mlen = 0;
        }
    }
}

