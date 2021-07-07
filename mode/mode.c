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

/// @return -1: msg length is larger than block size
/// @return -2: msg length is equal to block size. Add padded block to end of msg array
/// @return 0: msg was padded
int pad_msg(byte msg[], byte msg_len, byte blk_size){
    byte idx = msg_len;
    byte left;

    if((left = blk_size - msg_len) < 0){
        return -1;
    } else if(left == 0){
        return -2;
    }

    msg[idx++] = 0x80;

    for(; idx < blk_size; idx++){
        msg[idx] = 0x0;
    }
    return 0;
}

// dblblk[] needs to be 2*blk_size ie. the contents of the last two blocks
byte *unpad_msg(const byte dblblk[], byte blk_size, byte num_blks, int *ret_len){
    byte *ret, it, fnd;

    it = 2 * blk_size - 1;
    fnd = -1;

    while(it >= 0){
        if(dblblk[it] == 0x1){
            fnd = it;
            break;
        }
        it--;
    }

    if(fnd < 0){
        *ret_len = -1;
        return NULL;
    }

    ret = malloc(fnd);
    memcpy(ret, dblblk, fnd);

    *ret_len = fnd;
    return ret;
}

byte *get_padded_blk(byte blk_size){

}

void mode_init(state st, lword totlen, byte blk_size, byte key_size, void (*fp)(byte[], byte[], const byte[])){
    st->mlen = 0;
    st->tlen = 0;

    st->fp = fp;

    //TODO: free
    st->blk = malloc(blk_size);
    st->ciph = malloc(blk_size);
    st->out = malloc(totlen);
    st->key = malloc(key_size);
}

void mode_update(state st, const byte msg[], lword mlen, byte blk_size){
    for(unsigned i=0; i < mlen; i++){
        st->blk[st->mlen++] = msg[i];

        if(st->mlen == blk_size){
            st->fp(st->blk, st->ciph, st->key);


            st->tlen += blk_size;

            for(unsigned c=st->tlen - blk_size, h=0; h < blk_size; c++, h++){
                st->out[c] = st->ciph[h];
            }

            st->mlen = 0;
        }
    }
}

