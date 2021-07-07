//
// Created by SC 2135-047 on 7/1/21.
//

#include "aes.h"

// for gf(2^8), overflow = 0x100 = 2^8, mod = 0x11b (x^8 + x^4 + x^3 + x + 1)
byte gf2n_mult(int t, int s, int overflow, int mod){
    byte ret = 0;
    while(s > 0){
        if(s & 0x1){
            ret ^= t;
        }

        s >>= 1;
        t <<= 1;

        if(t & overflow){
            t ^= mod;
        }

    }
    return ret;
}

// copy state into temporary variable.
state *state_cpy(state *st){
    state *tmp = malloc(16);
    memcpy(tmp, st, 16);

    return tmp;
}

void in_cpy(const byte in[], state *st, byte r, byte c, byte i){ (*st)[c][r] = in[i]; }
void out_cpy(byte out[], state *st, byte r, byte c, byte i) { out[i] = (*st)[c][r]; }

/*
    copy into or out of state

    if dir = 0, copy into state, else copy out of state
*/
void st_cpy(byte hold[], state *st, byte dir){
    void (*fp)(byte[], state*, byte, byte, byte);

    if(dir){
        fp = out_cpy;
    } else {
        fp = in_cpy;
    }

    byte i=0;
    for(byte r=0; r < 4; r++){
        for(byte c=0; c < 4; c++){
            (*fp)(hold, st, r, c, i);
            i++;
        }
    }
}

// same as sub_bytes, but works on words instead of 4 bytes
void sub_word(word *w){
    word up = 0x000000f0, lo = 0x0000000f;
    word inter;
    word y = *w;
    *w = 0;

    for(byte j=0, m=24; j < 4; j++, m-=8){
        inter = y >> m;
        *w |= (sbox[(inter & up) >> 4][inter & lo]) << m;
    }
}

/*
    substitutes bytes in state by using upper nibble of byte to reference
    row of sbox and lower nibble to reference col of sbox or invsbox:

    0xfe --> box[f][e]
*/
void sub_bytes(state *st, byte inv){
    const byte (*box)[16][16] = inv ? &invsbox : &sbox;

    state *tmp = state_cpy(st);

    for(byte r=0; r < 4; r++){
        for(byte c=0; c < 4; c++){
            (*st)[r][c] = (*box)[((*tmp)[r][c] & 0xf0) >> 4][(*tmp)[r][c] & 0x0f];
        }
    }
    free(tmp);
}

static inline void rot_row(state *st, state *tmp, byte r, byte c, byte s){
    (*st)[r][c] = (*tmp)[r][s];
}

static inline void rot_row_inv(state *st, state *tmp, byte r, byte c, byte s){
    (*st)[r][s] = (*tmp)[r][c];
}

/*
    shift rows of state right or left if inv is set, respectively

    1st row of state not shifted

    a shift right is three shift lefts
*/
void rot_rows(state *st, byte inv){
    state *tmp = state_cpy(st);

    void (*fp)(state*, state*, byte, byte, byte) = inv ? rot_row_inv : rot_row;

    for(byte r=1, s=1; r < 4; r++){
        for(byte c=0; c < 4; c++){
            (*fp)(st, tmp, r, c, s);

            if(s == 3) s = 0;
            else s++;
        }
        s++;
    }
    free(tmp);
}

const static byte Ax[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
};

const static byte invAx[4][4] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
};

/*
    function applies eqn: s'(x) = a(x) @* s(x)
    onto the columns of the working state where:

    @* is finite field multiplication operator and
    a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
    s(x) is a column vector in the state

*/
void mix_cols(state *st, byte inv){
    byte tx;
    byte t = 0;

    // if inv is set, use A^-1(x), else use A(x)
    const byte (*mix)[4][4] = inv ? &invAx : &Ax;

    state *tmp = state_cpy(st);

    for(byte i=0; i < 4; i++){
        for(byte r=0; r < 4; r++){
            for(byte c=0; c < 4; c++){

                // gf28_mult is a macro of gf2n_mult
                tx = ((*mix)[r][c] == 0x01) ? (*tmp)[c][i] : gf28_mult((*mix)[r][c], (*tmp)[c][i]);

                t ^= tx;
            }
            (*st)[r][i] = t;
            t = 0;
        }
    }
    free(tmp);
}

/*
    adds round_key modulo m(x) to columns of state
    round key chosen is dependent on Nb and the current round.

    note: having round_keys as arrays of bytes requires less bitwise arithmetic,
          but i chose to keep them as 32-bit words when implementing.

    could cut down on computation by defining round key in terms of bytes
*/
void add_round_key(byte round, state *st, const word round_key[]){
    byte l = round * Nb;
    word m;

    for(byte c=0; c < 4; c++){
        m = 0xff000000UL;
        //printf("round key: %x\n", round_key[l + c]);

        for(byte r=0, s=24; r < 4; s-=8, r++){
      //      printf("%x, %x\n", (*st)[r][c], (round_key[l + c] & m) >> s);
            (*st)[r][c] ^= (round_key[l + c] & m) >> s;
            m >>= 8;
        }
    }
    //printf("\n");
}

#define rot_word(w) (((w) << 8) | ((w) >> (32 - 8)))

#define b2w(key, t, s, d, r) (((key)[t] << 24) | ((key)[s] << 16) | ((key)[d] << 8) | ((key)[r]))

/*
    round_key[Nb * (Nr + 1)]
    key[4 * Nk]

    expands keys in order to use in block cipher
 */
void key_expand(word round_key[], const byte key[], const struct key_round *kr){
    word tmp;
    byte i, m;

    i = m = 0;

    //printf("Start key expansion routine: \n\n");

    // convert bytes to words
    //printf("Copy key into first %d round keys: \n", kr->Nk);
    while(i < kr->Nk){
        round_key[i] = b2w(key, m, m+1, m+2, m+3) & WRD_MAX
        //printf("w[%d] = %x   ", i, round_key[i]);
        i++;
        m += 4;
    }
    //printf("\n\n");

    i = kr->Nk;

    //printf("Start expanding: \n");
    while(i < kr->RK_LEN){
        tmp = round_key[i - 1];
        //printf("tmp = %x   ", tmp);

        if(i % kr->Nk == 0){
            tmp = rot_word(tmp);
            //printf("rot: %x   ", tmp);
            sub_word(&tmp);
            //printf("sub: %x   ", tmp);

            tmp ^= rcon[i/kr->Nk];
          //  printf("rcon: %x   ", tmp);

        } else if(kr->Nk > 6 && i % kr->Nk == 4){
            sub_word(&tmp);
        }

        round_key[i] = round_key[i - kr->Nk] ^ tmp;
        //printf("w[%d - Nk] = %x   ", i, round_key[i - kr->Nk]);
        //printf("w[%d - Nk] ^ tmp = %x\n", i, round_key[i]);

        i++;
    }
}

void print_state(state *st){
    for(byte r=0; r < 4; r++){
        for(byte c=0; c < 4; c++){
            printf("%x ", (*st)[r][c]);
        }
        printf("\n");
    }
    printf("\n\n");
}

// in[4 * Nb]
// out[4 * Nb]
// round_key[Nb * (Nr + 1)]
void cipher(byte inp[], byte outp[], const word round_key[], const struct key_round *kr){
    byte round = 0;
    state st;

    st_cpy(inp, &st, 0);

    add_round_key(round++, &st, round_key);

    for(;; round++){

        sub_bytes(&st, 0);
        rot_rows(&st, 0);

        if(round == kr->Nr){
            add_round_key(round, &st, round_key);
            break;
        }

        mix_cols(&st, 0);
        add_round_key(round, &st, round_key);
    }

    st_cpy(outp, &st, 1);
}

void cipher_inv(byte in[], byte out[], const word round_key[], const struct key_round *kr){
    byte round = kr->Nr;

    state st;

    st_cpy(in, &st, 0);

    add_round_key(round--, &st, round_key);

    for(;; round--){
        rot_rows(&st, 1);
        sub_bytes(&st, 1);
        add_round_key(round, &st, round_key);

        if(!round){
            break;
        }

        mix_cols(&st, 1);
    }

    st_cpy(out, &st, 1);
}

const struct key_round kr_128 = {4, 10, 44};
const struct key_round kr_192 = {6, 12, 56};
const struct key_round kr_256 = {8, 14, 60};

const struct key_round *get_k_consts(unsigned k_len){
    return !(k_len ^ 128) ? &kr_128 : !(k_len ^ 192) ? &kr_192 : !(k_len ^ 256) ? &kr_256 : NULL;
}

void AES_do(byte inp[], byte outp[], const byte key[], unsigned k_len, byte inv){

    void (*ciph)(byte[], byte[], const word[], const struct key_round*);
    const struct key_round *kr;

    if((kr = get_k_consts(k_len)) == NULL){
        return;
    }

    ciph = inv ? cipher_inv : cipher;

    word round_key[kr->RK_LEN];

    key_expand(round_key, key, kr);

    (*ciph)(inp, outp, round_key, kr);
}

