//
// Created by SC 2135-047 on 7/1/21.
//

#include "sha.h"

#define rotr(t, s) (wrotr(t, s, 32))
#define rotl(t, s) (wrotl(t, s, 32))

#define usig0(t) (uf0(t, 2, 13, 22))
#define usig1(t) (uf1(t, 6, 11, 25))
#define sig0(t)  (f0(t, 7, 18, 3))
#define sig1(t)  (f1(t, 17, 19, 10))


void schedule12_init(word wblk[], byte bblk[]){
    word i, n;
    for(i = n = 0; i < 16; i++, n+=4){
        wblk[i] = b2w(bblk, n, n+1, n+2, n+3) & WRD_MAX
    }
}

void sha1_schedule_init(word wblk[]){
    for(word i=16; i < S_1_SCHEDULE_LEN; i++){
        wblk[i] = rotl(wblk[i-3] ^ wblk[i-8] ^ wblk[i-14] ^ wblk[i-16], 1);
    }
}

void sha256_schedule_init(word wblk[]){
    for(word i=16; i < S_2XX_SCHEDULE_LEN; i++){
        wblk[i] = sig1(wblk[i - 2]) + wblk[i - 7] + sig0(wblk[i - 15]) + wblk[i - 16];
    }
}

void sha1_do(work12 w){
    word a, b, c, d, e;
    word t;
    word blk[S_1_SCHEDULE_LEN];
    word i, ft, k;

    schedule12_init(blk, w->blk);
    sha1_schedule_init(blk);

    hval_5cpy(w->hval, a, b, c, d, e)
    for(i=0; i < S_1_SCHEDULE_LEN; i++){
        if(i < 20){
            ft = ch(b, c, d);
            k = K_1[0];
        } else if(i < 40){
            ft = b ^ c ^ d;
            k = K_1[1];
        } else if(i < 60){
            ft  = maj(b, c, d);
            k = K_1[2];
        } else {
            ft = b ^ c ^ d;
            k = K_1[3];
        }

        t = rotl(a, 5) + ft + e + k + blk[i];
        e = d;
        d = c;
        c = rotl(b, 30);
        b = a;
        a = t;
    }
    hval_5inc(w->hval, a, b, c, d, e)
}

void sha256_do(work12 w){
    word a, b, c, d, e, f, g, h;
    word t1, t2;
    word blk[S_2XX_SCHEDULE_LEN];
    word i;

    schedule12_init(blk, w->blk);
    sha256_schedule_init(blk);

    hval_8cpy(w->hval, a, b, c, d, e, f, g, h)

    for(i=0; i < S_2XX_SCHEDULE_LEN; i++){
        t1 = h + usig1(e) + ch(e, f, g) + K_2xx[i] + blk[i];
        t2 = usig0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    hval_8inc(w->hval, a, b, c, d, e, f, g, h)
}

void (*get_type(word type))(work12){
    switch(type){
        case 160:
            return sha1_do;
        case 224:
            return sha256_do;
        case 256:
            return sha256_do;
        default:
            return NULL;
    }
}



void sha12_init(work12 w, word type){
    word h0_len;
    const word *h0;

    switch(type){
        case 160:
            h0_len = H0_1_LEN;
            h0 = &H0_1[0];
            break;
        case 256:
            h0_len = H0_256_LEN;
            h0 = &H0_256[0];
            break;
        case 224:
            h0_len = H0_224_LEN;
            h0 = &H0_224[0];
            break;
        default:
            return;
    }

    wzero(w)

    w->hval = malloc(h0_len);

    memcpy(w->hval, h0, h0_len * 4);
}

void sha12_update(work12 w, const byte inp[], lword inp_len, word type){
    void (*sha_do)(work12);

    if((sha_do = get_type(type)) == NULL){
        return;
    }

    for(word i=0; i < inp_len; i++){

        w->blk[w->mlen++] = inp[i];

        if(w->mlen == BLK_LEN_12){
            (*sha_do)(w);
            w->tlen += BLK_LEN_12 * 8;
            w->mlen = 0;
        }
    }
}

void sha12_final(work12 w, byte digest[], word type){
    void (*sha_do)(work12);
    word digest_len = type/8;

    if((sha_do = get_type(type)) == NULL){
        return;
    }

    word len = w->mlen;
    word up = len < MLEN_BLK_LEN_12;
    word upper = up == 1 ? MLEN_BLK_LEN_12 : BLK_LEN_12;

    w->blk[len++] = 0x80;

    while(len < upper){
        w->blk[len++] = 0x0;
    }

    if(!up){
        (*sha_do)(w);
        bzero(w->blk, MLEN_BLK_LEN_12);
    }

    w->tlen += w->mlen * 8;

    for(word i=BLK_LEN_12 - 1, n=0; i > MLEN_BLK_LEN_12 - 1; i--, n += 8){
        w->blk[i] = w->tlen >> n;
    }

    (*sha_do)(w);

    word k=0, idx=0;
    while(idx < digest_len){
        for(word j=0, m=24; j < 4; j++, m-=8){
            digest[idx++] = (w->hval[k] >> m) & 0x000000ff;
        }
        k++;
    }
    free(w->hval);
}


