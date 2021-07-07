//
// Created by SC 2135-047 on 7/1/21.
//

#include "sha.h"

#define rotl(t, s) (wrotl(t, s, 64))
#define rotr(t, s) (wrotr(t, s, 64))

#define usig0(t) (uf0(t, 28, 34, 39))
#define usig1(t) (uf1(t, 14, 18, 41))
#define sig0(t)  (f0(t, 1, 8, 7))
#define sig1(t)  (f1(t, 19, 61, 6))

void schedule35_init(lword wblk[], const byte bblk[]){

    lword p1, p2, i, n;
    for(i = n = 0; i < 16; i++, n+=8){
        p1 = b2w(bblk, n, n+1, n+2, n+3);
        p2 = b2w(bblk, n+4, n+5, n+6, n+7);

        wblk[i] = ((p1 << 32) | p2) & LWRD_MAX
    }
}

void schedule512_init(lword wblk[]){
    for(word i=16; i < 80; i++){
        wblk[i] = sig1(wblk[i - 2]) + wblk[i - 7] + sig0(wblk[i - 15]) + wblk[i - 16];
    }
}

void sha35_init(work35 w, word type){
    word h0_len;
    const lword *h0;

    switch(type){
        case 512:
            h0_len = H0_512_LEN;
            h0 = &H0_512[0];
            break;
        case 384:
            h0_len = H0_384_LEN;
            h0 = &H0_384[0];
            break;
        case 256:
            h0_len = H0_512_256_LEN;
            h0 = &H0_512_256[0];
            break;
        case 224:
            h0_len = H0_512_224_LEN;
            h0 = &H0_512_224[0];
            break;
        default:
            return;
    }

    wzero(w)

    w->hval = malloc(h0_len);

    memcpy(w->hval, h0, 8 * h0_len);
}

void sha512_do(work35 w){
    lword a, b, c, d, e, f, g, h;
    lword t1, t2;
    lword blk[S_512_SCHEDULE_LEN];
    word i;

    schedule35_init(blk, w->blk);
    schedule512_init(blk);

    hval_8cpy(w->hval, a, b, c, d, e, f, g, h)

    // printf("a= %llx, b= %llx, c= %llx, d= %llx, e= %llx, f= %llx, g= %llx, h= %llx\n", a, b, c, d, e, f, g, h);

    for(i=0; i < S_512_SCHEDULE_LEN; i++){
        t1 = h + usig1(e) + ch(e, f, g) + K_35xx[i] + blk[i];
        t2 = usig0(a) + maj(a, b, c);

        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;

//        printf("a= %llx, b= %llx, c= %llx, d= %llx, e= %llx, f= %llx, g= %llx, h= %llx\n", a, b, c, d, e, f, g, h);
    }
    hval_8inc(w->hval, a, b, c, d, e, f, g, h)
}

void sha35_update(work35 w, const byte inp[], lword inp_len){
    for(word i=0; i < inp_len; i++){

        w->blk[w->mlen++] = inp[i];

        if(w->mlen == BLK_LEN_35){
            sha512_do(w);
            w->tlen += BLK_LEN_35 * 8;
            w->mlen = 0;
        }
    }
}

void sha35_final(work35 w, byte digest[], word digest_len){
    lword len = w->mlen;
    word up = len < MLEN_BLK_LEN_35;
    word upper = up == 1 ? MLEN_BLK_LEN_35 : BLK_LEN_35;

    w->blk[len++] = 0x80;

    while(len < upper){
        w->blk[len++] = 0x0;
    }

    if(!up){
        sha512_do(w);
        bzero(w->blk, MLEN_BLK_LEN_35);
    }

    w->tlen += 8 * w->mlen;

    lword tmp = w->tlen;
    for(word i=BLK_LEN_35 - 1, n=0; i > MLEN_BLK_LEN_35 - 1; i--, n+=8){
        tmp >>= n;
        w->blk[i] = tmp;
    }

    sha512_do(w);

    word k=0, idx=0;
    while(idx < digest_len){
        for(word j=0, m=56; j < 8; j++, m-=8){
            digest[idx++] = (w->hval[k] >> m) & 0x00000000000000ff;
        }
        k++;
    }
    free(w->hval);
}


