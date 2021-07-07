#include <stdio.h>

#include "sha/sha.h"
#include "aes/aes.h"

void sha512_test(void){
    char *this = "isabella";

    byte out[S_512_DIGEST_LEN];
    struct sha35_state st;
    work35 w = &st;

    sha512_init(w);
    sha512_update(w, (byte*)this, strlen(this));
    sha512_final(w, out);

    for(byte i=0; i < S_512_DIGEST_LEN; i++){
        printf("%x ", out[i]);
    }
    printf("\n");
}

void sha256_test(char *filename){
    FILE *f = fopen(filename, "r");
    size_t n;

    struct sha12_state st;
    work12 w = &st;

    char in[64];

    byte out[S_256_DIGEST_LEN];

    sha256_init(w);

    while((n = fread(&in, 1, 64, f)) > 0){
        sha256_update(w, (byte*)in, n);
        bzero(in, 64);
    }

    sha256_final(w, out);

    for(byte i=0; i < S_256_DIGEST_LEN; i++){
        printf("%x ", out[i]);
    }
    printf("\n");
}

void aes_ecb_test(char *filename, char *fo, char *back){
    FILE *f = fopen(filename, "r");
    FILE *o = fopen(fo, "w");
    lword f_size;
    size_t n, r;
    char in[16];
    byte out[16];

    const byte key_128[K_128_LEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    word round_key[44];

    const struct key_round kround = {4, 10, 44};
    key_expand(round_key, key_128, &kround);

    lword nblocks = 0;

    printf("\n\nENCRYPT\n\n");

    printf("\e[?25l");

    while((n = fread(&in, 1, 16, f)) > 0){
        cipher((byte*)in, out, round_key, &kround);
        //AES128_ENCRYPT((byte *)in, out, key_128);
        fwrite(&out, 1, 16, o);

        printf("Block %llu ", nblocks);
        for(byte c=0; c < 16; c++) {
            printf("%x ", out[c]);
        }
        printf("\r");
        //fflush(stdout);

        nblocks++;
    }
    fclose(f);
    fclose(o);

    FILE *t = fopen(fo, "r");
    FILE *b = fopen(back, "w");

    printf("\n\nDECRYPT\n\n");

    nblocks = 0;
    while((r = fread(&in, 1, 16, t)) > 0){
        //AES128_DECRYPT((byte *)in, out, key_128);
        cipher_inv((byte*)in, out, round_key, &kround);
        fwrite(&out, 1, 16, b);

        printf("Block %llu ", nblocks);
        for(byte c=0; c < 16; c++){
            printf("%x ", out[c]);
        }
        printf("\r");
        //fflush(stdout);

        nblocks++;
    }
    printf("\e[?25h");


    fclose(o);
    fclose(b);
}

void aes_test(void){
    /*
     const byte key_128[K_128_LEN] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    */

    /*
     const byte key_192[K_192_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
     */

    const byte key_256[K_256_LEN] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

    byte in[BLK_LEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};

    byte out[BLK_LEN];
    byte decrypt_out[BLK_LEN];

    //AES_do(in, out, key_256, 256, 0);
    AES256_ENCRYPT(in, out, key_256);

    //AES_do(out, decrypt_out, key_256, 256, 1);
    AES256_DECRYPT(out, decrypt_out, key_256);

    for(byte i=0; i < BLK_LEN; i++){
        printf("%x ", decrypt_out[i]);
    }
}


int main() {

    //sha512_test();
    //aes_test();

    aes_ecb_test("/Users/sc2135-047/Desktop/NIST.FIPS.180-4.pdf",
                 "/Users/sc2135-047/Desktop/encryptout.txt",
                 "/Users/sc2135-047/Desktop/decrypted.pdf");


}
