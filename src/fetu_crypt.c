#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "fetu_cipher.c"
#include "fetu_kdf.c"
#include "reddye.c"

/* FETU Cipher */
/* [KryptoMagick 2021] */

void usage() {
    printf("fetucrypt <encrypt/decrypt> <input file> <output file> <password>\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    FILE *infile, *outfile, *randfile;
    char *in, *out, *mode;
    unsigned char *data = NULL;
    unsigned char *buf = NULL;
    int x = 0;
    int i = 0;
    int ch;
    int buflen = 131072;
    int bsize;
    uint64_t output;
    int keylen = 1728;
    unsigned char key[keylen];
    memset(key, 0, keylen);
    //unsigned char *key[keylen];
    unsigned char *password;
    int nonce_length = 16;
    int itera = 10000;
    unsigned char *salt = "FETUrACipher";
    unsigned char nonce[nonce_length];
    unsigned char block[buflen];
    if (argc != 5) {
        usage();
    }
    mode = argv[1];
    in = argv[2];
    out = argv[3];
    password = argv[4];
    infile = fopen(in, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    outfile = fopen(out, "wb");
    int c = 0;
    if (strcmp(mode, "encrypt") == 0) {
        unsigned char *msg = (unsigned char *)malloc(fsize);
        reddye_random(nonce, nonce_length);
        fwrite(nonce, 1, nonce_length, outfile);
        fetu_kdf(password, strlen(password), key, itera);
        //char digest[keylen*2+1];
        //for (int x = 0; x < keylen; x++) {
        //    sprintf(&digest[x*2], "%02x", key[x]);
        //}
        //printf("%s\n", digest);
        fread(msg, fsize, 1, infile);
        fetu_crypt(msg, key, nonce, fsize);
        fwrite(msg, 1, fsize, outfile);
        free(msg);
    }
    else if (strcmp(mode, "decrypt") == 0) {
        fsize = fsize - nonce_length;
        unsigned char *msg = (unsigned char *)malloc(fsize);
        //unsigned char msg[fsize];
        fread(nonce, 1, nonce_length, infile);
        fetu_kdf(password, strlen(password), key, itera);
        //char digest[keylen*2+1];
        //for (int x = 0; x < keylen; x++) {
        //    sprintf(&digest[x*2], "%02x", key[x]);
        //}
        //printf("%s\n", digest);
        fread(msg, fsize, 1, infile);
        fetu_crypt(msg, key, nonce, fsize);
        fwrite(msg, 1, fsize, outfile);
        free(msg);
    }
    fclose(infile);
    fclose(outfile);
    return 0;
}
