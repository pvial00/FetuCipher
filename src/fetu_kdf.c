#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void fetu_KF(struct fetu_state *state) {
    int i;
    int r;
    uint64_t x;
    uint64_t y[29];
    for (i = 0; i < 29; i++) {
        y[i] = state->w[i];
    }
    for (i = 0; i < 29; i++) {
        x = state->w[i];
        state->w[i] = state->w[i] + state->w[(i + 7) & 0x28];
        state->w[i] = state->w[i] - state->w[(i + 4) & 0x28];
        state->w[i] = rotateleft64(state->w[i], 12);
    }
    for (i = 0; i < 29; i++) {
        state->w[i] = state->w[i] ^ y[i];
    }
}

void fetu_kdf_keysetup(struct fetu_state *state, unsigned char *key, rounds) {
    int keylen = 384;
    memset(state->w, 0, 29*(sizeof(uint64_t)));
    int i;
    int m = 0;
    int inc = 8;
    for (i = 0; i < 29; i++) {
        state->w[i] = 0;
    }

    for (i = 0; i < (keylen / 8); i++) {
        state->w[i] = 0;
        state->w[i] = ((uint64_t)(key[m]) << 56) + ((uint64_t)key[m+1] << 48) + ((uint64_t)key[m+2] << 40) + ((uint64_t)key[m+3] << 32) + ((uint64_t)key[m+4] << 24) + ((uint64_t)key[m+5] << 16) + ((uint64_t)key[m+6] << 8) + (uint64_t)key[m+7];
        m += inc;
    }
   
    for (int i = 0; i < 4; i++) {
        fetu_F(state, rounds);
    }
}

void fetu_kdf(unsigned char * key, int keylen, unsigned char * k, int iterations) {
    struct fetu_state state;
    
    int rounds = 42;
    uint64_t output;

    fetu_kdf_keysetup(&state, key, rounds);
    for (long r = 0; r < (rounds * iterations); r++) {
        fetu_KF(&state);
    }

    k[0] = (state.w[0] & 0xFF00000000000000) >> 56;
    k[1] = (state.w[1] & 0x00FF000000000000) >> 48;
    k[2] = (state.w[2] & 0x0000FF0000000000) >> 40;
    k[3] = (state.w[3] & 0x000000FF00000000) >> 32;
    k[4] = (state.w[4] & 0x00000000FF000000) >> 24;
    k[5] = (state.w[5] & 0x0000000000FF0000) >> 16;
    k[6] = (state.w[6] & 0x000000000000FF00) >> 8;
    k[7] = (state.w[7] & 0x00000000000000FF);
    k[8] = (state.w[8] & 0xFF00000000000000) >> 56;
    k[9] = (state.w[9] & 0x00FF000000000000) >> 48;
    k[10] = (state.w[10] & 0x00FF000000000000) >> 40;
    k[11] = (state.w[11] & 0x0000FF0000000000) >> 32;
    k[12] = (state.w[12] & 0x000000FF00000000) >> 24;
    k[13] = (state.w[13] & 0x00000000FF000000) >> 16;
    k[14] = (state.w[14] & 0x0000000000FF0000) >> 8;
    k[15] = (state.w[15] & 0x00000000000000FF);

}
