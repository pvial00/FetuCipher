#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* FETU Cipher */
/* [KryptoMagick 2021] */

struct fetu_state {
     uint64_t w[29];
};

uint64_t rotateleft64(uint64_t a, uint64_t b) {
    return ((a << b) | (a >> (64 - b)));
}

void fetu_F(struct fetu_state *state, int rounds) {
    int i;
    int r;
    uint64_t x;
    uint64_t y[29];
    for (r = 0; r < rounds; r++) {

        for (i = 0; i < 29; i++) {
            y[i] = state->w[i];
        }
        x = state->w[0];

        state->w[0] = state->w[0] + state->w[28];
        state->w[0] = state->w[0] ^ x;
	state->w[0] = (state->w[0] + state->w[5]);
	state->w[0] = rotateleft64(state->w[0], 9);
        
        state->w[1] = state->w[1] + state->w[0];
	state->w[1] = (state->w[1] ^ state->w[3]);
	state->w[1] = rotateleft64(state->w[1], 3);

        state->w[2] = state->w[2] ^ state->w[1];
	state->w[2] = (state->w[2] + state->w[25]);
	state->w[2] = rotateleft64(state->w[2], 13);

        state->w[3] = state->w[3] + state->w[2];
	state->w[3] = (state->w[3] ^ state->w[4]);
	state->w[3] = rotateleft64(state->w[3], 7);

        state->w[4] = state->w[4] ^ state->w[3];
	state->w[4] = (state->w[4] + state->w[21]);
	state->w[4] = rotateleft64(state->w[4], 21);

        state->w[5] = state->w[5] + state->w[4];
	state->w[5] = (state->w[5] ^ state->w[1]);
	state->w[5] = rotateleft64(state->w[5], 12);

        state->w[6] = state->w[6] ^ state->w[5];
	state->w[6] = (state->w[6] + state->w[8]);
	state->w[6] = rotateleft64(state->w[6], 19);

        state->w[7] = state->w[7] + state->w[6];
	state->w[7] = (state->w[7] ^ state->w[16]);
	state->w[7] = rotateleft64(state->w[7], 8);

        state->w[8] = state->w[8] ^ state->w[7];
	state->w[8] = (state->w[8] + state->w[9]);
	state->w[8] = rotateleft64(state->w[8], 9);

        state->w[9] = state->w[9] + state->w[8];
	state->w[9] = (state->w[9] ^ state->w[12]);
	state->w[9] = rotateleft64(state->w[9], 3);

        state->w[10] = state->w[10] ^ state->w[9];
	state->w[10] = (state->w[10] + state->w[23]);
	state->w[10] = rotateleft64(state->w[10], 13);

        state->w[11] = state->w[11] + state->w[10];
	state->w[11] = (state->w[11] ^ state->w[18]);
	state->w[11] = rotateleft64(state->w[11], 7);

        state->w[12] = state->w[12] ^ state->w[11];
	state->w[12] = (state->w[12] + state->w[26]);
	state->w[12] = rotateleft64(state->w[12], 21);

        state->w[13] = state->w[13] + state->w[12];
	state->w[13] = (state->w[13] ^ state->w[27]);
	state->w[13] = rotateleft64(state->w[13], 12);

        state->w[14] = state->w[14] ^ state->w[13];
	state->w[14] = (state->w[14] + state->w[20]);
	state->w[14] = rotateleft64(state->w[14], 19);

        state->w[15] = state->w[15] ^ state->w[14];
	state->w[15] = (state->w[15] + state->w[24]);
	state->w[15] = rotateleft64(state->w[15], 8);

        state->w[16] = state->w[16] ^ state->w[15];
	state->w[16] = (state->w[16] + state->w[17]);
	state->w[16] = rotateleft64(state->w[16], 9);

        state->w[17] = state->w[17] ^ state->w[16];
	state->w[17] = (state->w[17] + state->w[15]);
	state->w[17] = rotateleft64(state->w[17], 3);

        state->w[18] = state->w[18] ^ state->w[17];
	state->w[18] = (state->w[18] + state->w[6]);
	state->w[18] = rotateleft64(state->w[18], 13);

        state->w[19] = state->w[19] ^ state->w[18];
	state->w[19] = (state->w[19] + state->w[22]);
	state->w[19] = rotateleft64(state->w[19], 7);

        state->w[20] = state->w[20] ^ state->w[19];
	state->w[20] = (state->w[20] + state->w[28]);
	state->w[20] = rotateleft64(state->w[20], 21);

        state->w[21] = state->w[21] ^ state->w[20];
	state->w[21] = (state->w[21] + state->w[16]);
	state->w[21] = rotateleft64(state->w[21], 12);

        state->w[22] = state->w[22] ^ state->w[21];
	state->w[22] = (state->w[22] + state->w[3]);
	state->w[22] = rotateleft64(state->w[22], 19);

        state->w[23] = state->w[23] ^ state->w[22];
	state->w[23] = (state->w[23] + state->w[1]);
	state->w[23] = rotateleft64(state->w[23], 8);

        state->w[24] = state->w[24] ^ state->w[23];
	state->w[24] = (state->w[24] + state->w[10]);
	state->w[24] = rotateleft64(state->w[24], 9);

        state->w[25] = state->w[25] ^ state->w[24];
	state->w[25] = (state->w[25] + state->w[7]);
	state->w[25] = rotateleft64(state->w[25], 3);

        state->w[26] = state->w[26] ^ state->w[25];
	state->w[26] = (state->w[26] + state->w[11]);
	state->w[26] = rotateleft64(state->w[26], 13);

        state->w[27] = state->w[27] ^ state->w[26];
	state->w[27] = (state->w[27] + state->w[2]);
	state->w[27] = rotateleft64(state->w[27], 7);

        state->w[28] = state->w[28] ^ state->w[27];
	state->w[28] = (state->w[28] + state->w[19]);
	state->w[28] = rotateleft64(state->w[28], 26);

        }
        for (i = 0; i < 29; i++) {
            state->w[i] = state->w[i] + y[i];
        }
}

void fetu_keysetup(struct fetu_state *state, unsigned char *key, unsigned char *nonce, int rounds) {
    memset(state->w, 0, 29*(sizeof(uint64_t)));
    int i;

    state->w[0] = ((uint64_t)(key[0]) << 56) + ((uint64_t)key[1] << 48) + ((uint64_t)key[2] << 40) + ((uint64_t)key[3] << 32) + ((uint64_t)key[4] << 24) + ((uint64_t)key[5] << 16) + ((uint64_t)key[6] << 8) + (uint64_t)key[7];
    state->w[1] = ((uint64_t)(key[8]) << 56) + ((uint64_t)key[9] << 48) + ((uint64_t)key[10] << 40) + ((uint64_t)key[11] << 32) + ((uint64_t)key[12] << 24) + ((uint64_t)key[5] << 16) + ((uint64_t)key[6] << 8) + (uint64_t)key[7];
    state->w[2] = ((uint64_t)(key[13]) << 56) + ((uint64_t)key[14] << 48) + ((uint64_t)key[15] << 40) + ((uint64_t)key[16] << 32) + ((uint64_t)key[17] << 24) + ((uint64_t)key[18] << 16) + ((uint64_t)key[19] << 8) + (uint64_t)key[20];
    state->w[3] = ((uint64_t)(key[21]) << 56) + ((uint64_t)key[22] << 48) + ((uint64_t)key[23] << 40) + ((uint64_t)key[24] << 32) + ((uint64_t)key[25] << 24) + ((uint64_t)key[26] << 16) + ((uint64_t)key[27] << 8) + (uint64_t)key[28];
    state->w[4] = ((uint64_t)(key[29]) << 56) + ((uint64_t)key[30] << 48) + ((uint64_t)key[31] << 40) + ((uint64_t)key[32] << 32) + ((uint64_t)key[33] << 24) + ((uint64_t)key[34] << 16) + ((uint64_t)key[35] << 8) + (uint64_t)key[36];
    state->w[5] = ((uint64_t)(key[37]) << 56) + ((uint64_t)key[38] << 48) + ((uint64_t)key[39] << 40) + ((uint64_t)key[40] << 32) + ((uint64_t)key[41] << 24) + ((uint64_t)key[42] << 16) + ((uint64_t)key[43] << 8) + (uint64_t)key[44];
    state->w[6] = ((uint64_t)(key[45]) << 56) + ((uint64_t)key[46] << 48) + ((uint64_t)key[47] << 40) + ((uint64_t)key[48] << 32) + ((uint64_t)key[49] << 24) + ((uint64_t)key[50] << 16) + ((uint64_t)key[51] << 8) + (uint64_t)key[52];
    state->w[7] = ((uint64_t)(key[53]) << 56) + ((uint64_t)key[54] << 48) + ((uint64_t)key[55] << 40) + ((uint64_t)key[56] << 32) + ((uint64_t)key[57] << 24) + ((uint64_t)key[58] << 16) + ((uint64_t)key[59] << 8) + (uint64_t)key[60];
    state->w[8] = ((uint64_t)(key[61]) << 56) + ((uint64_t)key[62] << 48) + ((uint64_t)key[63] << 40) + ((uint64_t)key[64] << 32) + ((uint64_t)key[65] << 24) + ((uint64_t)key[66] << 16) + ((uint64_t)key[67] << 8) + (uint64_t)key[68];
    state->w[9] = ((uint64_t)(key[69]) << 56) + ((uint64_t)key[70] << 48) + ((uint64_t)key[71] << 40) + ((uint64_t)key[72] << 32) + ((uint64_t)key[73] << 24) + ((uint64_t)key[74] << 16) + ((uint64_t)key[75] << 8) + (uint64_t)key[76];
    state->w[10] = ((uint64_t)(key[77]) << 56) + ((uint64_t)key[78] << 48) + ((uint64_t)key[79] << 40) + ((uint64_t)key[80] << 32) + ((uint64_t)key[81] << 24) + ((uint64_t)key[82] << 16) + ((uint64_t)key[83] << 8) + (uint64_t)key[84];
    state->w[11] = ((uint64_t)(key[85]) << 56) + ((uint64_t)key[86] << 48) + ((uint64_t)key[85] << 40) + ((uint64_t)key[86] << 32) + ((uint64_t)key[87] << 24) + ((uint64_t)key[88] << 16) + ((uint64_t)key[89] << 8) + (uint64_t)key[90];
    state->w[12] = ((uint64_t)(key[91]) << 56) + ((uint64_t)key[92] << 48) + ((uint64_t)key[93] << 40) + ((uint64_t)key[94] << 32) + ((uint64_t)key[95] << 24) + ((uint64_t)key[96] << 16) + ((uint64_t)key[97] << 8) + (uint64_t)key[98];
    state->w[13] = ((uint64_t)(key[99]) << 56) + ((uint64_t)key[100] << 48) + ((uint64_t)key[101] << 40) + ((uint64_t)key[102] << 32) + ((uint64_t)key[103] << 24) + ((uint64_t)key[104] << 16) + ((uint64_t)key[105] << 8) + (uint64_t)key[106];
    state->w[15] = ((uint64_t)(key[107]) << 56) + ((uint64_t)key[108] << 48) + ((uint64_t)key[109] << 40) + ((uint64_t)key[110] << 32) + ((uint64_t)key[111] << 24) + ((uint64_t)key[112] << 16) + ((uint64_t)key[113] << 8) + (uint64_t)key[114];
    state->w[16] = ((uint64_t)(key[115]) << 56) + ((uint64_t)key[116] << 48) + ((uint64_t)key[117] << 40) + ((uint64_t)key[118] << 32) + ((uint64_t)key[119] << 24) + ((uint64_t)key[120] << 16) + ((uint64_t)key[121] << 8) + (uint64_t)key[122];
    state->w[17] = ((uint64_t)(key[123]) << 56) + ((uint64_t)key[124] << 48) + ((uint64_t)key[125] << 40) + ((uint64_t)key[126] << 32) + ((uint64_t)key[127] << 24) + ((uint64_t)key[128] << 16) + ((uint64_t)key[129] << 8) + (uint64_t)key[130];
    state->w[18] = ((uint64_t)(key[131]) << 56) + ((uint64_t)key[132] << 48) + ((uint64_t)key[133] << 40) + ((uint64_t)key[134] << 32) + ((uint64_t)key[135] << 24) + ((uint64_t)key[136] << 16) + ((uint64_t)key[137] << 8) + (uint64_t)key[138];
    state->w[19] = ((uint64_t)(key[139]) << 56) + ((uint64_t)key[140] << 48) + ((uint64_t)key[141] << 40) + ((uint64_t)key[142] << 32) + ((uint64_t)key[143] << 24) + ((uint64_t)key[144] << 16) + ((uint64_t)key[145] << 8) + (uint64_t)key[146];
    state->w[20] = ((uint64_t)(key[147]) << 56) + ((uint64_t)key[148] << 48) + ((uint64_t)key[149] << 40) + ((uint64_t)key[150] << 32) + ((uint64_t)key[151] << 24) + ((uint64_t)key[152] << 16) + ((uint64_t)key[153] << 8) + (uint64_t)key[154];
    state->w[21] = ((uint64_t)(key[155]) << 56) + ((uint64_t)key[156] << 48) + ((uint64_t)key[157] << 40) + ((uint64_t)key[158] << 32) + ((uint64_t)key[159] << 24) + ((uint64_t)key[160] << 16) + ((uint64_t)key[161] << 8) + (uint64_t)key[162];
    state->w[22] = ((uint64_t)(key[162]) << 56) + ((uint64_t)key[163] << 48) + ((uint64_t)key[164] << 40) + ((uint64_t)key[165] << 32) + ((uint64_t)key[166] << 24) + ((uint64_t)key[167] << 16) + ((uint64_t)key[168] << 8) + (uint64_t)key[169];
    state->w[23] = ((uint64_t)(key[170]) << 56) + ((uint64_t)key[171] << 48) + ((uint64_t)key[172] << 40) + ((uint64_t)key[173] << 32) + ((uint64_t)key[174] << 24) + ((uint64_t)key[175] << 16) + ((uint64_t)key[176] << 8) + (uint64_t)key[177];
    state->w[24] = ((uint64_t)(key[178]) << 56) + ((uint64_t)key[179] << 48) + ((uint64_t)key[180] << 40) + ((uint64_t)key[181] << 32) + ((uint64_t)key[182] << 24) + ((uint64_t)key[183] << 16) + ((uint64_t)key[184] << 8) + (uint64_t)key[185];
    state->w[25] = ((uint64_t)(key[186]) << 56) + ((uint64_t)key[187] << 48) + ((uint64_t)key[188] << 40) + ((uint64_t)key[189] << 32) + ((uint64_t)key[190] << 24) + ((uint64_t)key[191] << 16) + ((uint64_t)key[192] << 8) + (uint64_t)key[193];
    state->w[26] = ((uint64_t)(key[194]) << 56) + ((uint64_t)key[195] << 48) + ((uint64_t)key[196] << 40) + ((uint64_t)key[197] << 32) + ((uint64_t)key[198] << 24) + ((uint64_t)key[199] << 16) + ((uint64_t)key[200] << 8) + (uint64_t)key[201];
    state->w[27] = ((uint64_t)(key[202]) << 56) + ((uint64_t)key[203] << 48) + ((uint64_t)key[204] << 40) + ((uint64_t)key[205] << 32) + ((uint64_t)key[206] << 24) + ((uint64_t)key[207] << 16) + ((uint64_t)key[208] << 8) + (uint64_t)key[209];
   
    state->w[14] = ((uint64_t)nonce[0] << 56) + ((uint64_t)nonce[1] << 48) + ((uint64_t)nonce[2] << 40) + ((uint64_t)nonce[3] << 32) + ((uint64_t)nonce[4] << 24) + ((uint64_t)nonce[5] << 16) + ((uint64_t)nonce[6] << 8) + (uint64_t)nonce[7];
    state->w[28] = ((uint64_t)nonce[8] << 56) + ((uint64_t)nonce[9] << 48) + ((uint64_t)nonce[10] << 40) + ((uint64_t)nonce[11] << 32) + ((uint64_t)nonce[12] << 24) + ((uint64_t)nonce[13] << 16) + ((uint64_t)nonce[14] << 8) + (uint64_t)nonce[15];
    
    for (int i = 0; i < 4; i++) {
        fetu_F(state, rounds);
    }
}

void * fetu_crypt(unsigned char * data, unsigned char * key, unsigned char * nonce, long datalen) {
    struct fetu_state state;
    long c = 0;
    int i;
    int l = 16;
    int rounds = 19;
    uint64_t output;
    int k[16] = {0};
    long blocks = datalen / 16;
    long extra = datalen % 16;
    if (extra != 0) {
        blocks += 1;
    }
    fetu_keysetup(&state, key, nonce, rounds);
    for (long b = 0; b < blocks; b++) {
        fetu_F(&state, rounds);
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
        k[10] = (state.w[10] & 0x0000FF0000000000) >> 40;
        k[11] = (state.w[11] & 0x000000FF00000000) >> 32;
        k[12] = (state.w[12] & 0x00000000FF000000) >> 24;
        k[13] = (state.w[13] & 0x0000000000FF0000) >> 16;
        k[14] = (state.w[14] & 0x000000000000FF00) >> 8;
        k[15] = (state.w[15] & 0x00000000000000FF);
        if (b == (blocks - 1) && (extra != 0)) {
            l = extra;
        }

	for (i = 0; i < l; i++) {
            data[c] = data[c] ^ k[i];
	    c += 1;
	}
    }
}
