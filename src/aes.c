#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


// 4*Nk -> Nb*(Nr+1)
byte *expand_key(byte *key, byte *expansion, int Nk) {
  int Nr = Nk + 6;
  byte *temp_word;
  //byte temp_byte_arr[4] = {0};
  //byte temp_byte;
  int i, j;
  memcpy(expansion, key, 4*Nk); //TODO: err check
//  for (i = 0; i < Nk; i++) {
    //expansion[i] = key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]
//  }
  word temp;
  byte rcon;
  for (i = Nk; i < Nb * (Nr+1); i++) {
    temp_word = expansion + 4*(i-1);
    if (i % Nk == 0) {
      // approximation of multiplication mod 0x011b
      rcon = i/Nk > 8 ? 0x1b<<(i/Nk - 9) : 1<<(i/Nk - 1);
      expansion[4*i] = expansion[4*(i-Nk)] ^ sub_bytes(temp_word[1]) ^ rcon;
      expansion[4*i+1] = expansion[4*(i-Nk)+1] ^ sub_bytes(temp_word[2]);
      expansion[4*i+2] = expansion[4*(i-Nk)+2] ^ sub_bytes(temp_word[3]);
      expansion[4*i+3] = expansion[4*(i-Nk)+3] ^ sub_bytes(temp_word[0]);
      // Possible alternate implementation
//      temp = sub_bytes(temp_word[1]) << 24
//        & sub_bytes(temp_word[2]) << 16
//        & sub_bytes(temp_word[3]) << 8
//        & sub_bytes(temp_word[0]);
//      temp ^= rcon << 24;
    } else if (Nk > 6 && i % Nk == 4) {
      expansion[4*i] = expansion[4*(i-Nk)] ^ sub_bytes(temp_word[0]);
      expansion[4*i+1] = expansion[4*(i-Nk)+1] ^ sub_bytes(temp_word[1]);
      expansion[4*i+2] = expansion[4*(i-Nk)+2] ^ sub_bytes(temp_word[2]);
      expansion[4*i+3] = expansion[4*(i-Nk)+3] ^ sub_bytes(temp_word[3]);
    } else {
      expansion[4*i] = expansion[4*(i-Nk)] ^ temp_word[0];
      expansion[4*i+1] = expansion[4*(i-Nk)+1] ^ temp_word[1];
      expansion[4*i+2] = expansion[4*(i-Nk)+2] ^ temp_word[2];
      expansion[4*i+3] = expansion[4*(i-Nk)+3] ^ temp_word[3];
    }
    //expansion[4*i] = expansion[4*(i-Nk)] ^ temp;
  }
  return NULL;
}


void do_encrypt(byte *sbox, byte *key, int Nr) {
  int r, i, j;
  byte *tmp, *s, *sp;
  // temporary sboxes
  byte tmp_sbox1[16] = {0};
  byte tmp_sbox2[16] = {0};
  s = tmp_sbox1;
  sp = tmp_sbox2;
  // AddRoundKey
  for (i = 0; i < 16; i++)
    s[i] = sbox[i] ^ key[i];
//  for (i = 0; i < 16; i++) {
//    printf("%2x", s[i]);
//    if ((i-3) % 4 == 0)
//      printf("\n");
//  }
//  printf("\n");
  for (r = 1; r < Nr; r++) {
    // SubBytes
    for (i = 0; i < 16; i++)
      s[i] = sub_bytes(s[i]);
//    for (i = 0; i < 16; i++) {
//      printf("%2x", s[i]);
//      if ((i-3) % 4 == 0)
//        printf("\n");
//    }
//    printf("\n");
    // ShiftRows, MixColumns, and AddRoundKey
    sp[0] = gf_mult(0x2, s[0]) ^ gf_mult(0x3, s[5]) ^ s[10] ^ s[15] ^ key[16*r];
    sp[1] = s[0] ^ gf_mult(0x2, s[5]) ^ gf_mult(0x3, s[10]) ^ s[15] ^ key[16*r + 1];
    sp[2] = s[0] ^ s[5] ^ gf_mult(0x2, s[10]) ^ gf_mult(0x3, s[15]) ^ key[16*r + 2];
    sp[3] = gf_mult(0x3, s[0]) ^ s[5] ^ s[10] ^ gf_mult(0x2, s[15]) ^ key[16*r + 3];
    sp[4] = gf_mult(0x2, s[4]) ^ gf_mult(0x3, s[9]) ^ s[14] ^ s[3] ^ key[16*r + 4];
    sp[5] = s[4] ^ gf_mult(0x2, s[9]) ^ gf_mult(0x3, s[14]) ^ s[3] ^ key[16*r + 5];
    sp[6] = s[4] ^ s[9] ^ gf_mult(0x2, s[14]) ^ gf_mult(0x3, s[3]) ^ key[16*r + 6];
    sp[7] = gf_mult(0x3, s[4]) ^ s[9] ^ s[14] ^ gf_mult(0x2, s[3]) ^ key[16*r + 7];
    sp[8] = gf_mult(0x2, s[8]) ^ gf_mult(0x3, s[13]) ^ s[2] ^ s[7] ^ key[16*r + 8];
    sp[9] = s[8] ^ gf_mult(0x2, s[13]) ^ gf_mult(0x3, s[2]) ^ s[7] ^ key[16*r + 9];
    sp[10] = s[8] ^ s[13] ^ gf_mult(0x2, s[2]) ^ gf_mult(0x3, s[7]) ^ key[16*r + 10]; //4f 03 (19)
    sp[11] = gf_mult(0x3, s[8]) ^ s[13] ^ s[2] ^ gf_mult(0x2, s[7]) ^ key[16*r + 11]; //b2 80 (65)
    sp[12] = gf_mult(0x2, s[12]) ^ gf_mult(0x3, s[1]) ^ s[6] ^ s[11] ^ key[16*r + 12];
    sp[13] = s[12] ^ gf_mult(0x2, s[1]) ^ gf_mult(0x3, s[6]) ^ s[11] ^ key[16*r + 13];
    sp[14] = s[12] ^ s[1] ^ gf_mult(0x2, s[6]) ^ gf_mult(0x3, s[11]) ^ key[16*r + 14];
    sp[15] = gf_mult(0x3, s[12]) ^ s[1] ^ s[6] ^ gf_mult(0x2, s[11]) ^ key[16*r + 15];
    tmp = s;
    s = sp;
    sp = tmp;
//    for (i = 0; i < 16; i++) {
//      printf("%2x", s[i]);
//      if ((i-3) % 4 == 0)
//        printf("\n");
//    }
//    printf("\n");
  }
  // SubBytes, ShiftRows, and AddRoundKey
  int shiftedRow;
  for (i = 0; i < 16; i++) {
    shiftedRow = (5*(i%4) + 4*(i/4)) % 16;
    //printf("%d ", shiftedRow);
    sbox[i] = sub_bytes(s[shiftedRow]) ^ key[16*Nr+i];
  }
//  for (i = 0; i < 16; i++) {
//    printf("%2x", sbox[i]);
//    if ((i-3) % 4 == 0)
//      printf("\n");
//  }
//  printf("\n");
}


byte *encrypt(byte *plaintext, int pt_length, byte *key, int mode) {
  // Select Mode and initialize mode-dependent values
  int Nk, Nr;
  byte *key_sched;
  if (mode == 128) {
    Nk = 4;
  } else if (mode == 192) {
    Nk = 6;
  } else if (mode == 256) {
    Nk = 8;
  } else {
    goto exit;
  }
  Nr = Nk + 6;
  // Allocate state array
  byte *state = calloc(STATEROWS * STATECOLS, sizeof(byte *));
  int i;
//  for (i = 0; i < STATEROWS; i++) {
//    state[i] = calloc(STATECOLS, sizeof(byte));
//  }
  // Generate key schedule
  key_sched = malloc(Nb*(Nr+1) * sizeof(word));
  if (expand_key(key, key_sched, Nk)) {
    goto free_sched;
  }
  // Process each block
  for (int j = 0; j < 16; j++) {
    state[j] = plaintext[j];
  }
  do_encrypt(state, key_sched, Nr);
  for (i = 0; i < 16; i++) {
    printf("%2x", state[i]);
    if ((i-3) % 4 == 0)
      printf("\n");
  }
  printf("\n");

  
free_sched:
  free(key_sched);
free_state:
  //for (i = 0; i < STATEROWS; i++) {
  //  free(state[i]);
  //}
  free(state);
exit:
  return NULL;
}



byte *decrypt(byte *ciphertext, int ct_length, byte *key, int mode) {
  return NULL;
}
