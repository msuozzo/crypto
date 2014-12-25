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
  byte **state = calloc(STATEROWS, sizeof(byte *));
  int i;
  for (i = 0; i < STATEROWS; i++) {
    state[i] = calloc(STATECOLS, sizeof(byte));
  }
  // Generate key schedule
  key_sched = malloc(Nb*(Nr+1) * sizeof(word));
  if (expand_key(key, key_sched, Nk)) {
    goto free_sched;
  }
  for (int j = 0; j < 4*Nb*(Nr+1); j++) {
    printf("%2x", key_sched[j]);
    if ((j-3) % 4 == 0) {
      printf("\n");
    }
  }
  printf("\n");
  // Process each block
  
free_sched:
  free(key_sched);
free_state:
  for (i = 0; i < STATEROWS; i++) {
    free(state[i]);
  }
  free(state);
exit:
  return NULL;
}



byte *decrypt(byte *ciphertext, int ct_length, byte *key, int mode) {
  return NULL;
}
