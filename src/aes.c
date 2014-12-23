#include<stdio.h>
#include<stdlib.h>
#include "aes.h"



char *encrypt(char *plaintext, int pt_length, char *key, int key_length, int mode) {
  int Nk, Nr;
  // Select Mode and initialize mode-dependent values
  if (mode == 128) {
    Nk = 4;
    Nr = 10;
  } else if (mode == 192) {
    Nk = 6;
    Nr = 12;
  } else if (mode == 256) {
    Nk = 8;
    Nr = 14;
  } else {
    goto exit;
  } 
  // Allocate state array
  char **state = calloc(STATEROWS, sizeof(char *));
  int i;
  for (i = 0; i < STATEROWS; i++) {
    state[i] = calloc(STATECOLS, sizeof(char));
  }
  // Generate key schedule

  // Process each block
  
free_state:
  for (i = 0; i < STATEROWS; i++) {
    free(state[i]);
  }
  free(state);
exit:
  return NULL;
}




char *decrypt(char *ciphertext, int ct_length, char *key, int key_length, int mode) {
  return NULL;
}
