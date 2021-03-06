#include "aes.h"
#include "priv/priv_aes.h"
#include <stdio.h>
#include <stdlib.h>


/*
 * Implements the AES key expansion algorithm
 * Converts key of length 4 * Nk to a schedule of 4 * (Nr + 1) words
 */
void expand_key(byte *key, byte *expansion, int Nk) {
  int Nr = Nk + 6;
  byte *temp_word;
  int i;
  for (i = 0; i < 4*Nk; i++)
    expansion[i] = key[i];
  byte rcon;
  for (i = Nk; i < Nb * (Nr+1); i++) {
    temp_word = expansion + 4*(i-1);
    if (i % Nk == 0) {
      // approximation of multiplication mod 0x011b
      // Functions correctly for all possible values in AES key expansion
      rcon = i/Nk > 8 ? 0x1b<<(i/Nk - 9) : 1<<(i/Nk - 1);
      expansion[4*i] = expansion[4*(i-Nk)] ^ sub_bytes(temp_word[1]) ^ rcon;
      expansion[4*i+1] = expansion[4*(i-Nk)+1] ^ sub_bytes(temp_word[2]);
      expansion[4*i+2] = expansion[4*(i-Nk)+2] ^ sub_bytes(temp_word[3]);
      expansion[4*i+3] = expansion[4*(i-Nk)+3] ^ sub_bytes(temp_word[0]);
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
  }
}

/*
 * Implements a single encryption block
 *
 * sbox -- state array initialized to the plaintext of the block
 * key  -- key schedule for encryption of byte-length 4 * Nb * (Nr + 1)
 * Nr   -- number of rounds associated with the key length (e.g. 10, 12, 14)
 *
 * On Success: sbox is populated with ciphertext
 * On Error: No error case
 */
void encrypt_block(byte *sbox, byte *key, int Nr) {
  int r, i;
  byte *tmp, *s, *sp;
  // temporary sboxes
  byte tmp_sbox1[16] = {0};
  byte tmp_sbox2[16] = {0};
  s = tmp_sbox1;
  sp = tmp_sbox2;
  // AddRoundKey
  for (i = 0; i < 16; i++)
    s[i] = sbox[i] ^ key[i];
  for (r = 1; r < Nr; r++) {
    // SubBytes
    for (i = 0; i < 16; i++)
      s[i] = sub_bytes(s[i]);
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
    sp[10] = s[8] ^ s[13] ^ gf_mult(0x2, s[2]) ^ gf_mult(0x3, s[7]) ^ key[16*r + 10];
    sp[11] = gf_mult(0x3, s[8]) ^ s[13] ^ s[2] ^ gf_mult(0x2, s[7]) ^ key[16*r + 11];

    sp[12] = gf_mult(0x2, s[12]) ^ gf_mult(0x3, s[1]) ^ s[6] ^ s[11] ^ key[16*r + 12];
    sp[13] = s[12] ^ gf_mult(0x2, s[1]) ^ gf_mult(0x3, s[6]) ^ s[11] ^ key[16*r + 13];
    sp[14] = s[12] ^ s[1] ^ gf_mult(0x2, s[6]) ^ gf_mult(0x3, s[11]) ^ key[16*r + 14];
    sp[15] = gf_mult(0x3, s[12]) ^ s[1] ^ s[6] ^ gf_mult(0x2, s[11]) ^ key[16*r + 15];
    tmp = s;
    s = sp;
    sp = tmp;
  }
  // SubBytes, ShiftRows, and AddRoundKey
  int shiftedRow;
  for (i = 0; i < 16; i++) {
    shiftedRow = (5*(i%4) + 4*(i/4)) % 16;
    sbox[i] = sub_bytes(s[shiftedRow]) ^ key[16*Nr+i];
  }
}

/*
 * Implements a single decryption block
 *
 * sbox -- state array initialized to the ciphertext of the block
 * key  -- key schedule for decryption of byte-length 4 * Nb * (Nr + 1)
 * Nr   -- number of rounds associated with the key length (e.g. 10, 12, 14)
 *
 * On Success: sbox is populated with decrypted plaintext
 * On Error: No error case
 */
void decrypt_block(byte *sbox, byte *key, int Nr) {
  int r, i, shift_ind;
  byte *tmp, *s, *sp;
  // temporary sboxes
  byte tmp_sbox1[16] = {0};
  byte tmp_sbox2[16] = {0};
  s = tmp_sbox1;
  sp = tmp_sbox2;
  // AddRoundKey
  for (i = 0; i < 16; i++)
    s[i] = sbox[i] ^ key[16*Nr + i];
  for (r = Nr - 1; r >= 1; r--) {
    // InvSubBytes, InvShiftRows, and AddRoundKey
    for (i = 0; i < 16; i++) {
      shift_ind = (i + 16 - (i % 4 * 4)) % 16;
      sp[i] = inv_sub_bytes(s[shift_ind]) ^ key[16*r + i];
    }
    tmp = s;
    s = sp;
    sp = tmp;
    // InvMixColumns
    for (i = 0; i < 16; i++) {
      if (i % 4 == 0)
        sp[i] = gf_mult(0xe, s[i]) ^ gf_mult(0xb, s[i+1]) ^
                gf_mult(0xd, s[i+2]) ^ gf_mult(0x9, s[i+3]);
      else if (i % 4 == 1)
        sp[i] = gf_mult(0x9, s[i-1]) ^ gf_mult(0xe, s[i]) ^
                gf_mult(0xb, s[i+1]) ^ gf_mult(0xd, s[i+2]);
      else if (i % 4 == 2)
        sp[i] = gf_mult(0xd, s[i-2]) ^ gf_mult(0x9, s[i-1]) ^
                gf_mult(0xe, s[i]) ^ gf_mult(0xb, s[i+1]);
      else if (i % 4 == 3)
        sp[i] = gf_mult(0xb, s[i-3]) ^ gf_mult(0xd, s[i-2]) ^
                gf_mult(0x9, s[i-1]) ^ gf_mult(0xe, s[i]);
    }
    tmp = s;
    s = sp;
    sp = tmp;
  }
  // InvSubBytes, InvShiftRows, and AddRoundKey
  for (i = 0; i < 16; i++) {
    shift_ind = (i + 16 - (i % 4 * 4)) % 16;
    sbox[i] = inv_sub_bytes(s[shift_ind]) ^ key[i];
  }
}

/*
 * Allocates buffer of necessary size to hold
 */
byte *allocate_output_buffer(size_t in_length, aes_mode_t mode) {
  return calloc(BLK_BYTES * (1 + in_length / BLK_BYTES), 1);
}

void free_output_buffer(byte *output_buffer) {
  free(output_buffer);
}

/*
 * Implements the AES encryption function
 *
 * plaintext -- byte array to be encrypted
 * pt_length -- length of plaintext in bytes
 * key       -- byte array of encryption key
 * iv        -- initialization vector, ignored if the mode does not require one
 * key_len   -- enum value of the key length in bits (e.g. 128, 192, etc.)
 * mode      -- enum value of the encryption mode (e.g. ECB, CBC, etc.)
 * ct_buffer -- byte array allocated by call to allocate_output_buffer
 *
 * On Success: returns the number of bytes written to ct_buffer
 * On Error: returns -1
 */
ssize_t aes_encrypt(byte *plaintext, size_t pt_length, byte *key, byte *iv,
    aes_key_len_t key_len, aes_mode_t mode, byte *ct_buffer) {
  // Select key length and initialize length-dependent values
  int Nk, Nr;
  byte *key_sched;
  if (key_len == AES_128) {
    Nk = 4;
  } else if (key_len == AES_192) {
    Nk = 6;
  } else if (key_len == AES_256) {
    Nk = 8;
  } else {
    fprintf(stderr, "Unsupported aes_key_len_t provided: %d\n", mode);
    goto exit;
  }
  Nr = Nk + 6;
  // Validate plaintext size
  if (pt_length == 0) {
    fprintf(stderr, "Cannot encrypt 0 bytes\n");
    goto exit;
  }
  // Generate key schedule
  key_sched = malloc(4 * Nb * (Nr+1));
  expand_key(key, key_sched, Nk);
  // Populate output array with plaintext
  // PKCS#7 scheme used for padding -- all padding bytes equal to the number of
  // padding bytes (e.g. ...01, ...02 02, ...03 03 03, ...04 04 04 04, etc.)
  size_t ct_length = BLK_BYTES * (1 + pt_length / BLK_BYTES);
  int i, j;
  for (i = 0; i < pt_length; i++)
    ct_buffer[i] = plaintext[i];
  for (; i < ct_length; i++)
    ct_buffer[i] = ct_length - pt_length;
  // Process each block
  byte *sbox;
  if (mode == AES_ECB) {
    for (i = 0; i < ct_length / BLK_BYTES; i++) {
      sbox = ct_buffer + BLK_BYTES * i;
      encrypt_block(sbox, key_sched, Nr);
    }
  } else if (mode == AES_CBC) {
    byte *prev_block = iv;
    for (i = 0; i < ct_length / BLK_BYTES; i++) {
      sbox = ct_buffer + BLK_BYTES * i;
      for (j = 0; j < 16; j++)
        sbox[j] ^= prev_block[j];
      encrypt_block(sbox, key_sched, Nr);
      prev_block = sbox;
    }
  } else {
    fprintf(stderr, "Unsupported aes_mode_t provided: %d\n", mode);
    goto free_buffers;
  }
  free(key_sched);
  return ct_length;
free_buffers:
  free(key_sched);
exit:
  return -1;
}


/*
 * Implements the AES decryption function
 *
 * ciphertext -- byte array to be decrypted
 * ct_length  -- length of ciphertext in bytes
 * key        -- byte array of encryption key
 * iv         -- initialization vector, ignored if the mode does not require one
 * key_len    -- enum value of the key length in bits (e.g. 128, 192, etc.)
 * mode       -- enum value of the decryption mode (e.g. ECB, CBC, etc.)
 * pt_buffer  -- byte array allocated by call to allocate_output_buffer
 *
 * On Success: returns the number of bytes written to pt_buffer
 * On Error: returns -1
 */
ssize_t aes_decrypt(byte *ciphertext, size_t ct_length, byte *key, byte *iv,
    aes_key_len_t key_len, aes_mode_t mode, byte *pt_buffer) {
  // Select key length and initialize length-dependent values 
  int Nk, Nr;
  byte *key_sched;
  if (key_len == AES_128) {
    Nk = 4;
  } else if (key_len == AES_192) {
    Nk = 6;
  } else if (key_len == AES_256) {
    Nk = 8;
  } else {
    fprintf(stderr, "Unsupported aes_key_len_t provided: %d\n", mode);
    goto exit;
  }
  Nr = Nk + 6;
  // Validate plaintext size
  if (ct_length == 0) {
    fprintf(stderr, "Cannot decrypt 0 bytes\n");
    goto exit;
  }
  // Generate key schedule
  key_sched = malloc(4 * Nb * (Nr+1));
  expand_key(key, key_sched, Nk);
  // Populate output array with ciphertext
  int i, j;
  for (i = 0; i < ct_length; i++)
    pt_buffer[i] = ciphertext[i];
  // Process each block
  byte *sbox;
  if (mode == AES_ECB) {
    for (i = 0; i < ct_length / BLK_BYTES; i++) {
      sbox = pt_buffer + BLK_BYTES * i;
      decrypt_block(sbox, key_sched, Nr);
    }
  } else if (mode == AES_CBC) {
    byte *prev_block = iv;
    for (i = 0; i < ct_length / BLK_BYTES; i++) {
      sbox = pt_buffer + BLK_BYTES * i;
      decrypt_block(sbox, key_sched, Nr);
      for (j = 0; j < 16; j++)
        sbox[j] ^= prev_block[j];
      prev_block = ciphertext + BLK_BYTES * i;
    }
  } else {
    fprintf(stderr, "Unsupported aes_mode_t provided: %d\n", mode);
    goto free_buffers;
  }
  // Validate decryption by stripping padding
  byte padding_bytes = pt_buffer[ct_length - 1];
  if (padding_bytes > BLK_BYTES) {
    goto padding_err;
  }
  for (i = ct_length - 1; i > (ct_length - padding_bytes - 1); i--) {
    if (pt_buffer[i] != padding_bytes) {
      goto padding_err;
    }
    // zero out padding bytes
    pt_buffer[i] = 0;
  }
  free(key_sched);
  return ct_length - padding_bytes;
padding_err:
  fprintf(stderr, "Padding corrupted\n");
free_buffers:
  free(key_sched);
exit:
  return -1;
}
