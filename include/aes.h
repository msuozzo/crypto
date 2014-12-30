#ifndef AES_H
#define AES_H
#include <stddef.h>
#include <unistd.h>

typedef unsigned char byte;
typedef unsigned int word;
typedef enum {AES_ECB, AES_CBC} aes_mode_t;
typedef enum {AES_128, AES_192, AES_256} aes_key_len_t;

byte *allocate_output_buffer(size_t in_length, aes_mode_t mode);
void free_output_buffer(byte *output_buffer);
ssize_t aes_encrypt(byte *plaintext, size_t pt_length, byte *key, byte *iv, aes_key_len_t key_len, aes_mode_t mode, byte *ct_buffer);
ssize_t aes_decrypt(byte *ciphertext, size_t ct_length, byte *key, byte *iv, aes_key_len_t key_len, aes_mode_t mode, byte *pt_buffer);

#endif
