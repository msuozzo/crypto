#define KEY_LEN 128
#define BLK_LEN 128
#define Nb BLK_LEN/32


char *encrypt(char *plaintext, int pt_length, char *key, int key_length);
char *decrypt(char *ciphertext, int ct_length, char *key, int key_length);
