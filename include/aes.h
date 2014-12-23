#define KEY_LEN 128
#define BLK_LEN 128
#define BLK_BYTES BLK_LEN/4
#define Nb BLK_LEN/32
#define STATEROWS 4
#define STATECOLS Nb


char *encrypt(char *plaintext, int pt_length, char *key, int key_length, int mode);
char *decrypt(char *ciphertext, int ct_length, char *key, int key_length, int mode);
