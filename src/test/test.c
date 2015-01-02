#include "aes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


int hex_to_bin(char *hex_str, byte *output) {
  int i;
  char tmp;
  for (i = 0; i < strlen(hex_str); i++) {
    tmp = tolower(hex_str[i]);
    if (tmp < 58 && tmp >= 48) {
      // digits 0-9
      tmp -= 48;
    } else if (tmp < 103 && tmp >= 97) {
      // lowercase a-f
      tmp -= 87;
    } else {
      return 1;
    }
    if (i % 2 == 0)
      tmp <<= 4;
    output[i/2] |= tmp;
  }
  return 0;
}


int main(int argc, char **argv) {
  // parse args
  char *in_fname = NULL, *out_fname = NULL, *key_hex = NULL, *iv_hex = NULL;
  FILE *in_file = NULL;
  FILE *out_file = NULL;
  aes_mode_t mode;
  aes_key_len_t key_len;
  int key_size;
  char op = 0;  // either e for encrypt or d for decrypt
  int i;
  char *next;
  if (argc <= 1) {
    goto usage;
  }
  for (i = 1; i < argc; i++) {
    if (!strcmp("-e", argv[i]) || !strcmp("-d", argv[i])) {
      if (op) {
        fprintf(stderr,
            "Encryption and decryption flags must be mutually exclusive.\n");
        goto err;
      }
      op = argv[i][1];
    } else if (!strncmp("-aes-", argv[i], 5)) {
      if (strlen(argv[i]) != 12)
        goto invalid_arg;
      if (!strncmp("128", argv[i] + 5, 3)) {
        key_len = AES_128;
        key_size = 16;
      } else if (!strncmp("192", argv[i] + 5, 3)) {
        key_len = AES_192;
        key_size = 24;
      } else if (!strncmp("256", argv[i] + 5, 3)) {
        key_len = AES_256;
        key_size = 32;
      } else {
        goto invalid_arg;
      }
      if (!strncmp("ecb", argv[i] + 9, 3)) {
        mode = AES_ECB;
      } else if (!strncmp("cbc", argv[i] + 9, 3)) {
        mode = AES_CBC;
      } else {
        goto invalid_arg;
      }
    } else {
      if (i == (argc - 1)) {
        fprintf(stderr, "Reached end of flag parsing\n");
        goto invalid_arg;
      }
      next = argv[i + 1];
      if (!strcmp("-in", argv[i])) {
        in_fname = next;
      } else if (!strcmp("-out", argv[i])) {
        out_fname = next;
      } else if (!strcmp("-K", argv[i])) {
        key_hex = next;
      } else if (!strcmp("-iv", argv[i])) {
        iv_hex = next;
      }
      i++;
    }
  }
  // validate args
  if (!key_hex) {
    fprintf(stderr, "Key not supplied\n");
    goto usage;
  }
  // ensure key is correct length
  size_t key_strlen = strlen(key_hex);
  if (key_strlen > key_size*2) {
    fprintf(stderr, "Key incorrect length\n");
    goto usage;
  }
  byte *key = calloc(1, key_size);
  if (hex_to_bin(key_hex, key)) {
    fprintf(stderr, "Error parsing key: ");
    goto invalid_hex;
  }
  // If IV necessary, parse and validate
  int has_iv = mode == AES_CBC;
  byte *iv;
  if (has_iv) {
    if (!iv_hex) {
      fprintf(stderr, "No IV provided\n");
      goto usage;
    }
    iv = calloc(1, 16);
    if (hex_to_bin(iv_hex, iv)) {
      fprintf(stderr, "Error parsing key: ");
      goto invalid_hex;
    }
  }
  // open file handles, default to standard IO streams
  if (!in_fname) {
    in_file = stdin;
  } else if (!(in_file = fopen(in_fname, "rb"))) {
    perror("Failed to open input file");
    goto err;
  }
  if (!out_fname) {
    out_file = stdout;
  } else if (!(out_file = fopen(out_fname, "wb"))) {
    perror("Failed to open output file");
    if (in_file != stdin)
      fclose(in_file);
    goto err;
  }
  // Get input from input file descriptor
  size_t total_read = 0;
  size_t input_capacity = BUFSIZ;
  byte *input = malloc(input_capacity);
  byte *tmp_input;
  size_t bytes_read, expected_bytes;
  while (1) {
    expected_bytes = input_capacity - total_read;
    bytes_read = fread(input + total_read, 1, expected_bytes, in_file);
    total_read += bytes_read;
    if (bytes_read == expected_bytes) {
      input_capacity <<= 1;
      tmp_input = input;
      input = malloc(input_capacity);
      memcpy(input, tmp_input, total_read);
      free(tmp_input);
    } else if (!feof(in_file)) {
      perror("Error reading input file");
      goto free_input;
    } else {
      break;
    }
  }
  // Run enc or dec on input buffer
  byte *output;
  ssize_t bytes_processed;
  output = allocate_output_buffer(total_read, mode);
  if (op == 'e') {
    bytes_processed = aes_encrypt(input, total_read, key, iv, key_len, mode, output);
    if (bytes_processed < 0) {
      fprintf(stderr, "Encryption failed\n");
      goto free_input;
    }
  } else {
    bytes_processed = aes_decrypt(input, total_read, key, iv, key_len, mode, output);
    if (bytes_processed < 0) {
      fprintf(stderr, "Decryption failed\n");
      goto free_input;
    }
  }
  memset(key, 0, key_size);
  free(key);
  if (has_iv) {
    memset(iv, 0, 16);
    free(iv);
  }
  memset(input, 0, input_capacity);
  free(input);

  size_t bytes_written = 0;
  size_t total_written = 0;
  while (total_written != bytes_processed) {
    bytes_written = fwrite(output + total_written, 1,
                            bytes_processed - total_written, out_file);
    total_written += bytes_written;
    if (!bytes_written) {
      if (ferror(out_file)) {
        perror("Error writing to output file.\n");
        goto err;
      } else {
        break;
      }
    }
  }
  free_output_buffer(output);
  // Close file descriptors and exit
  fflush(in_file);
  if (in_file != stdin)
    fclose(in_file);
  fflush(out_file);
  if (out_file != stdout)
    fclose(out_file);
  return 0;

// Error handling
invalid_hex:
  fprintf(stderr, "Invalid hex digit\n");
  goto err;
invalid_arg:
  fprintf(stderr, "Invalid argument: %s\n", argv[i]);
  goto err;
free_input:
  memset(input, 0, input_capacity);
  free(input);
free_iv:
  if (has_iv) {
    memset(iv, 0, 16);
    free(iv);
  }
free_key:
  memset(key, 0, key_size);
  free(key);
  goto err;
usage:
  fprintf(stderr, "Incorrect Usage.\n");
err:
  return 1;
}
