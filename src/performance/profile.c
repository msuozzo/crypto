#include "profile.h"
#include "alloc.h"
#include "timing.h"
#include <aes.h>
//#include <priv/priv_aes.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TEST_SIZE (1<<20)


int main(int argc, char **argv) {
  int num_trials;
  if (argc != 2 || 0 >= (num_trials = atoi(argv[1]))) {
    fprintf(stderr, "USAGE:  ./profile NumTrials\n");
    return 1;
  }
  return profile_aes(num_trials);
}

/*
 * Unsigned long long comparison function for qsort.
 */
static inline int ull_cmp(const void *a, const void *b) {
  return *((unsigned long long *)a) - *((unsigned long long *)b);
}

/*
 * Calculates the median of a subset of numbers represented in the array arr.
 * This subset is created by removing the outliers, calculated as 1.5*IQR
 * beyond the first and third quartiles.
 */
static unsigned long long get_trimmed_median(unsigned long long *arr,
    size_t num_elements) {
  qsort(arr, num_elements, sizeof(unsigned long long), &ull_cmp);
  unsigned long long first_q = arr[num_elements / 4];
  unsigned long long third_q = arr[3 * num_elements / 4];
  unsigned long long iqr = third_q - first_q;
  size_t start, end;
  for (start = 0; arr[start] < first_q - (1.5 * iqr); start++) ;
  for (end = num_elements - 1; arr[end] > third_q + (1.5 * iqr); end--) ;
  return arr[(start + end) / 2];
}

/*
 * Profiles AES encryption and decryption performance for all key lengths and
 * operation modes. Runs these configurations num_trials times for each input
 * length.
 *
 * num_trials -- Number of times each configuration is run for each input
 * length.
 *
 * On Success: returns 0
 * On Failure: returns 1
 * Outputs trimmed median of each result set.
 *
 * NOTE: The trimmed median statistic is used because of the erratic nature of
 * the timing data. 
 */
int profile_aes(unsigned int num_trials) {
  int i, j, key_len, mode;
  size_t num_bytes = 2 * num_trials * MAX_TEST_SIZE;
  byte *test_bytes = (byte *) get_rand_bytes(num_bytes);
  byte *byte_position;
  byte *enc_output = allocate_output_buffer(MAX_TEST_SIZE, AES_ECB);
  byte *dec_output = allocate_output_buffer(MAX_TEST_SIZE, AES_ECB);
  byte *key = test_bytes;
  unsigned long long *enc_times = calloc(num_trials, sizeof(unsigned long long));
  unsigned long long *dec_times = calloc(num_trials, sizeof(unsigned long long));;
  unsigned long long trimmed_median;
  size_t bytes;
  for (key_len = AES_128; key_len <= AES_256; key_len++) {
    for (mode = AES_ECB; mode <= AES_CBC; mode++) {
      byte_position = test_bytes;
      for (i = 1; i <= MAX_TEST_SIZE; i<<=1) {
        for (j = 0; j < num_trials; j++) {
          start_timing();
          if ((bytes = aes_encrypt(byte_position, i, key, key, key_len, mode, enc_output)) < 0) {
            fprintf(stderr, "Failed\n");
            return 1;
          }
          enc_times[j] = get_elapsed();
          start_timing();
          if (aes_decrypt(enc_output, bytes, key, key, key_len, mode, dec_output) < 0) {
            fprintf(stderr, "Failed\n");
            return 1;
          }
          dec_times[j] = get_elapsed();
          // advance to next random segment
          byte_position += i;
        }
        trimmed_median = get_trimmed_median(enc_times, num_trials);
        printf("0xec, %d, %d, %d, %1.9f\n",
            key_len, mode, i, 1.0*trimmed_median/1000000000.0);
        trimmed_median = get_trimmed_median(dec_times, num_trials);
        printf("0xdc, %d, %d, %d, %1.9f\n",
            key_len, mode, i, 1.0*trimmed_median/1000000000.0);
      }
    }
  }
  free_output_buffer(enc_output);
  free_output_buffer(dec_output);
  free(enc_times);
  free(dec_times);
  free(test_bytes);
  return 0;
}


/*
 * Profiles the random data allocator performance used for testing for various
 * input lengths.
 *
 * num_trials -- Number of times the allocator is run for each input length.
 *
 * On Success: returns 0
 * On Failure: returns 1
 * Outputs trimmed median of each result set.
 *
 * NOTE: The trimmed median statistic is used because of the erratic nature of
 * the timing data. 
 */
int profile_alloc(unsigned int num_trials) {
  int i, j;
  byte *test_bytes;
  unsigned long long elapsed, total;
  for (i = 1; i <= MAX_TEST_SIZE; i<<=1) {
    total = 0;
    for (j = 0; j < num_trials; j++) {
      start_timing();
      test_bytes = (byte *) get_rand_bytes(i);
      elapsed = get_elapsed();
      total += elapsed / num_trials;
      free(test_bytes);
    }
    printf("%d, %1.6f\n", i, 1.0*total/1000000000.0);
    // advance to next random segment
    test_bytes += i;
  }
  return 0;
}
