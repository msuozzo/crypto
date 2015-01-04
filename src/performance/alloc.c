#include "alloc.h"
#include "timing.h"
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <unistd.h>

#define MAX_TEST_SIZE (1<<24)


static char rand_state[256];

static int seed() {
  static int seeded;
  if (seeded)
    return 0;
  int dev_urandom = open("/dev/urandom", O_RDONLY);
  if (dev_urandom < 0) {
    perror("Failed to open /dev/urandom\n");
    return 1;
  }
  size_t bytes = sizeof(unsigned int);
  unsigned int vec;
  size_t data_len = 0;
  while (data_len < bytes) {
    ssize_t bytes_read = read(dev_urandom, ((char *)&vec) + data_len, (bytes - data_len));
    if (bytes_read < 0) {
      perror("Failed to read from /dev/urandom\n");
      return 1;
    }
    data_len += bytes_read;
  }
  close(dev_urandom);
  if (initstate(vec, rand_state, sizeof(rand_state)) == NULL) {
    perror("Failed to initialize rand state\n");
    return 1;
  }
  seeded = 1;
  return 0;
}

void *get_rand_bytes(size_t num_bytes) {
  int i;
  if (seed()) {
    fprintf(stderr, "Seeding failed\n");
    return NULL;
  }
  if (num_bytes == 0) {
    return NULL;
  } else if (num_bytes < 4) {
    unsigned char *ret = malloc(num_bytes);
    long rand = random();
    for (i = 0; i < num_bytes; i++)
      ret[i] = rand >> (i * 8);
    return ret;
  } else {
    long *rand_array = malloc(num_bytes);
    int i;
    for (i = 0; i < num_bytes / sizeof(long); i++)
      rand_array[i] = random();
    return rand_array;
  }
}
