#include "timing.h"
#include <time.h>
#include <inttypes.h>

#define SMP 0

// Per-process timing (CLOCK_PROCESS_CPUTIME_ID) is more accurate than absolute
// timing but unsafe for SMP applications because of the possibility of CPU
// migration. The precision of the two timers should be equal (+/- 1ns).
#if SMP
#define CLOCK CLOCK_MONOTONIC
#else
#define CLOCK CLOCK_PROCESS_CPUTIME_ID
#endif

/*
 * Retrieves the approximate cycle count since "the last cpu reset," which
 * often corresponds to the start of the current process.
 *
 * NOTE: Not a precise measure on multicore systems and on modern OSes due to
 * cpu reassignment and hibernation, respectively.
 *
 * NOTE: Using a single 64 bit value and the =A constraint does not seem to
 * work properly on the system tested [gcc (Ubuntu 4.8.2-19ubuntu1) 4.8.2] so
 * edx:eax is constructed using two output arguments.
 */
static inline uint64_t cycle_count() {
    uint64_t ccl, cch;
    asm volatile("rdtsc\n\t" : "=a"(ccl), "=d"(cch));
    return cch<<32 | ccl;
}


/* 
 * Converts a populated timespec struct to the number of nanoseconds it
 * represents.
 */
static inline unsigned long long spec_to_nanos(struct timespec spec) {
  return (1000*1000*1000*spec.tv_sec) + spec.tv_nsec;
}

static unsigned long long start_nanos;
static struct timespec spec;

/*
 * Starts a nanosecond-resolution timer
 */
void start_timing() {
  clock_gettime(CLOCK, &spec);
  start_nanos = spec_to_nanos(spec);
}

/*
 * Returns the number of nanoseconds elapsed since the last call to
 * start_timing()
 */
unsigned long long get_elapsed() {
  clock_gettime(CLOCK, &spec);
  return spec_to_nanos(spec) - start_nanos;
}
