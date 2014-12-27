#include "aes.h"
#include <stdio.h>


int main(int argc, char **argv) {
  int i = 0;
  int j = 0;
  char m[6] = {2, 3, 9, 0xb, 0xd, 0xe};
  for (j=0; j<6; j++) {
    printf("  {");
    for (i=1; i<=0xfe; i++) {
      printf("0x%x, ", gf_mult_calc(m[j], i));
    }
    printf("0x%x", gf_mult_calc(m[j], 0xff));
    if (j == 5) {
      printf("}\n");
    } else {
      printf("},\n");
    }
  }
}

