; // https://artfulcode.wordpress.com/
; // https://github.com/cmovz/
; // License: use it as you wish, just keep this notice. No liability taken.

#include "randomctx.h"
#include "speck.h"
#include <stdio.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>

typedef struct {
  uint32_t a;
  uint32_t b;
  uint32_t c;
  uint32_t d;
} Counter;

int is_number(char const* str)
{
  do {
    if(!isdigit(*str)){
      return 0;
    }
  } while(*++str);
  
  return 1;
}

int str_to_time(char const* str)
{
  int t = 0;
  
  while(*str){
    t *= 10;
    t += *str - '0'; // it's ascii for sure
    ++str;
  }
  
  return t;
}

int main(int argc, char* argv[])
{
  if(argc != 3){
    fprintf(stderr, "Usage: %s file_name 10\n", argv[0]);
    return EXIT_FAILURE;
  }
  
  if(!is_number(argv[2])){
    fprintf(stderr, "Error: '%s' is not a valid time\n", argv[2]);
    return EXIT_FAILURE;
  }
  
  if(strlen(argv[2]) > 6){
    fputs("Error: time is too long, max time is 999999\n", stderr);
    return EXIT_FAILURE;
  }
  
  struct stat st;
  if(-1 == stat(argv[1], &st)){
    perror(argv[1]);
    return EXIT_FAILURE;
  }
  
  int fd = open(argv[1], O_RDONLY);
  if(-1 == fd){
    perror(argv[1]);
    return EXIT_FAILURE;
  }
  
  uint32_t* mem = malloc(st.st_size+3);
  if(!mem){
    perror("malloc()");
    return EXIT_FAILURE;
  }
  
  if(st.st_size != read(fd, mem, st.st_size)){
    perror("Didn't read enough from user file, returned: ");
    return EXIT_FAILURE;
  }
  
  close(fd);
  
  
  unsigned char seed[16];
  int urandom = open("/dev/urandom", O_RDONLY);
  if(16 != read(urandom, seed, 16)){
    perror("Didn't read enough from urandom: ");
    return EXIT_FAILURE;
  }
  close(urandom);
  
  puts("Your seed is:");
  for(int i = 0; i < 16; ++i){
    printf("0x%.2x,", seed[i]);
  }
  putchar('\n');
  
  RandomCtx rctx;
  randomctx_init(&rctx, seed);
  
  time_t end = time(NULL) +  str_to_time(argv[2]);
  int iterations = 0;
  while(time(NULL) < end){
    for(int i = 0; i < 1024; ++i){
      randomctx_update(&rctx);
    }
    iterations += 1024;    
    if(iterations > 2147483647 - 1024){
      fprintf(stderr, "Overflow detected at iterations = %d\n", iterations);
      return EXIT_FAILURE;
    }
  }
  
  printf("did %d iterations\n", iterations);
  
  // now encrypt
  Speck speck;
  speck_init(&speck, rctx.state);
  Counter plain = {0,0,0,0};
  
  for(int i = 0; i < st.st_size; i += 16){
    Counter cipher = plain;
    speck_encrypt(&speck, &cipher);
    
    // xor plaintext with stream
    mem[i/4 + 0] ^= cipher.a;
    mem[i/4 + 1] ^= cipher.b;
    mem[i/4 + 2] ^= cipher.c;
    mem[i/4 + 3] ^= cipher.d;
    
    ++plain.a;
  }
  
  // save cipher blob
  int out = open("cipher_blob", O_WRONLY|O_CREAT|O_TRUNC, 0600);
  if(-1 == out){
    perror("open()");
    return EXIT_FAILURE;
  }
  
  if(st.st_size != write(out, mem, st.st_size)){
    perror("write()");
    return EXIT_FAILURE;
  }
  
  close(out);
  
  return EXIT_SUCCESS;
}
