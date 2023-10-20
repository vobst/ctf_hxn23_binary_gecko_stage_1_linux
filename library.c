#include <stdio.h>
#include <sys/auxv.h>

__attribute__((constructor))
void init(void)
{
  puts("Hello World");
  printf("Client base at %lx\n", getauxval(AT_ENTRY));
  getchar();
}
