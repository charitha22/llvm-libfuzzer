#include<stdio.h>
// trace-pc-guard-example.cc
void foo() { }
int main(int argc, char **argv) {
  if (argc > 1) foo();
  int a=5, b=10;
  if(a>2){
      if(b>4) printf("Nice!\n");
     
  }
  while(b>4) b--;
}

