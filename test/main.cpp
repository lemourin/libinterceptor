#include <cmath>
#include <cstdio>
#include <iostream>

#include "interceptor.h"

int my_puts(const char*) {
  std::cout << "krappa\n";
  return 0;
}

int main() {
  puts("kek");
  putchar('\n');
  void* f = intercept_function("puts", (void*)my_puts);
  if (f) {
    ((void (*)(const char*))f)("dupa");
  }
  puts("lol");
  putchar('d');
}
