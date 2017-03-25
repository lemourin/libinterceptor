#include <cstdio>
#include "interceptor.h"

int my_puts(const char*) {}

int main() { intercept_function("puts", (void*)my_puts); }
