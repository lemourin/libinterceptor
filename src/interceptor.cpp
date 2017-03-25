#include "interceptor.h"

#include <cstdio>

void *intercept_function(const char *name, void *new_func) {
  printf("intercepting %s\n", name);
}

void unintercept_function(const char *name) {}