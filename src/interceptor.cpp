#include "interceptor.h"

#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <cassert>
#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

namespace {

std::map<std::string, void *> original_func_addr;

struct data {
  const char *name;
  void *new_func;
  uint64_t ret_val;
};

struct relevant_data {
  ElfW(Rela) *jmprel_table = nullptr;
  size_t jmprel_size = 0;
  ElfW(Sym) *sym_table = nullptr;
  size_t sym_entry_size = 0;
  char *str_table = nullptr;
  size_t str_table_size = 0;
  ElfW(Rela) *rela_table = nullptr;
  size_t rela_size = 0;
  uint64_t *plt_table = nullptr;
};

relevant_data extract_data(ElfW(Dyn) * addr) {
  relevant_data d;
  size_t it = 0;
  while (addr[it].d_tag != DT_NULL) {
    auto current = addr + it;
    if (current->d_tag == DT_JMPREL)
      d.jmprel_table = (ElfW(Rela) *)current->d_un.d_ptr;
    else if (current->d_tag == DT_PLTREL)
      assert(current->d_un.d_val == DT_RELA);
    else if (current->d_tag == DT_PLTRELSZ)
      d.jmprel_size = current->d_un.d_val;
    else if (current->d_tag == DT_SYMTAB)
      d.sym_table = (ElfW(Sym) *)current->d_un.d_ptr;
    else if (current->d_tag == DT_SYMENT)
      d.sym_entry_size = current->d_un.d_val;
    else if (current->d_tag == DT_STRTAB)
      d.str_table = (char *)current->d_un.d_ptr;
    else if (current->d_tag == DT_STRSZ)
      d.str_table_size = current->d_un.d_ptr;
    else if (current->d_tag == DT_RELA)
      d.rela_table = (ElfW(Rela) *)current->d_un.d_ptr;
    else if (current->d_tag == DT_RELASZ)
      d.rela_size = current->d_un.d_val;
    else if (current->d_tag == DT_PLTGOT)
      d.plt_table = (uint64_t *)current->d_un.d_ptr;
    it++;
  }
  return d;
}

unsigned long elf_hash(const unsigned char *name) {
  unsigned long h = 0, g;
  while (*name) {
    h = (h << 4) + *name++;
    if (g = h & 0xf0000000) h ^= g >> 24;
    h &= ~g;
  }
  return h;
}

void unlock_memory() {
  std::fstream file("/proc/" + std::to_string(getpid()) + "/maps",
                    std::fstream::in);
  std::string line;
  while (std::getline(file, line)) {
    std::stringstream stream(line);
    std::string range;
    stream >> range;
    auto it = range.find_first_of('-');
    uint64_t begin = std::stoull(std::string(range.begin(), range.begin() + it),
                                 nullptr, 16);
    uint64_t end = std::stoull(std::string(range.begin() + it + 1, range.end()),
                               nullptr, 16);
    mprotect((void *)begin, end - begin, PROT_WRITE | PROT_READ | PROT_EXEC);
  }
}
}

void *intercept_function(const char *name, void *new_func) {
  unlock_memory();
  data d = {name, new_func};
  dl_iterate_phdr(
      [](dl_phdr_info *info, size_t size, void *ptr) {
        data *d = static_cast<data *>(ptr);
        // std::cout << "lib name: << info->dlpi_name << "\n";
        for (size_t i = 0; i < info->dlpi_phnum; i++) {
          auto segment = info->dlpi_phdr + i;
          if (segment->p_type == PT_DYNAMIC) {
            auto r = extract_data(
                (ElfW(Dyn) *)((char *)info->dlpi_addr + segment->p_vaddr));
            if (r.jmprel_table) {
              assert(r.jmprel_size % sizeof(ElfW(Rela)) == 0);
              for (size_t i = 0; i < r.jmprel_size / sizeof(ElfW(Rela)); i++) {
                auto current = r.jmprel_table + i;
                auto symbol = r.sym_table + ELF64_R_SYM(current->r_info);
                if (r.str_table + symbol->st_name == std::string(d->name)) {
                  // std::cout << "puts jmprel " << ELF64_R_SYM(current->r_info)
                  //          << "\n";
                }
              }
            } else {
              // std::cout << "no jmprel table\n";
            }
            if (r.rela_table) {
              assert(r.rela_size % sizeof(ElfW(Rela)) == 0);
              for (size_t i = 0; i < r.rela_size / sizeof(ElfW(Rela)); i++) {
                auto current = r.rela_table + i;
                auto symbol = r.sym_table + ELF64_R_SYM(current->r_info);
                if (r.str_table + symbol->st_name == std::string(d->name)) {
                  auto address = (uint64_t)info->dlpi_addr + current->r_offset;
                  // std::cout << "swapping func " << std::hex << address <<
                  // "\n";
                  d->ret_val = *((uint64_t *)address);
                  *((uint64_t *)address) = (uint64_t)d->new_func;
                }
              }
            }
          }
        }
        return 0;
      },
      &d);
  if (original_func_addr.find(name) == std::end(original_func_addr))
    original_func_addr[name] = (void *)d.ret_val;
  return (void *)d.ret_val;
}

void unintercept_function(const char *name) {
  if (original_func_addr.find(name) != std::end(original_func_addr)) {
    intercept_function(name, original_func_addr[name]);
  }
}
