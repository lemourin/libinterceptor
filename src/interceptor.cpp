#include "interceptor.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <sys/mman.h>
#include <unistd.h>
#include <algorithm>
#include <cassert>
#include <cstring>
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

uint mprotect_ptr(uint64_t ptr, uint mask) {
  std::fstream file("/proc/" + std::to_string(getpid()) + "/maps",
                    std::fstream::in);
  std::string line;
  while (std::getline(file, line)) {
    std::stringstream stream(line);
    std::string range, attribs;
    stream >> range >> attribs;
    auto it = range.find_first_of('-');
    uint64_t begin = std::stoull(std::string(range.begin(), range.begin() + it),
                                 nullptr, 16);
    uint64_t end = std::stoull(std::string(range.begin() + it + 1, range.end()),
                               nullptr, 16);
    if (ptr >= begin && ptr < end) {
      uint current = 0;
      if (attribs[0] == 'r') current |= PROT_READ;
      if (attribs[1] == 'w') current |= PROT_WRITE;
      if (attribs[2] == 'x') current |= PROT_EXEC;
      mprotect((void *)begin, end - begin, mask);
      return current;
    }
  }
  return 0;
}

void force_assign(uint64_t address, uint64_t value) {
  auto t = mprotect_ptr(address, PROT_WRITE);
  *((uint64_t *)address) = value;
  mprotect_ptr(address, t);
}

template <class T>
T force_read(uint64_t address) {
  auto t = mprotect_ptr(address, PROT_READ);
  T result = *((T *)address);
  mprotect_ptr(address, t);
  return result;
}

void find_relocation(ElfW(Rela) * relocs, size_t size, dl_phdr_info *info,
                     const relevant_data &r, data *d) {
  for (size_t i = 0; i < size; i++) {
    auto current = relocs + i;
    auto symbol = r.sym_table + ELF64_R_SYM(current->r_info);
    if (r.str_table + symbol->st_name == std::string(d->name)) {
      auto address = (uint64_t)info->dlpi_addr + current->r_offset;
      d->ret_val = (uint64_t)dlsym(RTLD_NEXT, d->name);
      force_assign(address, (uint64_t)d->new_func);
    }
  }
}
}

void *intercept_function(const char *name, void *new_func) {
  data d = {name, new_func};
  dl_iterate_phdr(
      [](dl_phdr_info *info, size_t size, void *ptr) {
        data *d = static_cast<data *>(ptr);
        // std::cout << "library name: " << info->dlpi_name << "\n";
        for (size_t i = 0; i < info->dlpi_phnum; i++) {
          auto segment = info->dlpi_phdr + i;
          if (segment->p_type == PT_DYNAMIC) {
            auto r = extract_data(
                (ElfW(Dyn) *)((char *)info->dlpi_addr + segment->p_vaddr));
            if (r.rela_table) {
              assert(r.rela_size % sizeof(ElfW(Rela)) == 0);
              find_relocation(r.rela_table, r.rela_size / sizeof(ElfW(Rela)),
                              info, r, d);
            }
            if (r.jmprel_table) {
              assert(r.jmprel_size % sizeof(ElfW(Rela)) == 0);
              find_relocation(r.jmprel_table,
                              r.jmprel_size / sizeof(ElfW(Rela)), info, r, d);
            }
            static bool f = false;
            if (r.sym_table && info->dlpi_name != std::string("")) {
              f = true;
              /*for (size_t i = 0; i < 1000; i++) {
                auto current = r.sym_table + i;
                std::cout << r.str_table + current->st_name << " "
                          << (void *)current->st_value << " "
                          << current->st_shndx << "\n";
              } */
            }
          }
        }
        return 0;
      },
      &d);
  if (original_func_addr.find(name) == std::end(original_func_addr)) {
    original_func_addr[name] = (void *)d.ret_val;
    return (void *)d.ret_val;
  } else {
    return original_func_addr[name];
  }
}

void unintercept_function(const char *name) {
  if (original_func_addr.find(name) != std::end(original_func_addr)) {
    intercept_function(name, original_func_addr[name]);
  }
}
