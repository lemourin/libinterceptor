libinterceptor
==============

Opis rozwiązania
----------------
- przeglądam tablice relokacji `DT_RELA` i `DT_JMPREL` ze wszystkich bibliotek  
  przechodzonych przez `dl_iterate_phdr`
- nadpisuję tablicę `DT_PLTGOT` wykorzystując offsety z tablicy relokacji,  
  przed pisaniem po `DT_PLTGOT` zmieniam uprawnienia do pisania po nim za  
  pomocą `mprotect`
- jako adres nadpisywanego symbolu zwracam wartość funkcji  
  `dlsym(RTLD_NEXT, nazwa_funkcji)`

Budowanie
---------
- `./configure && make`
- plik `libinterceptor.so` powinien powstać w katalogu `src/.libs`

