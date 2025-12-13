// whitelist.h - YENİ DOSYA

#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdbool.h>

// Whitelist için bir üst limit tanımlayın (Örn: En fazla 32 süreç)
#define MAX_WHITELIST_ENTRIES 32

/**
 * @brief Global whitelist string'ini (config'den gelen) parçalar ve arama için hazırlar.
 */
void init_whitelist(const char *whitelist_string);

/**
 * @brief Verilen süreç adının (comm) beyaz listede olup olmadığını kontrol eder.
 *
 * @param comm Kontrol edilecek süreç adı (örn: "apt").
 * @return true Eger süreç beyaz listedeyse.
 */
bool is_whitelisted(const char *comm);

#endif // WHITELIST_H