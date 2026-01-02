/* whitelist.h */
#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdbool.h>

// Whitelist için bir üst limit (Bellek güvenliği için)
#define MAX_WHITELIST_ENTRIES 32

/**
 * @brief Global whitelist string'ini (config'den gelen) parçalar ve arama için hazırlar.
 */
void init_whitelist(const char *whitelist_string);

/**
 * @brief Verilen süreç adının (comm) beyaz listede olup olmadığını kontrol eder.
 * @return true Eğer süreç beyaz listedeyse.
 */
bool is_whitelisted(const char *comm);

/**
 * @brief Program kapanırken ayrılan belleği temizler.
 * (Main fonksiyonunda cleanup çağrısı için gereklidir)
 */
void cleanup_whitelist();

#endif // WHITELIST_H