/* whitelist.h */
#ifndef WHITELIST_H
#define WHITELIST_H

#include <stdbool.h>
#include "uthash.h" // Uthash eklendi

// Uthash yapısı için struct tanımı
struct whitelist_entry {
    char comm[16];      // Anahtar (Key) - Süreç Adı
    UT_hash_handle hh;  // Uthash kancası
};

/**
 * @brief Global whitelist string'ini parçalar ve hash tablosuna ekler.
 */
void init_whitelist(const char *whitelist_string);

/**
 * @brief Verilen süreç adının (comm) beyaz listede olup olmadığını kontrol eder.
 * @return true Eğer süreç beyaz listedeyse (O(1) Karmaşıklık).
 */
bool is_whitelisted(const char *comm);

/**
 * @brief Program kapanırken ayrılan belleği temizler.
 */
void cleanup_whitelist();

#endif // WHITELIST_H