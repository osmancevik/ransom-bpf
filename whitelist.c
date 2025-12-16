#include "whitelist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "logger.h"

// Beyaz listedeki süreç isimlerini tutacak global dizi (Pointer dizisi)
static char *whitelisted_comms[MAX_WHITELIST_ENTRIES];
static int whitelist_count = 0;

/**
 * @brief Beyaz liste stringini parçalar ve bellekten yer ayırarak kaydeder.
 */
void init_whitelist(const char *whitelist_string) {
    if (whitelist_string == NULL || strlen(whitelist_string) == 0) {
        LOG_INFO("Whitelist (Beyaz Liste) bos. Tum surecler kontrol edilecek.");
        return;
    }

    // strtok_r ile çalışmak için stringin değiştirilebilir kopyası gerekir.
    char *temp_str = strdup(whitelist_string);
    if (temp_str == NULL) {
        // DÜZELTME: LOG_ERROR -> LOG_ERR
        LOG_ERR("Whitelist icin bellek ayirma hatasi.");
        return;
    }

    char *token;
    char *saveptr; // strtok_r için gerekli thread-safe pointer

    // Virgül (,) ve boşluk karakterine göre token'lara ayır
    for (token = strtok_r(temp_str, ", ", &saveptr);
         token != NULL && whitelist_count < MAX_WHITELIST_ENTRIES;
         token = strtok_r(NULL, ", ", &saveptr)) {

        // Token'ı kalıcı olarak kaydetmek için tekrar kopyala (strdup)
        whitelisted_comms[whitelist_count] = strdup(token);
        if (whitelisted_comms[whitelist_count] == NULL) {
            // DÜZELTME: LOG_ERROR -> LOG_ERR
            LOG_ERR("Whitelist token'i icin bellek ayirma hatasi.");
            break;
        }
        whitelist_count++;
    }

    LOG_INFO("Whitelist yuklendi. Toplam %d surec haric tutulacak.", whitelist_count);

    // Geçici olarak kullandığımız bellek kopyasını serbest bırak
    free(temp_str);
}

/**
 * @brief Verilen süreç adının beyaz listede olup olmadığını kontrol eder.
 */
bool is_whitelisted(const char *comm) {
    if (whitelist_count == 0) {
        return false;
    }

    // Lineer arama (Küçük bir liste için performansı çok yüksektir)
    for (int i = 0; i < whitelist_count; i++) {
        if (strcmp(whitelisted_comms[i], comm) == 0) {
            return true;
        }
    }

    return false;
}

void cleanup_whitelist() {
    for (int i = 0; i < whitelist_count; i++) {
        if (whitelisted_comms[i] != NULL) {
            free(whitelisted_comms[i]); // strdup ile ayrılan belleği iade et
            whitelisted_comms[i] = NULL;
        }
    }
}