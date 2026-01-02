/* whitelist.c */
#include "whitelist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "logger.h" // LOG_ERR, LOG_INFO makroları için

// Beyaz listedeki süreç isimlerini tutacak global dizi
static char *whitelisted_comms[MAX_WHITELIST_ENTRIES];
static int whitelist_count = 0;

void init_whitelist(const char *whitelist_string) {
    // 1. Güvenlik önlemi: Boş liste kontrolü
    if (whitelist_string == NULL || strlen(whitelist_string) == 0) {
        LOG_INFO("Whitelist (Beyaz Liste) bos. Tum surecler izlenecek.");
        return;
    }

    // 2. String kopyalama (strtok_r orijinal veriyi bozar, kopyası lazım)
    char *temp_str = strdup(whitelist_string);
    if (temp_str == NULL) {
        LOG_ERR("Whitelist icin bellek ayirma hatasi (strdup).");
        return;
    }

    char *token;
    char *saveptr;

    // 3. Ayrıştırma Döngüsü
    whitelist_count = 0;
    for (token = strtok_r(temp_str, ",", &saveptr);
         token != NULL && whitelist_count < MAX_WHITELIST_ENTRIES;
         token = strtok_r(NULL, ",", &saveptr)) {

        // Her token için ayrı yer ayır
        whitelisted_comms[whitelist_count] = strdup(token);
        if (whitelisted_comms[whitelist_count] == NULL) {
            LOG_ERR("Whitelist elemani icin bellek yetersiz.");
            break;
        }
        whitelist_count++;
    }

    LOG_INFO("Whitelist yuklendi. %d guvenli surec haric tutulacak.", whitelist_count);
    free(temp_str); // Geçici kopyayı temizle
}

bool is_whitelisted(const char *comm) {
    if (whitelist_count == 0 || comm == NULL) {
        return false;
    }

    for (int i = 0; i < whitelist_count; i++) {
        // Tam eşleşme kontrolü (örn: "git" == "git")
        if (strcmp(whitelisted_comms[i], comm) == 0) {
            return true;
        }
    }
    return false;
}

void cleanup_whitelist() {
    for (int i = 0; i < whitelist_count; i++) {
        if (whitelisted_comms[i] != NULL) {
            free(whitelisted_comms[i]);
            whitelisted_comms[i] = NULL;
        }
    }
    whitelist_count = 0;
}