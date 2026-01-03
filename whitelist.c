/* whitelist.c - O(1) Performance Optimized with uthash */
#include "whitelist.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "logger.h"

// Hash tablosu (Global Başlangıç Noktası)
static struct whitelist_entry *whitelist_head = NULL;

void init_whitelist(const char *whitelist_string) {
    if (whitelist_string == NULL || strlen(whitelist_string) == 0) {
        LOG_INFO("Whitelist bos. Tum surecler izlenecek.");
        return;
    }

    char *temp_str = strdup(whitelist_string);
    if (temp_str == NULL) {
        LOG_ERR("Whitelist bellek hatasi.");
        return;
    }

    char *token;
    char *saveptr;
    int count = 0;

    for (token = strtok_r(temp_str, ",", &saveptr);
         token != NULL;
         token = strtok_r(NULL, ",", &saveptr)) {

        // Hash tablosunda zaten var mı kontrol et (Mükerrer kayıt önleme)
        struct whitelist_entry *s;
        HASH_FIND_STR(whitelist_head, token, s);

        if (s == NULL) {
            s = (struct whitelist_entry*)malloc(sizeof(struct whitelist_entry));
            if (s) {
                strncpy(s->comm, token, sizeof(s->comm) - 1);
                s->comm[sizeof(s->comm) - 1] = '\0';

                // Tabloya ekle (Key: comm alanı)
                HASH_ADD_STR(whitelist_head, comm, s);
                count++;
            }
        }
         }

    LOG_INFO("Whitelist hash tablosu olusturuldu. %d surec yuklendi.", count);
    free(temp_str);
}

bool is_whitelisted(const char *comm) {
    if (whitelist_head == NULL || comm == NULL) {
        return false;
    }

    struct whitelist_entry *s;
    // O(1) Arama - String tabanlı
    HASH_FIND_STR(whitelist_head, comm, s);

    return (s != NULL);
}

void cleanup_whitelist() {
    struct whitelist_entry *current_entry, *tmp;

    HASH_ITER(hh, whitelist_head, current_entry, tmp) {
        HASH_DEL(whitelist_head, current_entry);
        free(current_entry);
    }
    whitelist_head = NULL;
}