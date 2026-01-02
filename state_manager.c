/* state_manager.c */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "state_manager.h"
#include "logger.h"

// Hash tablosu (Global)
struct process_stats *processes = NULL;

struct process_stats *get_process_stats(int pid, const char *comm) {
    struct process_stats *s;

    // Hash tablosunda PID'yi ara
    HASH_FIND_INT(processes, &pid, s);

    if (s == NULL) {
        // Yoksa yeni oluştur
        s = (struct process_stats*)malloc(sizeof(struct process_stats));
        if (!s) {
            // Logger header'ına bağlı olarak LOG_WARN veya printf kullanabilirsiniz
            fprintf(stderr, "[WARN] Bellek hatasi (malloc) PID: %d\n", pid);
            return NULL;
        }

        // Alanları doldur
        s->pid = pid;
        strncpy(s->comm, comm, sizeof(s->comm) - 1);
        s->comm[sizeof(s->comm) - 1] = '\0';

        s->total_write_count = 0;
        s->write_burst = 0;
        s->rename_burst = 0;
        s->current_score = 0;

        s->window_start_time = time(NULL);
        s->last_decay_time = time(NULL);

        // Tabloya ekle
        HASH_ADD_INT(processes, pid, s);
    }
    return s;
}

void remove_process(int pid) {
    struct process_stats *s;
    HASH_FIND_INT(processes, &pid, s);
    if (s) {
        HASH_DEL(processes, s);
        free(s);
    }
}

// --- YENİ: Çıkışta temizlik fonksiyonu ---
void cleanup_all_processes() {
    struct process_stats *current_process, *tmp;

    // uthash makrosu: Güvenli iterasyon ile silme
    HASH_ITER(hh, processes, current_process, tmp) {
        HASH_DEL(processes, current_process);
        free(current_process);
    }
}