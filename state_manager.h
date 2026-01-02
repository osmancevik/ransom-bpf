/* state_manager.h */
#ifndef STATE_MANAGER_H
#define STATE_MANAGER_H

#include "uthash.h"
#include <time.h>

struct process_stats {
    int pid;                    // Anahtar (Key)
    char comm[16];              // Süreç Adı
    unsigned long total_write_count;
    unsigned long write_burst;
    unsigned long rename_burst;

    time_t window_start_time;   // Pencere başlangıcı
    time_t last_decay_time;     // Son sönümleme zamanı (Task 2.7)

    int current_score;          // Risk Puanı

    UT_hash_handle hh;          // Uthash kancası
};

// Fonksiyon prototipleri
// main.c "get_or_create_process" arıyor olabilir ama biz "get_process_stats" ismini kullanıyoruz.
struct process_stats *get_process_stats(int pid, const char *comm);

// process'i silme fonksiyonu
void remove_process(int pid);

// Program kapanırken tüm belleği temizleyen fonksiyon (Hata 2'nin çözümü)
void cleanup_all_processes();

#endif // STATE_MANAGER_H