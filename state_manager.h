#ifndef STATE_MANAGER_H
#define STATE_MANAGER_H

#include <time.h>
#include "uthash.h"
#include "common.h"

struct process_stats {
    int pid;                   // KEY
    char comm[TASK_COMM_LEN];  // Process Name

    // İstatistikler
    unsigned long total_exec_count;
    unsigned long total_write_count;

    // Hız Analizi (H1)
    time_t window_start_time;
    unsigned int write_burst;
    unsigned int rename_burst;

    UT_hash_handle hh;         // uthash handle
};

// Fonksiyon prototipleri
struct process_stats* get_or_create_process(int pid, const char* comm);
void remove_process(int pid);
void cleanup_all_processes();

#endif // STATE_MANAGER_H