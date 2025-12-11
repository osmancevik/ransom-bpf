#include <stdlib.h>
#include <string.h>
#include "state_manager.h"
#include "logger.h"

struct process_stats *processes = NULL; // Hash table head

struct process_stats* get_or_create_process(int pid, const char* comm) {
    struct process_stats *s;

    HASH_FIND_INT(processes, &pid, s);
    if (!s) {
        s = (struct process_stats *)malloc(sizeof(struct process_stats));
        if (!s) {
            LOG_ERR("Bellek ayrilamadi! PID: %d", pid);
            return NULL;
        }
        s->pid = pid;
        strncpy(s->comm, comm, TASK_COMM_LEN);
        s->comm[TASK_COMM_LEN - 1] = '\0';

        // Başlangıç değerleri
        s->total_exec_count = 0;
        s->total_write_count = 0;
        s->window_start_time = time(NULL);
        s->write_burst = 0;
        s->rename_burst = 0;

        HASH_ADD_INT(processes, pid, s);
    }
    return s;
}

void remove_process(int pid) {
    struct process_stats *s;
    HASH_FIND_INT(processes, &pid, s);
    if (s) {
        LOG_DEBUG("PID: %d temizleniyor.", pid);
        HASH_DEL(processes, s);
        free(s);
    }
}

void cleanup_all_processes() {
    struct process_stats *current, *tmp;
    HASH_ITER(hh, processes, current, tmp) {
        HASH_DEL(processes, current);
        free(current);
    }
}