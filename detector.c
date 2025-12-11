#include "detector.h"
#include "logger.h"

// Yardımcı fonksiyon: Pencere kontrolü
static void check_window(struct process_stats *s) {
    time_t now = time(NULL);
    if (difftime(now, s->window_start_time) >= RATE_WINDOW_SEC) {
        s->window_start_time = now;
        s->write_burst = 0;
        s->rename_burst = 0;
    }
}

void analyze_event(struct process_stats *s, const struct event *e) {
    check_window(s);

    switch (e->type) {
        case EVENT_EXEC:
            s->total_exec_count++;
            LOG_INFO("[EXEC] PID: %-6d | COMM: %s | FILE: %s", s->pid, s->comm, e->filename);
            break;

        case EVENT_WRITE:
            s->total_write_count++;
            s->write_burst++;

            if (s->write_burst > THRESHOLD_WRITE) {
                LOG_ALARM("FIDYE YAZILIMI SUPHESI (WRITE BURST)! PID: %d (%s) -> %u dosya/sn",
                          s->pid, s->comm, s->write_burst);
                s->write_burst = 0; // Alarm spam engellemek için sıfırla
            }
            break;

        case EVENT_RENAME:
            s->rename_burst++;

            if (s->rename_burst > THRESHOLD_RENAME) {
                LOG_ALARM("FIDYE YAZILIMI SUPHESI (RENAME BURST)! PID: %d (%s) -> %u dosya/sn",
                          s->pid, s->comm, s->rename_burst);
                s->rename_burst = 0;
            } else {
                LOG_INFO("[RENAME] PID: %-6d | File: %s", s->pid, e->filename);
            }
            break;

        default:
            break;
    }
}