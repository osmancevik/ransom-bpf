#include "detector.h"
#include "logger.h"
#include "config.h"  // <--- YENİ EKLENDİ

// Yardımcı fonksiyon: Pencere kontrolü
static void check_window(struct process_stats *s) {
    time_t now = time(NULL);
    // RATE_WINDOW_SEC yerine config.window_sec kullanıyoruz
    if (difftime(now, s->window_start_time) >= config.window_sec) {
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

            // THRESHOLD_WRITE yerine config.write_threshold
            if (s->write_burst > config.write_threshold) {
                LOG_ALARM("FIDYE YAZILIMI SUPHESI (WRITE BURST)! PID: %d (%s) -> %u dosya (Limit: %d)",
                          s->pid, s->comm, s->write_burst, config.write_threshold);
                s->write_burst = 0;
            }
            break;

        case EVENT_RENAME:
            s->rename_burst++;

            // THRESHOLD_RENAME yerine config.rename_threshold
            if (s->rename_burst > config.rename_threshold) {
                LOG_ALARM("FIDYE YAZILIMI SUPHESI (RENAME BURST)! PID: %d (%s) -> %u dosya (Limit: %d)",
                          s->pid, s->comm, s->rename_burst, config.rename_threshold);
                s->rename_burst = 0;
            } else {
                LOG_INFO("[RENAME] PID: %-6d | File: %s", s->pid, e->filename);
            }
            break;

        default:
            break;
    }
}