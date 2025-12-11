#ifndef DETECTOR_H
#define DETECTOR_H

#include "state_manager.h"
#include "common.h"

// Varsayılan Ayarlar (İleride main.c'den parametre olarak alınabilir)
#define RATE_WINDOW_SEC 2
#define THRESHOLD_WRITE 15
#define THRESHOLD_RENAME 5

void analyze_event(struct process_stats *s, const struct event *e);

#endif // DETECTOR_H