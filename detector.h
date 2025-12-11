#ifndef DETECTOR_H
#define DETECTOR_H

#include "state_manager.h"
#include "common.h"

// Not: Eşik değerleri artık config.h üzerinden alınıyor.

void analyze_event(struct process_stats *s, const struct event *e);

#endif // DETECTOR_H