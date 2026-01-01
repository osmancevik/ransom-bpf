#ifndef DETECTOR_H
#define DETECTOR_H

#include "state_manager.h"
#include "common.h"

// Not: Eşik değerleri artık config.h üzerinden alınıyor.

/**
 * @brief Olayı analiz eder ve fidye yazılımı belirtisi arar.
 */
void analyze_event(struct process_stats *s, const struct event *e);

/**
 * @brief Verilen dosya adının tuzak dosya (Honeypot) olup olmadığını kontrol eder.
 * @param filename Kontrol edilecek dosya adı
 * @return 1 (True) eğer honeypot ise, 0 (False) değilse.
 */
int is_honeypot_access(const char *filename);

#endif // DETECTOR_H