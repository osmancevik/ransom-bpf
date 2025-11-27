/* common.h */
#ifndef COMMON_H
#define COMMON_H

enum event_type {
    EVENT_EXEC = 1,
    EVENT_WRITE = 2,
    EVENT_OPEN = 3,
    EVENT_RENAME = 4  // YENİ: Dosya adı değiştirme
};

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct event {
    int type;
    __u32 pid;
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif // COMMON_H