/* common.h */
#ifndef COMMON_H
#define COMMON_H

#define APP_VERSION "0.5.0"

enum event_type {
    EVENT_EXEC = 1,
    EVENT_WRITE = 2,
    EVENT_OPEN = 3,
    EVENT_RENAME = 4,
    EVENT_EXIT = 5
};

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

struct event {
    int type;
    unsigned int pid;            // <--- DÜZELTME BURADA (__u32 -> unsigned int)
    char comm[TASK_COMM_LEN];
    char filename[MAX_FILENAME_LEN];
};

#endif // COMMON_H