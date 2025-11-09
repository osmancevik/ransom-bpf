/*
* common.h: Shared data structures between kernel and user-space
 *
 * This header defines the 'struct event' which is used to pass data
 * from the eBPF program (kernel) to the user-space agent via a ring buffer.
 */

#ifndef COMMON_H
#define COMMON_H

// Define fixed-size arrays for strings
#define TASK_COMM_LEN 16    // Standard Linux process name length
#define MAX_FILENAME_LEN 256 // Maximum file path length to capture

/*
 * struct event
 *
 * The data record is sent from kernel to user-space.
 */
struct event {
    // Process ID
    __u32 pid;

    // Process name (e.g., "ls", "bash")
    char comm[TASK_COMM_LEN];

    // File path being executed (for execve)
    // We will re-use this for other file operations (openat, renameat) later.
    char filename[MAX_FILENAME_LEN];
};

#endif // COMMON_H