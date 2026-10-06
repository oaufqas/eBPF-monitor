#ifndef __COMMON_H
#define __COMMON_H

#define TASK_COMM_LEN 16
#define MAX_PATH_LEN 256

enum event_type {
    EVENT_EXEC,
    EVENT_OPEN
};

struct event_data {
    unsigned int pid;
    unsigned int uid;
    enum event_type type;
    char comm[TASK_COMM_LEN];
    char path[MAX_PATH_LEN];
};

#endif