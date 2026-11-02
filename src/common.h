#ifndef __COMMON_H
#define __COMMON_H

#define MAX_PATH_LEN 200
#define MAX_ARGS_LEN 64

enum event_type {
    EVENT_EXEC,
    EVENT_OPEN
};

struct event_data {
    unsigned int pid;
    unsigned int uid;
    enum event_type type;
    char path[MAX_PATH_LEN];
    char args[MAX_ARGS_LEN];
};

#endif