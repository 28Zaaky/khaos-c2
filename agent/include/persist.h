#pragma once
#include <windows.h>

typedef enum {
    PERSIST_REGISTRY = 0,
    PERSIST_SCHTASK  = 1,
} persist_method_t;

int persist_install(persist_method_t method);
int persist_remove(persist_method_t method);
int persist_auto(void);
