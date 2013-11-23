#ifndef RESTORE_H
#define RESTORE_H

#include <openssl/ssl.h>
#include <list>
#include <string>
#include "helper.h"

using namespace std;

typedef struct
{
    uint32_t backup_id;
    uint32_t finish_time;
}history_t;

#endif
