#ifndef RESTORE_H
#define RESTORE_H

#include <openssl/ssl.h>
#include <vector>
#include <string>
#include "helper.h"

using namespace std;

typedef struct IDTIME
{
    uint32_t backup_id;
    uint32_t finished_time;
}IDTIME;

#endif
