#ifndef RESTORE_H
#define RESTORE_H

#include <openssl/ssl.h>
#include <vector>
#include <string>
#include <map>
#include "helper.h"

using namespace std;

typedef struct IDTIME
{
    uint32_t backup_id;
    uint32_t finished_time;
}IDTIME;

void restore_get_prj(SSL *ssl, vector<string> &prj_list);

void restore_get_time_line(SSL *ssl, const char *prj_name, vector<IDTIME> &prj_list);

void restore(SSL *ssl, const char *prj_name, uint32_t backup_id, const char *prj_restore_dir);


#endif
