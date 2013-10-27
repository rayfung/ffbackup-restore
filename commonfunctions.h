#ifndef COMMONFUNCTIONS_H
#define COMMONFUNCTIONS_H

#include <stdio.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <vector>

using namespace std;

char *read_item(const char *item);
char *read_string(SSL *ssl);
void ssl_read_wrapper(SSL *ssl, void *buffer, int num);
void ssl_write_wrapper(SSL *ssl, const void *buffer, int num); 
void get_file_sha1(const char *file, unsigned char *md);
#endif
