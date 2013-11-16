#ifndef HELPER_H
#define HELPER_H

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdint.h>

void dump_data(void *data, size_t size);

uint16_t ntoh16(uint16_t net);

uint16_t hton16(uint16_t host);

uint32_t ntoh32(uint32_t net);

uint32_t hton32(uint32_t host);

uint64_t ntoh64(uint64_t net);

uint64_t hton64(uint64_t host);

char *read_string(SSL *ssl);
void ssl_read_wrapper(SSL *ssl, void *buffer, int num);
void ssl_write_wrapper(SSL *ssl, const void *buffer, int num);

#endif
