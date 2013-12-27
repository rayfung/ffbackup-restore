#include <stdio.h>
#include <arpa/inet.h>
#include <sstream>
#include <algorithm>
#include "helper.h"
#include "ffbuffer.h"

#define FF_LITTLE_ENDIAN 0
#define FF_BIG_ENDIAN 1

const char *CFG_PATH = "/etc/ffbackup/client.cfg";

void dump_data(void *data, size_t size)
{
    unsigned char *ptr = (unsigned char *)data;
    size_t i;
    for(i = 0; i < size; ++i)
        fprintf(stderr, "%02X ", (int)ptr[i]);
}

int get_byte_order()
{
    uint16_t k = 0x0102;
    unsigned char *ptr = (unsigned char *)&k;
    if(ptr[0] == 0x02)
        return FF_LITTLE_ENDIAN;
    else
        return FF_BIG_ENDIAN;
}

uint16_t ntoh16(uint16_t net)
{
    return ntohs(net);
}

uint16_t hton16(uint16_t host)
{
    return htons(host);
}

uint32_t ntoh32(uint32_t net)
{
    return ntohl(net);
}

uint32_t hton32(uint32_t host)
{
    return htonl(host);
}

uint64_t ntoh64(uint64_t net)
{
    uint64_t u = net;
    if(get_byte_order() == FF_LITTLE_ENDIAN)
    {
        uint8_t *ptr_net = (uint8_t *)&net;
        uint8_t *ptr_u = (uint8_t *)&u;
        int i, j;
        for(i = 0, j = 7; i < 8; ++i, --j)
            ptr_u[i] = ptr_net[j];
    }
    return u;
}

uint64_t hton64(uint64_t host)
{
    uint64_t u = host;
    if(get_byte_order() == FF_LITTLE_ENDIAN)
    {
        uint8_t *ptr_host = (uint8_t *)&host;
        uint8_t *ptr_u = (uint8_t *)&u;
        int i, j;
        for(i = 0, j = 7; i < 8; ++i, --j)
            ptr_u[i] = ptr_host[j];
    }
    return u;
}

char *read_string(SSL *ssl)
{
    ffbuffer store;
    char buf[1];
    int ret;
    size_t ffbuffer_length = 0;
    char *pass;
    while(1)
    {
        ret = SSL_read(ssl, buf, 1);
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_write error.\n",stderr);
                exit(1);
        }
        store.push_back(buf,1);
        if(!buf[0])
            break;
    }
    ffbuffer_length = store.get_size();
    pass = (char *)malloc(ffbuffer_length);
    if(!pass)
    {
        fputs("Malloc error.\n",stderr);
        exit(1);
    }
    store.get(pass, 0, ffbuffer_length);
    return pass;
}

void ssl_read_wrapper(SSL *ssl, void *buffer, int num)
{
    int ret = 0;
    int pos = 0;
    char *ptr = (char *)buffer;
    while(pos < num)
    {
        ret = SSL_read(ssl, ptr + pos, num - pos);
        switch( SSL_get_error( ssl, ret ) )
        {
            case SSL_ERROR_NONE:
                break;
            default:
                fputs("SSL_read error.\n",stderr);
                exit(1);
        }
        pos += ret;
    }
}

void ssl_write_wrapper(SSL *ssl, const void *buffer, int num)
{
    int ret;
    ret = SSL_write(ssl, buffer, num);
    switch( SSL_get_error( ssl, ret ) )
    {
        case SSL_ERROR_NONE:
            break;
        default:
            fputs("SSL_write error.\n",stderr);
            exit(1);
    }
}

std::string size2string(size_t size)
{
    std::ostringstream s;

    s << size;
    return s.str();
}

/**
 * 将一个路径以 '/' 为分隔符分割成若干个部分，如果路径以 '/' 开头，那么它会被当成是第一部分
 * 分割后的任何部分都不会再包含 '/'，除非参数是一个绝对路径，此时，第一部分是单个字符 '/'
 *
 * 例子：
 *   "/var/log" -> {"/", "var", "log"}
 *   "history/0/" -> {"history", "0"}
 *   "./cache///patch" -> {".", "cache", "patch"}
 */
std::list<std::string> split_path(const std::string &path)
{
    size_t path_len;
    const char *path_c;
    std::list<std::string> component_list;
    size_t i;
    size_t pos;
    size_t len;
    int state;

    path_len = path.size();
    path_c = path.c_str();

    if(path_c[0] == '/')
        component_list.push_back(std::string("/"));
    state = 0;
    for(i = 0; i <= path_len;)
    {
        char ch = path_c[i];
        switch(state)
        {
        case 0:
            if(ch == '/' || ch == '\0')
            {
                ++i;
                break;
            }
        case 1:
            pos = i;
            len = 0;
            state = 2;
        case 2:
            if(ch == '/' || ch == '\0')
            {
                component_list.push_back(std::string(path_c + pos, len));
                state = 0;
            }
            else
            {
                ++len;
                ++i;
            }
            break;
        }
    }
    return component_list;
}

/**
 * 检查路径是否"安全"
 *
 * 一个"安全"的路径必须满足以下所有条件：
 * 1.路径不为空
 * 2.路径不包含空字符
 * 3.不是绝对路径
 * 4.路径中所有组成部分都不能为 ".." 或者 "."
 *
 */
bool is_path_safe(const std::string &path)
{
    std::list<std::string> component_list;

    if(path.empty())
        return false;
    if(path.find('\0') != std::string::npos)
        return false;

    component_list = split_path(path);
    if(component_list.size() > 0 && component_list.front() == std::string("/"))
        return false;
    if(std::find(component_list.begin(), component_list.end(), std::string(".."))
            != component_list.end())
        return false;
    if(std::find(component_list.begin(), component_list.end(), std::string("."))
            != component_list.end())
        return false;
    return true;
}

/* 检查项目名是否合法 */
bool is_project_name_safe(const char *prj)
{
    if(prj[0] == '\0')
        return false; //项目名称不能为空
    while(prj[0])
    {
        if(prj[0] == '/' || prj[0] == '.')
            return false;
        ++prj;
    }
    return true;
}
