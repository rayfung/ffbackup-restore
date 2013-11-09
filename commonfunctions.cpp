#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "commonfunctions.h"
#include "ffbuffer.h"
#include "helper.h"

const char *CFG_PATH = "/home/william/git/ffbackup/Restore/client.cfg";

/**
 * read the configuration file
 * cfgFile: the configuration file to read
 * item: the item should be read in the file
 * for example the cfgFile contains:
 * Project = /home/william/Scan
 * Server = localhost
 * the result of the read_item(cfgFile, "Project") return "/home/william/Scan"
 */
char *read_item(const char *item)
{
    const size_t MAX_BUFFER_SIZE = 2048;
    FILE *fp;
    char buffer[MAX_BUFFER_SIZE];
    char *dest, *result;
    if((fp = fopen(CFG_PATH, "r") ) == NULL)
    {
        fputs("Can not open the configue file.\n",stderr);
        return NULL;
    }
    while(fgets(buffer, MAX_BUFFER_SIZE, fp) != NULL)
    {
        if(strncmp(item, buffer, strlen(item))==0)
        {
            dest = strstr(buffer, "=") + 2;
            if((result=(char *)malloc(strlen(dest))) == NULL)
            {
                fputs("Malloc error.\n",stderr);
                fclose(fp);
                return NULL;
            }
            size_t length = strlen(dest);
            memcpy(result, dest, length);
            //result = dest;
            result[length - 1] = '\0';
            fclose(fp);
            return (result);
        }
        continue;
    }
    fclose(fp);
    fputs("Can not find the item\n",stderr);
    return NULL;
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


void get_file_sha1(const char* path, unsigned char *md)
{
    char *project_path = read_item("Path");
    if(!project_path)
    {
        fputs("Read_item error.\n",stderr);
        exit(1);
    }
    if(chdir(project_path) == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }

    int pf = open(path,O_RDONLY);
    if(pf == -1)
    {
        fputs("File can not be open.\n",stderr);
        exit(1);
    }
    if(chdir("..") == -1)
    {
        fputs("Chdir error.\n",stderr);
        exit(1);
    }

    const size_t buffer_size = 2048;
    ssize_t ret;
    unsigned char data[buffer_size];
    SHA_CTX ctx;
    if(SHA1_Init(&ctx) == 0)
    {
        fputs("SHA1_Init error.\n",stderr);
        exit(1);
    }
    while( (ret = read(pf, data, buffer_size)) > 0)
    {
        if(SHA1_Update(&ctx,data,ret) == 0)
        {
            fputs("SHA1_Update error.\n",stderr);
            exit(1);
        }
    }
    if(SHA1_Final(md, &ctx) == 0)
    {
        fputs("SHA1_Final error.\n",stderr);
        exit(1);
    }
    return ;
}

