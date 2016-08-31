#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>

#include <vdb.h>
#include <debug.h>
#include <param.h>
/*向fd中写入len字节数据，直到完全写入或者出错
 * 才返回。
 * return:实际写入字节数
 */
int write_all(int fd, const void *bufx, int len)
{
    int ret = 0;
    int real_write = 0;
    const char *buf = (const char*)bufx;
    while(len > 0)
    {
        ret = send(fd, buf + real_write, len, 0);
        if(ret <= 0)
        {
            printf("write failed!\n");
            break;
        }
        real_write += ret;
        len -= ret;

    }
    return real_write;
}


/*向fd中读取len字节数据，直到完全读入或者出错
 * 才返回。
 * return:实际读入字节数
 */

int read_all(int fd, void *bufx, int len)
{
    int ret = 0;
    int real_read = 0;
    char *buf = (char*)bufx;
    while(len > 0)
    {
        ret = recv(fd, buf+real_read, len, 0);
        if(ret <= 0)
        {
            DEBUG("read failed!\n");
            break;
        }
        real_read += ret;
        len -= ret;

    }
    return real_read;
}

int send_val(int serfd, struct vdb_packet *vpk, int type, int len, int val)
{
    vpk->type = type;
    vpk->len = len;
    vpk->val = val;
    CHECK_RET(HEADER_LEN+len == write_all(serfd, vpk, HEADER_LEN + len));
    return SUCCESS;
}

int recv_pkt(int serfd, struct vdb_packet *vpk)
{
    CHECK_RET(read_all(serfd, vpk, HEADER_LEN) == HEADER_LEN);
    CHECK_RET(vpk->len <= MAX_DATA_LEN);
    CHECK_RET(read_all(serfd, vpk->data, vpk->len) == vpk->len);
    return SUCCESS;
}

int send_ele(int client_fd, element_t e, int type, struct vdb_packet *vpk)
{
    //send paix
    vpk->type = type;
    vpk->len = element_length_in_bytes_compressed(e);
    CHECK_RET(vpk->len <= ELEMENT_MAX_LEN);
    CHECK_RET(vpk->len == element_to_bytes_compressed(vpk->data, e));
    CHECK_RET(vpk->len + HEADER_LEN == write_all(client_fd, vpk, HEADER_LEN + vpk->len));
    return SUCCESS;
}


