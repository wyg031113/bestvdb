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

struct vdb_resource *get_vdb_resource(void)
{
    struct vdb_resource *vres = NULL;
    vres = (struct vdb_resource*) malloc(sizeof(struct vdb_resource));
    if(vres == NULL)
        return NULL;
    memset(vres, 0, sizeof(struct vdb_resource));
    return vres;
}
int vdb_init_res(struct vdb_resource *vres, struct vdb_config *pk, int id)
{
    int ret = FAIL;
    CHECK_GO(NULL != (vres->conn_pk = (void*)get_connection(pk->sql_ip, pk->sql_port, pk->sql_user,
                    pk->sql_passwd, pk->sql_dbname)), out);
    CHECK_GO(SUCCESS == get_pk_first(vres->conn_pk, id, &vres->pk), out);
    CHECK_GO(SUCCESS == get_pair(vres->conn_pk, vres->pk.pair_id, &vres->pair), out);
    vres->pair_inited = 1;
    element_init_G1(vres->pair.g, vres->pair.pair);
    vres->g_inited = 1;
    element_init_G1(vres->pk.CR, vres->pair.pair);
    element_init_G1(vres->pk.CT, vres->pair.pair);
    element_init_G1(vres->pk.Y, vres->pair.pair);
    vres->pk_inited = 1;

    element_init_G1(vres->ss.HT, vres->pair.pair);
    element_init_G1(vres->ss.CDTm1, vres->pair.pair);
    element_init_G1(vres->ss.CUT, vres->pair.pair);
    vres->ss_inited = 1;
    element_init_Zr(vres->sk.y, vres->pair.pair);
    ret = SUCCESS;
out:
    return ret;
}

int vdb_client_res_init(struct vdb_resource *vres, struct vdb_config *cli)
{
    int ret = FAIL;
    CHECK_GO(NULL != (vres->conn_data = (void*)get_connection(vres->pk.ip, vres->pk.port, vres->pk.dbuser,
                    vres->pk.dbpassword, vres->pk.dbname)), out);
    CHECK_GO(NULL != (vres->conn_sk = (void*)get_connection(cli->sql_ip, cli->sql_port, cli->sql_user,
                    cli->sql_passwd, cli->sql_dbname)), out);
    ret = SUCCESS;
out:
    return ret;
}

int vdb_server_res_init(struct vdb_resource *vres, struct vdb_config *cli)
{
    int ret = FAIL;
    CHECK_GO(NULL != (vres->conn_data = (void*)get_connection(vres->pk.ip, vres->pk.port, vres->pk.dbuser,
                    vres->pk.dbpassword, vres->pk.dbname)), out);
    CHECK_GO(NULL != (vres->conn_ss = (void*)get_connection(cli->sql_ip, cli->sql_port, cli->sql_user,
                    cli->sql_passwd, cli->sql_dbname)), out);
    ret = SUCCESS;
out:
    return ret;
}
int pk_element_get(struct vdb_resource *res, int id)
{
    int ret = FAIL;
    CHECK_GO(SUCCESS == db_get_ele(res->conn_pk, "vdb_pk", "Y", res->pk.Y, id), out);
    CHECK_GO(SUCCESS == db_get_ele(res->conn_pk, "vdb_pk", "CR", res->pk.CR, id), out);
    CHECK_GO(SUCCESS == db_get_ele(res->conn_pk, "vdb_pk", "CT", res->pk.CT, id), out);
    ret = SUCCESS;
out:
    return ret;
}

int pk_client_init_put(struct vdb_resource *res, int id)
{
    int ret = FAIL;
    CHECK_GO(SUCCESS == db_put_ele(res->conn_pk, "vdb_pk", "Y", res->pk.Y, id), out);
    CHECK_GO(SUCCESS == db_put_int(res->conn_pk, "vdb_pk", "CVerTimes", 0, id), out);
    CHECK_GO(SUCCESS == db_put_int(res->conn_pk, "vdb_pk", "VerTimes", 0, id), out);
    CHECK_GO(SUCCESS == db_put_int(res->conn_pk, "vdb_pk", "VerProg", -1, id), out);
    CHECK_GO(SUCCESS == db_put_str(res->conn_pk, "vdb_pk", "VerStatus", "idle", id), out);
    CHECK_GO(SUCCESS == db_put_str(res->conn_pk, "vdb_pk", "beinited", "inited", id), out);
    ret = SUCCESS;
out:
    return ret;
}
int sk_element_get(struct vdb_resource *res, int id)
{
    int ret = FAIL;
    CHECK_GO(SUCCESS == db_get_ele(res->conn_pk, "vdb_sk", "y", res->sk.y, id), out);
    ret = SUCCESS;
out:
    return ret;
}

int pk_element_put(struct vdb_resource *res, int id)
{
    int ret = FAIL;
    CHECK_GO(SUCCESS == db_put_ele(res->conn_sk, "vdb_pk", "y", res->sk.y, id), out);
    ret = SUCCESS;
out:
    return ret;
}
int ss_element_get(struct vdb_resource *res, int id)
{
    int ret = FAIL;
    CHECK_GO(SUCCESS == db_get_ele(res->conn_ss, "vdb_ss", "HT", res->ss.HT, id), out);
    CHECK_GO(SUCCESS == db_get_ele(res->conn_ss, "vdb_ss", "CDTm1", res->ss.CDTm1, id), out);
    CHECK_GO(SUCCESS == db_get_ele(res->conn_ss, "vdb_ss", "CUT", res->ss.CUT, id), out);
    CHECK_GO(SUCCESS == db_get_int64(res->conn_ss, "vdb_ss", "T", &res->ss.T, id), out);
    ret = SUCCESS;
out:
    return ret;
}

int ss_element_put(struct vdb_resource *res, int id)
{
    int ret = FAIL;
    CHECK_GO(SUCCESS == db_put_ele(res->conn_ss, "vdb_ss", "HT", res->ss.HT, id), out);
    CHECK_GO(SUCCESS == db_put_ele(res->conn_ss, "vdb_ss", "CDTm1", res->ss.CDTm1, id), out);
    CHECK_GO(SUCCESS == db_put_ele(res->conn_ss, "vdb_ss", "CUT", res->ss.CUT, id), out);
    CHECK_GO(SUCCESS == db_put_int64(res->conn_ss, "vdb_ss", "T", res->ss.T, id), out);
    ret = SUCCESS;
out:
    return ret;
}



int vdb_rel_vres(struct vdb_resource *vres)
{
    if(vres->conn_pk)
        release_connection(vres->conn_pk);
    if(vres->conn_sk)
        release_connection(vres->conn_sk);
    if(vres->conn_ss)
        release_connection(vres->conn_ss);
    if(vres->conn_data)
        release_connection(vres->conn_data);
    mysql_thread_end();
    if(vres->pk_inited)
    {
        element_clear(vres->pk.CR);
        element_clear(vres->pk.CT);
        element_clear(vres->pk.Y);
        vres->pk_inited = 0;
    }
    if(vres->sk_inited)
    {
        element_clear(vres->sk.y);
        vres->sk_inited = 0;
    }
    if(vres->ss_inited)
    {
        element_clear(vres->ss.HT);
        element_clear(vres->ss.CDTm1);
        element_clear(vres->ss.CUT);
    }
    if(vres->g_inited)
    {
        element_clear(vres->pair.g);
    }
    if(vres->pair_inited)
    {
        pairing_clear(vres->pair.pair);
    }

}
void free_vdb_resource(struct vdb_resource *vres)
{
    free(vres);
}

