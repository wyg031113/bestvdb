#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#include <pbc/pbc.h>
#include <debug.h>
#include <config.h>
#include <vdb.h>
#include <param.h>
char listen_ip[17] = "0.0.0.0";
int listen_port = 55555;
int help = 0;
int daem = 0;
const char *config_file = "./vdb_server_conf/vdb_server.conf";
const char *params_dir = "./vdb_server_conf/params";
volatile int stop = 0;
char ss_sql_ip[17] = "127.0.0.1";
int  ss_sql_port = 3306;
char ss_sql_user[64] = "root";
char ss_sql_passwd[64] = "letmein";
char ss_sql_dbname[64] = "vdb_client";

char pk_sql_ip[17] = "127.0.0.1";
int  pk_sql_port = 3306;
char pk_sql_user[64] = "root";
char pk_sql_passwd[64] = "letmein";
char pk_sql_dbname[64] = "vdb_server";


struct config config_table[] =
        {
            {"listen_ip", listen_ip, CFG_STR, 17, "i:", "server listen ip."},
            {"listen_port", &listen_port, CFG_INT, sizeof(int), "p:", "server listen port"},
            {"help", &help, CFG_INT, sizeof(int), "h", "show help."},
            {"daemon", &daem, CFG_INT, sizeof(int), "d:", "-d 0 not daemon, -d 1 daemon"},
            {"ss_sql_ip", ss_sql_ip, CFG_STR, 17, "", "" },
            {"ss_sql_port", &ss_sql_port, CFG_INT, sizeof(int), "", ""},
            {"ss_sql_user", ss_sql_user, CFG_STR, 64, "", "" },
            {"ss_sql_passwd", ss_sql_passwd, CFG_STR, 64, "", "" },
            {"ss_sql_dbname", ss_sql_dbname, CFG_STR, 64, "", "" },
            {"pk_sql_ip", pk_sql_ip, CFG_STR, 17, "", "" },
            {"pk_sql_port", &pk_sql_port, CFG_INT, sizeof(int), "", ""},
            {"pk_sql_user", pk_sql_user, CFG_STR, 64, "", "" },
            {"pk_sql_passwd", pk_sql_passwd, CFG_STR, 64, "", "" },
            {"pk_sql_dbname", pk_sql_dbname, CFG_STR, 64, "", "" },

            {NULL, NULL, 0, 0, "", NULL}
        };
int start_listen(void)
{
    int optval = 1;
    int listen_fd = -1;
    socklen_t len = sizeof(optval);
    struct sockaddr_in ser_addr;
    bzero(&ser_addr, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = inet_addr(listen_ip);
    ser_addr.sin_port = htons(listen_port);

    CHECK(listen_fd=socket(AF_INET, SOCK_STREAM, 0));

    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, len);

    CHECK(bind(listen_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr)));
    CHECK(listen(listen_fd, 5));
    INFO("listen on port:%d\n", listen_port);
    return listen_fd;
}

int calc_send_CR(int client_fd, void *conn_db, struct vdb_pk *pk,
                 struct vdb_pair *pair, struct vdb_packet *vpk,
                 struct vdb_ss *ss)
{
    int i;
    char fhi[MAX_FILE_NAME_LEN];
    FILE *fp = NULL;
    int ret = FAIL;
    int ele_len;
    char ele[ELEMENT_MAX_LEN];

    CHECK_RET(SUCCESS == check_build_path(params_dir, pair->hi_path, fhi));
    CHECK_RET(NULL != (fp = fopen(fhi, "r")));
    element_t hi;
    element_t hv;
    element_t CR;
    mpz_t vi;
    element_init_G1(hi, pair->pair);
    element_init_G1(hv, pair->pair);
    element_init_G1(CR, pair->pair);
    mpz_init(vi);
    ele_len = pairing_length_in_bytes_compressed_G1(pair->pair);
    CHECK_GO(ele_len<ELEMENT_MAX_LEN, out);

    for(i = 0; i < pk->dbsize; i++)
    {
        CHECK_GO(1 == fread(ele, ele_len, 1, fp), out);
        CHECK_GO(ele_len = element_from_bytes_compressed(hi, ele), out);
        element_printf("h[%d] = %B\n", i, hi);
        CHECK_GO(SUCCESS == db_getv(conn_db, pk->dbtable, i, vi), out);
        element_pow_mpz(hv, hi, vi);
        if(i == 0)
            element_set(CR, hv);
        else
            element_mul(CR, CR, hv);
    }
    element_printf("Init CR=%B\n", CR);
    ele_len = element_length_in_bytes_compressed(CR);
    CHECK_GO(ele_len < MAX_DATA_LEN, out);
    element_to_bytes_compressed(vpk->data, CR);
    vpk->type = T_I_CR;
    vpk->len = ele_len;
    CHECK_GO(HEADER_LEN + vpk->len == write_all(client_fd, vpk, HEADER_LEN + vpk->len), out);
    element_init_G1(pk->CR, pair->pair);
    element_init_G1(ss->CDTm1, pair->pair);
    element_init_G1(ss->CUT, pair->pair);
    element_set(pk->CR, CR);
    element_set(ss->CDTm1, CR);
    element_set(ss->CUT, CR);
    ret = SUCCESS;
out:
    mpz_clear(vi);
    element_clear(CR);
    element_clear(hv);
    element_clear(hi);
    fclose(fp);
    return ret;
}
int handle_init(int client_fd, struct vdb_packet *vpk)
{
    int id;
    int size;
    void *conn_pk = NULL;
    void *conn_ss = NULL;
    void *conn_db = NULL;
    struct vdb_pk *pk = NULL;
    struct vdb_ss *ss = NULL;
    struct vdb_pair *pair = NULL;
    int pair_inited = FAIL;
    int cr_suc = FAIL;
    int ct_suc = FAIL;
    int ht_suc = FAIL;
    FILE *fp = NULL;
    int ret = FAIL;
    DEBUG("Handle init.\n");
    //begin init
    CHECK_GO(SUCCESS == recv_pkt(client_fd, vpk) && vpk->type == T_I_ID, out);
    id = vpk->val;
    DEBUG("Init id is:%d\n", id);

    CHECK_GO(NULL != (pk = (struct vdb_pk *)malloc(sizeof(struct vdb_pk))), out);
    CHECK_GO (NULL != (ss = (struct vdb_ss *)malloc(sizeof(struct vdb_ss))), out);
    CHECK_GO (NULL != (pair = (struct vdb_pair*)malloc(sizeof(struct vdb_pair))),out);
    memset(pk, 0, sizeof(struct vdb_pk));
    memset(ss, 0, sizeof(struct vdb_ss));
    memset(pair,0,sizeof(struct vdb_pair));
    CHECK_GO(NULL != (conn_pk = (void*)get_connection(pk_sql_ip, pk_sql_port,
                                               pk_sql_user, pk_sql_passwd,
                                               pk_sql_dbname)), out);
    //get public key from database, dbsize in it
    CHECK_GO(SUCCESS == get_pk_first(conn_pk, id, pk), out);
    //get pair from database
    CHECK_GO(SUCCESS == get_pair(conn_pk, pk->pair_id, pair), out);
    pair_inited = SUCCESS;
    CHECK_GO(NULL != (conn_db = (void*)get_connection(pk->ip, pk->port, pk->dbuser,
                                               pk->dbpassword, pk->dbname)), out);

    //calc CR and build C-1 CU0 in ss
    CHECK_GO(SUCCESS == calc_send_CR(client_fd, conn_db, pk, pair, vpk, ss), out);
    cr_suc = SUCCESS;
    //recv H0, calc C0, set T=0
    CHECK_GO(SUCCESS == recv_pkt(client_fd, vpk) && vpk->type == T_I_H0, out);
    CHECK_GO(vpk->len == pairing_length_in_bytes_compressed_G1(pair->pair), out);
    element_init_G1(ss->HT, pair->pair);
    ht_suc = SUCCESS;
    CHECK_GO(element_from_bytes_compressed(ss->HT, vpk->data) == vpk->len, out);
    element_init_G1(pk->CT, pair->pair);
    element_mul(pk->CT, ss->HT, ss->CUT);
    ss->T = 0;
    ct_suc = SUCCESS;
    CHECK_GO(SUCCESS == db_put_ele(conn_pk, "vdb_pk", "CR", pk->CR, id), out);
    CHECK_GO(SUCCESS == db_put_ele(conn_pk, "vdb_pk", "CT", pk->CT, id), out);
    CHECK_GO(NULL != (conn_ss = (void*)get_connection(ss_sql_ip, ss_sql_port,
                                               ss_sql_user, ss_sql_passwd,
                                               ss_sql_dbname)), out);

    CHECK_GO(SUCCESS == db_put_ele(conn_ss, "vdb_s", "HT", ss->HT, id), out);
    CHECK_GO(SUCCESS == db_put_ele(conn_ss, "vdb_s", "CUT", ss->CUT, id), out);
    CHECK_GO(SUCCESS == db_put_ele(conn_ss, "vdb_s", "CDTm1", ss->CDTm1, id), out);
    CHECK_GO(SUCCESS == db_put_int64(conn_ss, "vdb_s", "T", ss->T, id), out);
    CHECK_GO(SUCCESS == send_val(client_fd, vpk, T_I_SFINISH, 0, 0), out);
    CHECK_GO(SUCCESS == recv_pkt(client_fd, vpk) && vpk->type == T_I_CFINISH, out);
    ret = SUCCESS;
out:
    if(ct_suc == SUCCESS)       element_clear(pk->CT);
    if(ht_suc == SUCCESS)       element_clear(ss->HT);
    if(cr_suc == SUCCESS)
    {
        element_clear(pk->CR);
        element_clear(ss->CDTm1);
        element_clear(ss->CUT);
    }
    if(conn_ss)                     release_connection(conn_ss);
    if(conn_db)                     release_connection(conn_db);
    if(pair_inited == SUCCESS)      pairing_clear(pair->pair);
    if(conn_pk)                     release_connection(conn_pk);
    if(pair)                        free(pair);
    if(ss)                          free(ss);
    if(pk)                          free(pk);
    return ret;

}
int calc_paix(element_t paix, void *conn, struct vdb_pk *pk, struct vdb_pair *pair, int x)
{
    char fhij[MAX_FILE_NAME_LEN];
    char ele[ELEMENT_MAX_LEN];
    FILE *fp = NULL;
    int ele_len;
    int j;
    mpz_t v;
    element_t hij;
    element_t hv;
    int ret = FAIL;
    int flag = 0;
    DEBUG("calculate proof pai...\n");
    ele_len = pairing_length_in_bytes_compressed_G1(pair->pair);
    CHECK_RET(ele_len <= ELEMENT_MAX_LEN);
    CHECK_RET(SUCCESS == check_build_path(params_dir, pair->hij_path, fhij));
    CHECK_RET(NULL != (fp = fopen(fhij, "r")));
    element_init_G1(hij, pair->pair);
    element_init_G1(hv, pair->pair);
    mpz_init(v);

    for(j = 0; j < pk->dbsize; j++)
    {
        int a;
        int b;
        if(j == x)
            continue;
        if(x > j)
        {
            a = x;
            b = j;
        }
        else
        {
            a = j;
            b = x;
        }
        CHECK_GO(0 == fseek(fp, ele_len * ((uint64)a *((uint64)a-1)/2+(uint64)b), SEEK_SET), out);
        CHECK_GO(1 == fread(ele, ele_len, 1, fp), out);
        CHECK_GO(ele_len = element_from_bytes_compressed(hij, ele), out);
        element_printf("h[%d][%d]=%B\n", x, j, hij);
        CHECK_GO(SUCCESS == db_getv(conn, pk->dbtable, j, v), out);
        element_pow_mpz(hv, hij, v);
        if(flag == 0)
            element_set(paix, hv);
        else
            element_mul(paix, paix, hv);
        flag = 1;

    }
    ret = SUCCESS;
out:
    mpz_clear(v);
    element_clear(hv);
    element_clear(hij);
    fclose(fp);
    return ret;
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
int send_proof(int client_fd, element_t paix, struct vdb_pair *pair,
               struct vdb_ss *ss, int x, struct vdb_packet *vpk)
{
    char fhi[MAX_FILE_NAME_LEN];
    FILE *fp = NULL;
    int ret = FAIL;
    char ele[ELEMENT_MAX_LEN];
    int ele_len = 0;
    element_t hi;
    DEBUG("Sending proof\n");
    CHECK_RET(SUCCESS == check_build_path(params_dir, pair->hi_path, fhi));
    //send paix Ht CDTm1
    CHECK_RET(SUCCESS == send_ele(client_fd, paix, T_Q_PAIX, vpk));
    CHECK_RET(SUCCESS == send_ele(client_fd, ss->HT, T_Q_HT, vpk));
    CHECK_RET(SUCCESS == send_ele(client_fd, ss->CDTm1, T_Q_CDTm1, vpk));
    CHECK_RET(SUCCESS == send_ele(client_fd, ss->CUT, T_Q_CUT, vpk));

    //send hi
    CHECK_RET(NULL != (fp = fopen(fhi, "r")));
    element_init_G1(hi, pair->pair);
    ele_len = pairing_length_in_bytes_compressed_G1(pair->pair);
    CHECK_GO(ele_len <= ELEMENT_MAX_LEN, out);
    CHECK_GO(0 == fseek(fp, (uint64)x*(uint64)ele_len, SEEK_SET), out);
    CHECK_GO(1 == fread(ele, ele_len, 1, fp), out);
    CHECK_GO(ele_len == element_from_bytes_compressed(hi, ele), out);
    CHECK_GO(SUCCESS == send_ele(client_fd, hi, T_Q_HX, vpk), out);

    //send T
    vpk->type = T_Q_T;
    vpk->len = sizeof(ss->T);
    memcpy(vpk->data, &ss->T, sizeof(ss->T));
    CHECK_GO(write_all(client_fd, vpk, HEADER_LEN + vpk->len) == HEADER_LEN + vpk->len, out);
    ret = SUCCESS;
out:
    element_clear(hi);
    fclose(fp);
    return ret;

}
int handle_query(int client_fd, struct vdb_packet *vpk)
{
    int id;
    int size;
    int x;
    void *conn_pk = NULL;
    void *conn_ss = NULL;
    void *conn_db = NULL;
    struct vdb_pk *pk = NULL;
    struct vdb_ss *ss = NULL;
    struct vdb_pair *pair = NULL;
    element_t paix;
    int pai_inited = FAIL;
    int pair_inited = FAIL;
    int hcc_suc = FAIL;
    FILE *fp = NULL;
    int ret = FAIL;
    DEBUG("Handle verify.\n");
    //begin init
    CHECK_GO(SUCCESS == recv_pkt(client_fd, vpk) && vpk->type == T_Q_ID, out);
    id = vpk->val;
    CHECK_GO(SUCCESS == recv_pkt(client_fd, vpk) && vpk->type == T_Q_X, out);
    x = vpk->val;
    DEBUG("verify id is:%d x is:%d\n", id, x);

    CHECK_GO(NULL != (pk = (struct vdb_pk *)malloc(sizeof(struct vdb_pk))), out);
    CHECK_GO (NULL != (ss = (struct vdb_ss *)malloc(sizeof(struct vdb_ss))), out);
    CHECK_GO (NULL != (pair = (struct vdb_pair*)malloc(sizeof(struct vdb_pair))),out);
    memset(pk, 0, sizeof(struct vdb_pk));
    memset(ss, 0, sizeof(struct vdb_ss));
    memset(pair,0,sizeof(struct vdb_pair));
    CHECK_GO(NULL != (conn_pk = (void*)get_connection(pk_sql_ip, pk_sql_port,
                                               pk_sql_user, pk_sql_passwd,
                                               pk_sql_dbname)), out);
    //get public key from database, dbsize in it
    CHECK_GO(SUCCESS == get_pk_first(conn_pk, id, pk), out);
    //get pair from database
    CHECK_GO(SUCCESS == get_pair(conn_pk, pk->pair_id, pair), out);
    pair_inited = SUCCESS;
    element_init_G1(paix, pair->pair);
    pai_inited = SUCCESS;
    CHECK_GO(NULL != (conn_db = (void*)get_connection(pk->ip, pk->port, pk->dbuser,
                                               pk->dbpassword, pk->dbname)), out);

    CHECK_GO(NULL != (conn_ss = (void*)get_connection(ss_sql_ip, ss_sql_port,
                                               ss_sql_user, ss_sql_passwd,
                                               ss_sql_dbname)), out);
    element_init_G1(ss->HT, pair->pair);
    element_init_G1(ss->CUT, pair->pair);
    element_init_G1(ss->CDTm1, pair->pair);
    hcc_suc = SUCCESS;
    CHECK_GO(SUCCESS == db_get_ele(conn_ss, "vdb_s", "HT", ss->HT, id), out);
    CHECK_GO(SUCCESS == db_get_ele(conn_ss, "vdb_s", "CUT", ss->CUT, id), out);
    CHECK_GO(SUCCESS == db_get_ele(conn_ss, "vdb_s", "CDTm1", ss->CDTm1, id), out);
    CHECK_GO(SUCCESS == db_get_int64(conn_ss, "vdb_s", "T", &ss->T, id), out);

    CHECK_GO(NULL != (conn_ss = (void*)get_connection(ss_sql_ip, ss_sql_port,
                                               ss_sql_user, ss_sql_passwd,
                                               ss_sql_dbname)), out);
    CHECK_GO(SUCCESS == calc_paix(paix, conn_db, pk, pair, x), out);
    CHECK_GO(SUCCESS == send_proof(client_fd, paix, pair, ss, x, vpk), out);
    CHECK_GO(SUCCESS == send_val(client_fd, vpk, T_Q_SFINISH, 0, 0), out);
    CHECK_GO(SUCCESS == recv_pkt(client_fd, vpk) && vpk->type == T_Q_CFINISH, out);
    ret = SUCCESS;
out:
    if(hcc_suc == SUCCESS)
    {
        element_clear(ss->HT);
        element_clear(ss->CDTm1);
        element_clear(ss->CUT);
    }
    if(conn_ss)                     release_connection(conn_ss);
    if(conn_db)                     release_connection(conn_db);
    if(pai_inited == SUCCESS)       element_clear(paix);
    if(pair_inited == SUCCESS)      pairing_clear(pair->pair);
    if(conn_pk)                     release_connection(conn_pk);
    if(pair)                        free(pair);
    if(ss)                          free(ss);
    if(pk)                          free(pk);
    return ret;

}

void *thread(void *arg)
{
    int client_fd = (int)arg;
    struct vdb_packet vpk;
    INFO("Client fd is %d\n", client_fd);
    pthread_detach(pthread_self());
    while(1)
    {
        CHECK_GO(read_all(client_fd, &vpk, HEADER_LEN) == HEADER_LEN, out1);
        switch(vpk.type)
        {
            case T_I_BEGIN:
                DEBUG("Begin initing...\n");
                CHECK_GO(SUCCESS == handle_init(client_fd, &vpk), out1);
                DEBUG("Inited successfully.\n");
                break;
            case T_Q_BEGIN:
                DEBUG("Begin verifying...\n");
                CHECK_GO(SUCCESS == handle_query(client_fd, &vpk), out1);
                DEBUG("Verify finished.\n");
                break;
            default:
                DEBUG("Unknow type:%d\n", vpk.type);
                break;
        }
    }
out1:
    close(client_fd);
    DEBUG("Client closed!\n");
}

void run_server(void)
{
    int listen_fd = -1;
    listen_fd = start_listen();
    while(!stop)
    {
        int client_fd = accept(listen_fd, NULL, 0);
        pthread_t tid;
        if(client_fd < 0)
            break;
        if(pthread_create(&tid, NULL, thread, (void*)client_fd) != 0)
        {
            INFO("Can't create thread.\n");
            close(client_fd);
        }
    }
}

void init_daemon()
{
    int pid;
    int i;
    pid=fork();
    CHECK(pid);
    if(pid>0) //父进程退出
        exit(0);

    setsid(); //使子进程成为组长

    //关闭进程打开的文件句柄
    for(i=0;i<3;i++)
        close(i);
    chdir("/");  //改变目录
    umask(0);//重设文件创建的掩码
}
int main(int argc, char *argv[])
{
    CHECK(load_config(config_file));
    parse_cmdline(argc, argv);
    if(help)
    {
        show_usage();
        exit(0);
    }
    show_config();
    if(daem)
        init_daemon();
    run_server();
    return 0;
}
